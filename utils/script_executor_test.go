package utils

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRunClashScriptMainTransformsConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		script string
		want   string
	}{
		{
			name:  "mutates ordinary objects and arrays",
			input: "mixed-port: 7890\nobsolete: true\nrules:\n  - MATCH,DIRECT\n",
			script: `function main(config) {
				config["mixed-port"] += 1;
				delete config.obsolete;
				config.rules.unshift("DOMAIN,example.test,REJECT");
				config.rules.push("DOMAIN,other.test,DIRECT");
				config["x-added"] = {enabled: true, ports: [80, 443]};
				return config;
			}`,
			want: `mixed-port: 7891
rules:
  - DOMAIN,example.test,REJECT
  - MATCH,DIRECT
  - DOMAIN,other.test,DIRECT
x-added:
  enabled: true
  ports: [80, 443]
`,
		},
		{
			name:  "serializes the returned replacement object",
			input: "mixed-port: 7890\nobsolete: true\n",
			script: `function main(config) {
				config.obsolete = false;
				return {"mixed-port": config["mixed-port"] + 10, rules: ["MATCH,REJECT"]};
			}`,
			want: "mixed-port: 7900\nrules: ['MATCH,REJECT']\n",
		},
		{
			name: "preserves nested extension fields",
			input: `mode: rule
dns:
  enable: true
  nameserver: ["https://dns.example.test/dns-query"]
  future-dns:
    policy: {"example.test": [DIRECT, REJECT]}
proxy-providers:
  remote:
    type: http
    url: https://provider.example.test/subscription
    interval: 3600
    health-check: {enable: true, url: "https://probe.example.test/", interval: 300}
proxies:
  - name: extended
    type: vless
    server: node.example.test
    port: 443
    future-proxy:
      transport: {enabled: true, weights: [1, 2]}
x-future:
  entries: [{name: "扩展", enabled: false, value: null}]
`,
			script: `function main(config) {
				config.mode = "global";
				return config;
			}`,
			want: `mode: global
dns:
  enable: true
  nameserver: ["https://dns.example.test/dns-query"]
  future-dns:
    policy: {"example.test": [DIRECT, REJECT]}
proxy-providers:
  remote:
    type: http
    url: https://provider.example.test/subscription
    interval: 3600
    health-check: {enable: true, url: "https://probe.example.test/", interval: 300}
proxies:
  - name: extended
    type: vless
    server: node.example.test
    port: 443
    future-proxy:
      transport: {enabled: true, weights: [1, 2]}
x-future:
  entries: [{name: "扩展", enabled: false, value: null}]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := RunClashScript(tt.script, tt.input)
			if err != nil {
				t.Fatalf("RunClashScript: %v", err)
			}
			var got, want map[string]any
			if err := yaml.Unmarshal([]byte(output), &got); err != nil {
				t.Fatalf("decode output YAML: %v", err)
			}
			if err := yaml.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatalf("decode expected YAML: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("configuration = %#v, want %#v", got, want)
			}
		})
	}
}

func TestRunClashScriptSubModTakesPrecedenceWithRawText(t *testing.T) {
	const script = `function main(config) {
		throw new Error("main must not run when subMod is present");
	}
	function subMod(input, clientType) {
		if (typeof input !== "string") throw new Error("expected raw text");
		return input + "# client=" + clientType + "\r\n";
	}`
	tests := []struct {
		name  string
		input string
	}{
		{name: "preserves YAML formatting", input: "# retained comment\r\nmixed-port: 7890\r\nrules: [ 'MATCH,DIRECT' ]\r\n"},
		{name: "does not require valid YAML", input: "unparsed: [\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RunClashScript(script, tt.input)
			if err != nil {
				t.Fatalf("RunClashScript: %v", err)
			}
			want := tt.input + "# client=clash\r\n"
			if got != want {
				t.Fatalf("raw result = %q, want %q", got, want)
			}
		})
	}
}

func TestRunClashScriptRejectsNonObjectMainResult(t *testing.T) {
	tests := []struct {
		name   string
		result string
	}{
		{name: "null", result: "null"},
		{name: "undefined", result: "undefined"},
		{name: "array", result: "[]"},
		{name: "string", result: `"mode: global"`},
		{name: "number", result: "42"},
		{name: "boolean", result: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := RunClashScript("function main(config) { return "+tt.result+"; }", "mode: rule\n")
			if err == nil || !strings.Contains(err.Error(), "main must return a Clash configuration object") {
				t.Fatalf("error = %v, want invalid configuration object error", err)
			}
			if output != "" {
				t.Fatalf("invalid result produced configuration %q", output)
			}
		})
	}
}
