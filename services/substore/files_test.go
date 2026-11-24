package substore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"sublink/services/substore"
)

func TestDownloadFileRejectsUnauthorizedSharesBeforeFetchingContent(t *testing.T) {
	const name = "private.txt"
	const token = "private-token"
	valid := substore.FileShare{Type: "file", Name: name, Token: token, ExpiresAt: 4102444800000}
	tests := []struct {
		name  string
		token string
		share substore.FileShare
	}{
		{name: "unknown token", token: token},
		{name: "missing token", share: valid},
		{name: "wrong token", token: "another-token", share: valid},
		{name: "wrong name", token: token, share: substore.FileShare{Type: "file", Name: "other.txt", Token: token}},
		{name: "wrong type", token: token, share: substore.FileShare{Type: "collection", Name: name, Token: token}},
		{name: "type is case sensitive", token: token, share: substore.FileShare{Type: "File", Name: name, Token: token}},
		{name: "expired millisecond timestamp", token: token, share: substore.FileShare{Type: "file", Name: name, Token: token, ExpiresAt: 946684800000}},
		{name: "exhausted count", token: token, share: substore.FileShare{Type: "file", Name: name, Token: token, Mode: "count", Count: 2, UsedCount: 2}},
		{name: "count exceeded", token: token, share: substore.FileShare{Type: "file", Name: name, Token: token, Mode: "count", Count: 2, UsedCount: 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contentRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/protected/api/tokens" {
					shares := []substore.FileShare{}
					if tt.share.Type != "" {
						shares = append(shares, tt.share)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": shares})
					return
				}
				contentRequests.Add(1)
				_, _ = w.Write([]byte("private content"))
			}))
			defer server.Close()
			client, err := substore.NewClient(substore.Config{BaseURL: server.URL + "/protected"})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			body, err := client.DownloadFile(context.Background(), name, tt.token)
			if !errors.Is(err, substore.ErrFileShareNotFound) {
				t.Fatalf("expected hidden share error, got body %q and error %v", body, err)
			}
			if got := contentRequests.Load(); got != 0 {
				t.Fatalf("unauthorized share caused %d content requests", got)
			}
		})
	}
}

func TestDownloadFileScopesRequestsAndPreservesPlainBytes(t *testing.T) {
	const name = "配置 &?#%.txt"
	const token = "secret&url=https://example.invalid/file?x=1#fragment +"
	content := []byte("  # raw configuration\r\n节点: direct\n\ntrailing spaces  \n")
	for _, mode := range []string{"duration", "count"} {
		t.Run(mode, func(t *testing.T) {
			requests := make(chan *http.Request, 16)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Clone(context.Background())
				if r.URL.Path == "/protected/api/tokens" {
					shares := []substore.FileShare{
						{Type: "collection", Name: name, Token: token},
						{Type: "file", Name: "unrelated.txt", Token: token},
						{Type: "file", Name: name, Token: token, ExpiresAt: 4102444800000, Mode: mode, Count: 2, UsedCount: 1},
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": shares})
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write(content)
			}))
			defer server.Close()
			client, err := substore.NewClient(substore.Config{BaseURL: server.URL + "/protected"})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			body, err := client.DownloadFile(context.Background(), name, token)
			if err != nil {
				t.Fatalf("download: %v", err)
			}
			if !bytes.Equal(body, content) {
				t.Fatalf("download changed plain bytes: got %q, want %q", body, content)
			}
			if got := len(requests); got != 2 {
				t.Fatalf("expected token lookup then content request, got %d requests", got)
			}
			assertFileDownloadRequest(t, <-requests, "/protected/api/tokens", url.Values{"type": {"file"}, "name": {name}})
			assertFileDownloadRequest(t, <-requests, "/share/file/"+url.PathEscape(name), url.Values{"token": {token}})
		})
	}
}

func TestDownloadFileRequiresProtectedBaseBeforeMakingRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("private content"))
	}))
	defer server.Close()
	client, err := substore.NewClient(substore.Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_, err = client.DownloadFile(context.Background(), "private.txt", "private-token")
	if !errors.Is(err, substore.ErrFileGateway) {
		t.Fatalf("expected protected gateway error, got %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("unprotected base received %d requests", got)
	}
}

func TestDownloadFileDoesNotFollowUpstreamRedirects(t *testing.T) {
	for _, redirectStage := range []string{"tokens", "content"} {
		t.Run(redirectStage, func(t *testing.T) {
			var redirectedRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirectedRequests.Add(1)
				_, _ = w.Write([]byte("redirected private content"))
			}))
			defer destination.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/protected/api/tokens" && redirectStage == "content" {
					_, _ = w.Write([]byte(`{"status":"success","data":[{"type":"file","name":"private.txt","token":"private-token","exp":4102444800000}]}`))
					return
				}
				http.Redirect(w, r, destination.URL+"/leak", http.StatusFound)
			}))
			defer server.Close()
			client, err := substore.NewClient(substore.Config{BaseURL: server.URL + "/protected"})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			body, err := client.DownloadFile(context.Background(), "private.txt", "private-token")
			if err == nil {
				t.Fatalf("expected redirect rejection, got content %q", body)
			}
			if got := redirectedRequests.Load(); got != 0 {
				t.Fatalf("upstream redirect destination received %d requests", got)
			}
		})
	}
}

func assertFileDownloadRequest(t *testing.T, request *http.Request, escapedPath string, query url.Values) {
	t.Helper()
	if request.Method != http.MethodGet || request.URL.EscapedPath() != escapedPath {
		t.Fatalf("unexpected request: %s %s; want GET %s", request.Method, request.URL.EscapedPath(), escapedPath)
	}
	if got := request.URL.Query().Encode(); got != query.Encode() {
		t.Fatalf("unexpected request scope: got %q, want %q", got, query.Encode())
	}
	for _, header := range []string{"Authorization", "Cookie", "Referer", "X-Forwarded-For", "X-Real-IP"} {
		if value := request.Header.Get(header); value != "" {
			t.Errorf("request forwarded %s: %q", header, value)
		}
	}
}
