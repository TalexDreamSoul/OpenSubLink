package utils

import (
	"encoding/json"
	"fmt"

	"github.com/dop251/goja"
	"gopkg.in/yaml.v3"
)

// RunScript executes subMod(input, clientType) with the existing text contract.
func RunScript(scriptContent string, input string, clientType string) (string, error) {
	return runScript(scriptContent, input, clientType, false)
}

// RunClashScript also supports Mihomo/Clash overrides defining main(config).
// subMod takes precedence and continues to receive and return raw YAML text.
func RunClashScript(scriptContent string, input string) (string, error) {
	return runScript(scriptContent, input, "clash", true)
}

func runScript(scriptContent string, input string, clientType string, allowClashMain bool) (string, error) {
	vm := goja.New()

	// Inject console object
	_ = vm.Set("console", map[string]any{
		"log":   fmt.Println,
		"info":  fmt.Println,
		"warn":  fmt.Println,
		"error": fmt.Println,
	})

	// Inject polyfills
	_, err := vm.RunString(polyfills)
	if err != nil {
		return "", fmt.Errorf("polyfill injection error: %w", err)
	}

	// Execute the script to load definitions
	_, err = vm.RunString(scriptContent)
	if err != nil {
		return "", fmt.Errorf("script compilation error: %w", err)
	}

	if subMod, ok := goja.AssertFunction(vm.Get("subMod")); ok {
		result, err := subMod(goja.Undefined(), vm.ToValue(input), vm.ToValue(clientType))
		if err != nil {
			return "", fmt.Errorf("script execution error: %w", err)
		}
		return result.String(), nil
	}
	if !allowClashMain {
		return "", fmt.Errorf("subMod function not found in script")
	}
	mainFn, ok := goja.AssertFunction(vm.Get("main"))
	if !ok {
		return "", fmt.Errorf("subMod or main function not found in script")
	}

	// Decode the complete configuration rather than a typed Clash schema so
	// provider, DNS, proxy and other extension fields survive the override.
	var config map[string]any
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		return "", fmt.Errorf("failed to decode Clash configuration: %w", err)
	}
	if config == nil {
		return "", fmt.Errorf("clash configuration must be an object")
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to encode Clash configuration as JSON: %w", err)
	}
	// JSON.parse creates ordinary JS objects and arrays, allowing scripts to
	// add/delete properties and use array operations without Go map/slice limits.
	parseJSON, ok := goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("parse"))
	if !ok {
		return "", fmt.Errorf("JSON.parse function not available")
	}
	configValue, err := parseJSON(goja.Undefined(), vm.ToValue(string(configJSON)))
	if err != nil {
		return "", fmt.Errorf("failed to create Clash configuration object: %w", err)
	}
	result, err := mainFn(goja.Undefined(), configValue)
	if err != nil {
		return "", fmt.Errorf("script execution error: %w", err)
	}
	resultConfig, ok := result.Export().(map[string]any)
	if !ok || resultConfig == nil {
		return "", fmt.Errorf("main must return a Clash configuration object")
	}
	resultJSON, err := json.Marshal(resultConfig)
	if err != nil {
		return "", fmt.Errorf("failed to encode script result: %w", err)
	}
	// Decode JSON through YAML to retain integral numbers as YAML integers.
	var output map[string]any
	if err := yaml.Unmarshal(resultJSON, &output); err != nil {
		return "", fmt.Errorf("failed to decode script result: %w", err)
	}
	outputYAML, err := yaml.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("failed to encode Clash configuration: %w", err)
	}
	return string(outputYAML), nil
}

// RunNodeFilterScript executes a JavaScript script to filter nodes.
// The script is expected to define a function `filterNode(nodes, clientType)` that returns a modified nodes array.
func RunNodeFilterScript(scriptContent string, nodesJSON []byte, clientType string) ([]byte, error) {
	vm := goja.New()

	// Inject console object
	_ = vm.Set("console", map[string]any{
		"log":   fmt.Println,
		"info":  fmt.Println,
		"warn":  fmt.Println,
		"error": fmt.Println,
	})

	// Inject polyfills
	_, err := vm.RunString(polyfills)
	if err != nil {
		return nil, fmt.Errorf("polyfill injection error: %w", err)
	}

	// Execute the script to load definitions
	_, err = vm.RunString(scriptContent)
	if err != nil {
		return nil, fmt.Errorf("script compilation error: %w", err)
	}

	// Get the filterNode function
	filterFn, ok := goja.AssertFunction(vm.Get("filterNode"))
	if !ok {
		// If function not found, return original nodes (or error? Plan said error, but maybe better to just return nil error and original nodes if we want to be lenient.
		// However, explicit error is better for debugging.
		return nil, fmt.Errorf("filterNode function not found in script")
	}

	// Unmarshal nodes
	var nodes any
	if err := json.Unmarshal(nodesJSON, &nodes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes: %w", err)
	}

	// Call the function
	result, err := filterFn(goja.Undefined(), vm.ToValue(nodes), vm.ToValue(clientType))
	if err != nil {
		return nil, fmt.Errorf("script execution error: %w", err)
	}

	// Marshal result back to JSON
	// The result should be the modified nodes array
	resNodes := result.Export()
	newJSON, err := json.Marshal(resNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	return newJSON, nil
}

const polyfills = `
if (!String.prototype.includes) {
  String.prototype.includes = function(search, start) {
    if (typeof start !== 'number') {
      start = 0;
    }
    if (start + search.length > this.length) {
      return false;
    } else {
      return this.indexOf(search, start) !== -1;
    }
  };
}

if (!String.prototype.startsWith) {
  String.prototype.startsWith = function(searchString, position) {
    position = position || 0;
    return this.substr(position, searchString.length) === searchString;
  };
}

if (!String.prototype.endsWith) {
  String.prototype.endsWith = function(searchString, position) {
    var subjectString = this.toString();
    if (typeof position !== 'number' || !isFinite(position) || Math.floor(position) !== position || position > subjectString.length) {
      position = subjectString.length;
    }
    position -= searchString.length;
    var lastIndex = subjectString.lastIndexOf(searchString, position);
    return lastIndex !== -1 && lastIndex === position;
  };
}

if (!String.prototype.padStart) {
    String.prototype.padStart = function padStart(targetLength, padString) {
        targetLength = targetLength >> 0; //truncate if number, or convert non-number to 0;
        padString = String(typeof padString !== 'undefined' ? padString : ' ');
        if (this.length >= targetLength) {
            return String(this);
        } else {
            targetLength = targetLength - this.length;
            if (targetLength > padString.length) {
                padString += padString.repeat(targetLength / padString.length); //append to original to ensure we are longer than needed
            }
            return padString.slice(0, targetLength) + String(this);
        }
    };
}

if (!String.prototype.padEnd) {
    String.prototype.padEnd = function padEnd(targetLength, padString) {
        targetLength = targetLength >> 0; //floor if number or convert non-number to 0;
        padString = String(typeof padString !== 'undefined' ? padString : ' ');
        if (this.length > targetLength) {
            return String(this);
        } else {
            targetLength = targetLength - this.length;
            if (targetLength > padString.length) {
                padString += padString.repeat(targetLength / padString.length); //append to original to ensure we are longer than needed
            }
            return String(this) + padString.slice(0, targetLength);
        }
    };
}

if (!Array.prototype.find) {
  Object.defineProperty(Array.prototype, 'find', {
    value: function(predicate) {
      if (this == null) {
        throw new TypeError('"this" is null or not defined');
      }
      var o = Object(this);
      var len = o.length >>> 0;
      if (typeof predicate !== 'function') {
        throw new TypeError('predicate must be a function');
      }
      var thisArg = arguments[1];
      var k = 0;
      while (k < len) {
        var kValue = o[k];
        if (predicate.call(thisArg, kValue, k, o)) {
          return kValue;
        }
        k++;
      }
      return undefined;
    },
    configurable: true,
    writable: true
  });
}

if (!Array.prototype.findIndex) {
  Object.defineProperty(Array.prototype, 'findIndex', {
    value: function(predicate) {
      if (this == null) {
        throw new TypeError('"this" is null or not defined');
      }
      var o = Object(this);
      var len = o.length >>> 0;
      if (typeof predicate !== 'function') {
        throw new TypeError('predicate must be a function');
      }
      var thisArg = arguments[1];
      var k = 0;
      while (k < len) {
        var kValue = o[k];
        if (predicate.call(thisArg, kValue, k, o)) {
          return k;
        }
        k++;
      }
      return -1;
    },
    configurable: true,
    writable: true
  });
}

if (!Array.prototype.includes) {
  Object.defineProperty(Array.prototype, 'includes', {
    value: function(searchElement, fromIndex) {
      if (this == null) {
        throw new TypeError('"this" is null or not defined');
      }
      var o = Object(this);
      var len = o.length >>> 0;
      if (len === 0) {
        return false;
      }
      var n = fromIndex | 0;
      var k = Math.max(n >= 0 ? n : len - Math.abs(n), 0);
      while (k < len) {
        if (o[k] === searchElement) {
          return true;
        }
        k++;
      }
      return false;
    }
  });
}

if (!Array.from) {
  Array.from = (function () {
    var toStr = Object.prototype.toString;
    var isCallable = function (fn) {
      return typeof fn === 'function' || toStr.call(fn) === '[object Function]';
    };
    var toInteger = function (value) {
      var number = Number(value);
      if (isNaN(number)) { return 0; }
      if (number === 0 || !isFinite(number)) { return number; }
      return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
    };
    var maxSafeInteger = Math.pow(2, 53) - 1;
    var toLength = function (value) {
      var len = toInteger(value);
      return Math.min(Math.max(len, 0), maxSafeInteger);
    };

    // The length property of the from method is 1.
    return function from(arrayLike/*, mapFn, thisArg */) {
      // 1. Let C be the this value.
      var C = this;

      // 2. Let items be ToObject(arrayLike).
      var items = Object(arrayLike);

      // 3. ReturnIfAbrupt(items).
      if (arrayLike == null) {
        throw new TypeError('Array.from requires an array-like object - not null or undefined');
      }

      // 4. If mapfn is undefined, then let mapping be false.
      var mapFn = arguments.length > 1 ? arguments[1] : undefined;
      var T;
      if (typeof mapFn !== 'undefined') {
        // 5. else
        // 5. a If IsCallable(mapfn) is false, throw a TypeError exception.
        if (!isCallable(mapFn)) {
          throw new TypeError('Array.from: when provided, the second argument must be a function');
        }

        // 5. b. If thisArg was supplied, let T be thisArg; else let T be undefined.
        if (arguments.length > 2) {
          T = arguments[2];
        }
      }

      // 10. Let lenValue be Get(items, "length").
      // 11. Let len be ToLength(lenValue).
      var len = toLength(items.length);

      // 13. If IsConstructor(C) is true, then
      // 13. a. Let A be the result of calling the [[Construct]] internal method 
      // of C with an argument list containing the single item len.
      // 14. a. Else, Let A be ArrayCreate(len).
      var A = isCallable(C) ? Object(new C(len)) : new Array(len);

      // 16. Let k be 0.
      var k = 0;
      // 17. Repeat, while k < len… (also steps a - h)
      var kValue;
      while (k < len) {
        kValue = items[k];
        if (mapFn) {
          A[k] = typeof T === 'undefined' ? mapFn(kValue, k) : mapFn.call(T, kValue, k);
        } else {
          A[k] = kValue;
        }
        k += 1;
      }
      // 18. Let putStatus be Put(A, "length", len, true).
      A.length = len;
      // 20. Return A.
      return A;
    };
  }());
}

if (typeof Object.assign != 'function') {
  Object.assign = function(target) {
    'use strict';
    if (target == null) {
      throw new TypeError('Cannot convert undefined or null to object');
    }
    target = Object(target);
    for (var index = 1; index < arguments.length; index++) {
      var source = arguments[index];
      if (source != null) {
        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }
    }
    return target;
  };
}

if (!Object.values) {
    Object.values = function(obj) {
        if (obj !== Object(obj))
            throw new TypeError('Object.values called on a non-object');
        var val = [], key;
        for (key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                val.push(obj[key]);
            }
        }
        return val;
    };
}

if (!Object.entries) {
    Object.entries = function(obj) {
        if (obj !== Object(obj))
            throw new TypeError('Object.entries called on a non-object');
        var val = [], key;
        for (key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                val.push([key, obj[key]]);
            }
        }
        return val;
    };
}
`
