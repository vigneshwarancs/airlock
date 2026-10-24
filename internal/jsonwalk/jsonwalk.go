// Package jsonwalk rewrites every string value in a JSON document without
// knowing the document's schema.
//
// This is what lets one code path cover both the Anthropic Messages API and
// the OpenAI Chat Completions API, plus every tool-call argument nested
// inside them. Rather than modelling each provider's wire format, Airlock
// transforms all string leaves except those under structurally meaningful
// keys.
package jsonwalk

import (
	"bytes"
	"encoding/json"
)

// skipKeys are string fields that carry protocol structure, not user content.
// Rewriting them would corrupt the request.
var skipKeys = map[string]bool{
	"model":         true,
	"role":          true,
	"type":          true,
	"id":            true,
	"tool_use_id":   true,
	"tool_call_id":  true,
	"stop_reason":   true,
	"finish_reason": true,
	"object":        true,
	"index":         true,
	"event":         true,
	"media_type":    true,
	"encoding":      true,
	"data":          true, // base64 image payloads
	"name":          true, // tool names
	"service_tier":  true,
	"citations":     true,
}

// MapFunc transforms one string leaf. key is the object key the string was
// found under ("" for top-level or array elements of an unkeyed array).
type MapFunc func(key, value string) string

// MapStrings decodes raw, applies fn to every eligible string leaf, and
// re-encodes.
//
// Numbers are decoded as json.Number so that re-encoding cannot turn
// max_tokens: 1000000 into 1e+06.
func MapStrings(raw []byte, fn MapFunc) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}

	doc = walk("", doc, fn)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func walk(key string, node any, fn MapFunc) any {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = walk(k, child, fn)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = walk(key, child, fn)
		}
		return v
	case string:
		if skipKeys[key] {
			return v
		}
		return fn(key, v)
	default:
		return node
	}
}

// Strings collects every eligible string leaf without modifying the document.
func Strings(raw []byte) ([]string, error) {
	var out []string
	_, err := MapStrings(raw, func(_, v string) string {
		out = append(out, v)
		return v
	})
	return out, err
}
