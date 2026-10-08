// Package safejson rejects ambiguous credential-bearing JSON without echoing input.
package safejson

import (
	"bytes"
	"encoding/json"
	"errors"
)

var ErrInvalid = errors.New("invalid JSON")

func Decode(data []byte, value any, limit int) error {
	if len(data) > limit || !json.Valid(data) {
		return ErrInvalid
	}
	if unique(json.NewDecoder(bytes.NewReader(data)), 0) != nil {
		return ErrInvalid
	}
	if json.Unmarshal(data, value) != nil {
		return ErrInvalid
	}
	return nil
}

func unique(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			key, ok := t.(string)
			if err != nil || !ok || seen[key] {
				return ErrInvalid
			}
			seen[key] = true
			if unique(d, depth+1) != nil {
				return ErrInvalid
			}
		}
	case '[':
		for d.More() {
			if unique(d, depth+1) != nil {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	_, err = d.Token()
	return err
}
