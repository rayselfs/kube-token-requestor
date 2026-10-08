package safejson

import "testing"

func TestDecode(t *testing.T) {
	for _, input := range []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"a":[{"b":1,"b":2}]}`, `{} {}`, `null trailing`} {
		var value any
		if Decode([]byte(input), &value, 1024) != ErrInvalid {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	var value map[string]any
	if Decode([]byte(`{"x":1}`), &value, 1024) != nil {
		t.Fatal("valid JSON rejected")
	}
	if Decode([]byte(`{"x":1}`), &value, 2) != ErrInvalid {
		t.Fatal("limit ignored")
	}
}
