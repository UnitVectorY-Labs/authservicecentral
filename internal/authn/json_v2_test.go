package authn

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestJWTStrictJSONAndNumericPrecision(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	token := func(claims string) string { return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(claims)) + "." }
	for _, claims := range []string{`{"exp":1,"exp":2}`, "{\"x\":\"\xff\"}", `{"exp":1} {}`} {
		if _, _, _, _, err := DecodeCompact(token(claims)); err == nil {
			t.Fatalf("accepted %q", claims)
		}
	}
	_, claims, _, _, err := DecodeCompact(token(`{"exp":9007199254740993,"nested":[9007199254740993]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := numericDate(claims["exp"]); !ok || got != 9007199254740993 {
		t.Fatalf("exp = %v", claims["exp"])
	}
	b, err := json.Marshal(claims)
	if err != nil || strings.Count(string(b), "9007199254740993") != 2 {
		t.Fatalf("claims = %s, %v", b, err)
	}
}
