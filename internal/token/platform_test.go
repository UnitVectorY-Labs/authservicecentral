package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing"
)

func TestPlatformIssueParseJWKSRotation(t *testing.T) {
	current, old := testSigner(t), testSigner(t)
	now := time.Unix(1000, 0)
	issuer := &Issuer{Issuer: "https://platform.test", Signer: current, Published: []signing.Signer{old, current}, Now: func() time.Time { return now }}
	principal := authn.Principal{Source: "corp", Subject: "alice:123"}
	actor := authn.Principal{Source: "gcp", Subject: "service-a"}
	jwt, issued, err := issuer.Issue(context.Background(), principal, &actor, "documents", 15*time.Minute, []string{"write", "read", "read"}, DelegationIntersection, map[string]any{"department": "engineering"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(issued.Permissions, []string{"read", "write"}) {
		t.Fatalf("permissions: %#v", issued.Permissions)
	}
	jwks, err := issuer.JWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(jwks)
	keys, err := authn.NewStaticJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	parser := &Parser{Issuer: issuer.Issuer, Algorithms: []string{"RS256"}, Keys: keys, Now: func() time.Time { return now }}
	parsed, err := parser.Parse(context.Background(), jwt, "documents")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AuthorizationContext.Subject != principal || parsed.AuthorizationContext.Actor == nil || *parsed.AuthorizationContext.Actor != actor || parsed.Act.Subject != "gcp:service-a" || parsed.Extra["department"] != "engineering" {
		t.Fatalf("parsed claims: %#v", parsed)
	}
	if _, err := parser.Parse(context.Background(), jwt, "billing"); err == nil {
		t.Fatal("wrong audience accepted")
	}
	parser.Now = func() time.Time { return now.Add(16 * time.Minute) }
	if _, err := parser.Parse(context.Background(), jwt, "documents"); err == nil {
		t.Fatal("expired platform token accepted")
	}
	if keysSlice, ok := jwks["keys"].([]signing.JWK); !ok || len(keysSlice) != 2 {
		t.Fatalf("rotation JWKS: %#v", jwks)
	}
}

func TestCombineModes(t *testing.T) {
	tests := []struct {
		mode     DelegationMode
		want     []string
		decision bool
	}{{DelegationSubject, []string{"a", "b"}, true}, {DelegationActor, []string{"b", "c"}, false}, {DelegationIntersection, []string{"b"}, false}, {DelegationUnion, []string{"a", "b", "c"}, true}}
	for _, tt := range tests {
		got, err := CombinePermissions(tt.mode, []string{"a", "b"}, []string{"b", "c"})
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: %#v %v", tt.mode, got, err)
		}
		decision, err := CombineDecisions(tt.mode, true, false)
		if err != nil || decision != tt.decision {
			t.Errorf("decision %s: %v %v", tt.mode, decision, err)
		}
	}
	if _, err := CombinePermissions(DelegationDisabled, nil, nil); err == nil {
		t.Fatal("disabled delegation accepted")
	}
}

func TestIssuerRejectsReservedExtra(t *testing.T) {
	issuer := &Issuer{Issuer: "i", Signer: testSigner(t)}
	if _, _, err := issuer.Issue(context.Background(), authn.Principal{Source: "s", Subject: "x"}, nil, "a", time.Minute, nil, DelegationSubject, map[string]any{"iss": "override"}); err == nil {
		t.Fatal("reserved extra accepted")
	}
}

func testSigner(t *testing.T) *signing.Local {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signing.ParseLocal(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
