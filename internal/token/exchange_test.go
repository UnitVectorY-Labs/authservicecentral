package token

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
)

type fakeValidator map[string]authn.Identity

func (f fakeValidator) Validate(_ context.Context, token string) (authn.Identity, error) {
	v, ok := f[token]
	if !ok {
		return authn.Identity{}, errors.New("bad token")
	}
	return v, nil
}

type fakeAudiences struct{ audience Audience }

func (f fakeAudiences) Audience(_ context.Context, id string) (Audience, error) {
	if id != f.audience.ID {
		return Audience{}, errors.New("not found")
	}
	return f.audience, nil
}

type fakePermissions map[string][]string

func (f fakePermissions) AudiencePermissions(_ context.Context, p authn.Principal, _ string) ([]string, error) {
	return f[p.String()], nil
}

func TestExchangeDirectAndDelegationModes(t *testing.T) {
	subject := authn.Principal{Source: "corp", Subject: "alice"}
	actor := authn.Principal{Source: "gcp", Subject: "service"}
	validator := fakeValidator{"subject": {Principal: subject, PropagatedClaims: map[string]any{"department": "eng"}}, "actor": {Principal: actor}}
	permissions := fakePermissions{subject.String(): {"invoke", "create"}, actor.String(): {"invoke", "operate"}}
	issuer := &Issuer{Issuer: "https://platform", Signer: testSigner(t), Now: func() time.Time { return time.Unix(1000, 0) }}
	e := &Exchanger{Validator: validator, Permissions: permissions, Issuer: issuer, Audiences: fakeAudiences{Audience{ID: "docs", TokenTTL: 10 * time.Minute, Delegation: DelegationDisabled}}}
	base := ExchangeRequest{GrantType: GrantTypeTokenExchange, SubjectToken: "subject", SubjectTokenType: TokenTypeJWT, Audience: "docs"}
	response, claims, err := e.Exchange(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if response.AccessToken == "" || response.ExpiresIn != 600 || claims.Act != nil || !reflect.DeepEqual(claims.Permissions, []string{"create", "invoke"}) || claims.Extra["department"] != "eng" {
		t.Fatalf("direct exchange: %#v %#v", response, claims)
	}
	delegated := base
	delegated.ActorToken = "actor"
	delegated.ActorTokenType = TokenTypeJWT
	tests := []struct {
		mode DelegationMode
		want []string
	}{{DelegationSubject, []string{"create", "invoke"}}, {DelegationActor, []string{"invoke", "operate"}}, {DelegationIntersection, []string{"invoke"}}, {DelegationUnion, []string{"create", "invoke", "operate"}}}
	for _, tt := range tests {
		e.Audiences = fakeAudiences{Audience{ID: "docs", TokenTTL: time.Minute, Delegation: tt.mode}}
		_, got, err := e.Exchange(context.Background(), delegated)
		if err != nil {
			t.Errorf("%s: %v", tt.mode, err)
			continue
		}
		if !reflect.DeepEqual(got.Permissions, tt.want) || got.Act == nil || got.AuthorizationContext.Mode != tt.mode {
			t.Errorf("%s: %#v", tt.mode, got)
		}
	}
	e.Audiences = fakeAudiences{Audience{ID: "docs", TokenTTL: time.Minute, Delegation: DelegationDisabled}}
	if _, _, err := e.Exchange(context.Background(), delegated); err == nil {
		t.Fatal("disabled delegated exchange accepted")
	}
}

func TestExchangeRequestValidation(t *testing.T) {
	e := &Exchanger{}
	for _, request := range []ExchangeRequest{{}, {GrantType: GrantTypeTokenExchange}, {GrantType: GrantTypeTokenExchange, SubjectToken: "x", SubjectTokenType: TokenTypeJWT}} {
		if _, _, err := e.Exchange(context.Background(), request); err == nil {
			t.Fatalf("invalid request accepted: %#v", request)
		}
	}
}
