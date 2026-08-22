package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
)

const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// ExchangeRequest is transport-neutral; an HTTP adapter maps RFC 8693 form
// fields into it.
type ExchangeRequest struct {
	GrantType        string
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Audience         string
}

type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

type Audience struct {
	ID         string
	TokenTTL   time.Duration
	Delegation DelegationMode
}

type AudienceLookup interface {
	Audience(context.Context, string) (Audience, error)
}
type PermissionLookup interface {
	AudiencePermissions(context.Context, authn.Principal, string) ([]string, error)
}
type IdentityValidator interface {
	Validate(context.Context, string) (authn.Identity, error)
}

type Exchanger struct {
	Validator   IdentityValidator
	Audiences   AudienceLookup
	Permissions PermissionLookup
	Issuer      *Issuer
}

func (e *Exchanger) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, Claims, error) {
	if e.Validator == nil || e.Audiences == nil || e.Permissions == nil || e.Issuer == nil {
		return ExchangeResponse{}, Claims{}, errors.New("token exchanger is not configured")
	}
	if request.GrantType != GrantTypeTokenExchange {
		return ExchangeResponse{}, Claims{}, errors.New("unsupported grant_type")
	}
	if request.SubjectToken == "" || request.SubjectTokenType != TokenTypeJWT {
		return ExchangeResponse{}, Claims{}, errors.New("subject_token and JWT subject_token_type are required")
	}
	if request.Audience == "" {
		return ExchangeResponse{}, Claims{}, errors.New("audience is required")
	}
	if (request.ActorToken == "") != (request.ActorTokenType == "") {
		return ExchangeResponse{}, Claims{}, errors.New("actor_token and actor_token_type must be supplied together")
	}
	if request.ActorToken != "" && request.ActorTokenType != TokenTypeJWT {
		return ExchangeResponse{}, Claims{}, errors.New("actor_token_type must be JWT")
	}
	audience, err := e.Audiences.Audience(ctx, request.Audience)
	if err != nil {
		return ExchangeResponse{}, Claims{}, fmt.Errorf("look up audience: %w", err)
	}
	if audience.ID == "" || audience.ID != request.Audience || audience.TokenTTL <= 0 {
		return ExchangeResponse{}, Claims{}, errors.New("audience configuration is invalid")
	}
	subject, err := e.Validator.Validate(ctx, request.SubjectToken)
	if err != nil {
		return ExchangeResponse{}, Claims{}, fmt.Errorf("validate subject token: %w", err)
	}
	subjectPermissions, err := e.Permissions.AudiencePermissions(ctx, subject.Principal, audience.ID)
	if err != nil {
		return ExchangeResponse{}, Claims{}, fmt.Errorf("evaluate subject permissions: %w", err)
	}
	permissions, mode := sortedUnique(subjectPermissions), DelegationSubject
	var actorPrincipal *authn.Principal
	if request.ActorToken != "" {
		if audience.Delegation == "" || audience.Delegation == DelegationDisabled {
			return ExchangeResponse{}, Claims{}, errors.New("delegated exchange is disabled for audience")
		}
		actor, err := e.Validator.Validate(ctx, request.ActorToken)
		if err != nil {
			return ExchangeResponse{}, Claims{}, fmt.Errorf("validate actor token: %w", err)
		}
		actorPermissions, err := e.Permissions.AudiencePermissions(ctx, actor.Principal, audience.ID)
		if err != nil {
			return ExchangeResponse{}, Claims{}, fmt.Errorf("evaluate actor permissions: %w", err)
		}
		permissions, err = CombinePermissions(audience.Delegation, subjectPermissions, actorPermissions)
		if err != nil {
			return ExchangeResponse{}, Claims{}, err
		}
		actorPrincipal, mode = &actor.Principal, audience.Delegation
	}
	accessToken, claims, err := e.Issuer.Issue(ctx, subject.Principal, actorPrincipal, audience.ID, audience.TokenTTL, permissions, mode, subject.PropagatedClaims)
	if err != nil {
		return ExchangeResponse{}, Claims{}, err
	}
	return ExchangeResponse{AccessToken: accessToken, IssuedTokenType: TokenTypeAccessToken, TokenType: "Bearer", ExpiresIn: int64(audience.TokenTTL / time.Second)}, claims, nil
}

// CombineDecisions applies delegation policy to fine-grained authorization
// results obtained independently for the token subject and actor.
func CombineDecisions(mode DelegationMode, subject, actor bool) (bool, error) {
	switch mode {
	case "", DelegationSubject:
		return subject, nil
	case DelegationActor:
		return actor, nil
	case DelegationIntersection:
		return subject && actor, nil
	case DelegationUnion:
		return subject || actor, nil
	case DelegationDisabled:
		return false, errors.New("delegation is disabled")
	default:
		return false, fmt.Errorf("unknown delegation mode %q", mode)
	}
}
