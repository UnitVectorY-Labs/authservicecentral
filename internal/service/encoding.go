package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

var rawURL = base64.RawURLEncoding

// PrincipalObject produces an unambiguous OpenFGA principal identifier. Each
// independently encoded component can contain arbitrary Unicode or delimiter
// characters without collisions.
func PrincipalObject(source, subject string) (string, error) {
	if source == "" || subject == "" {
		return "", errors.New("principal source and subject are required")
	}
	return "principal:" + encode(source) + "." + encode(subject), nil
}

func ResourceObject(ref database.ResourceRef) (string, error) {
	if ref.Type == "" || ref.ID == "" {
		return "", errors.New("resource type and id are required")
	}
	if strings.ContainsAny(ref.Type, ":# ") {
		return "", fmt.Errorf("invalid resource type %q", ref.Type)
	}
	return ref.Type + ":" + encode(ref.ID), nil
}

func GroupUserset(id string) (string, error) {
	object, err := ResourceObject(database.ResourceRef{Type: "group", ID: id})
	if err != nil {
		return "", err
	}
	return object + "#member", nil
}

func subjectTuple(s database.Subject) (string, error) {
	switch s.Kind {
	case "principal":
		return PrincipalObject(s.Source, s.Principal)
	case "group":
		return GroupUserset(s.GroupID)
	default:
		return "", fmt.Errorf("unsupported subject kind %q", s.Kind)
	}
}

func encode(value string) string { return rawURL.EncodeToString([]byte(value)) }
