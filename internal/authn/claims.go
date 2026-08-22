package authn

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

func validateRules(rules map[string]ClaimRule) error {
	for claim, rule := range rules {
		if claim == "" {
			return errors.New("claim rule name is required")
		}
		count := 0
		if rule.Exists != nil {
			count++
		}
		if rule.Equals != nil {
			count++
		}
		if rule.NotEquals != nil {
			count++
		}
		if rule.OneOf != nil {
			count++
		}
		if rule.Prefix != nil {
			count++
		}
		if rule.Suffix != nil {
			count++
		}
		if rule.Regex != nil {
			count++
		}
		if rule.Contains != nil {
			count++
		}
		if count != 1 {
			return fmt.Errorf("claim %q must have exactly one matcher", claim)
		}
		if rule.Regex != nil {
			if _, err := regexp.Compile(*rule.Regex); err != nil {
				return fmt.Errorf("claim %q regex: %w", claim, err)
			}
		}
	}
	return nil
}

func matchClaims(claims map[string]any, rules map[string]ClaimRule) error {
	for name, rule := range rules {
		value, present := claims[name]
		matched := false
		switch {
		case rule.Exists != nil:
			matched = present == *rule.Exists
		case !present:
			matched = false
		case rule.Equals != nil:
			matched = equalJSON(value, rule.Equals)
		case rule.NotEquals != nil:
			matched = !equalJSON(value, rule.NotEquals)
		case rule.OneOf != nil:
			for _, candidate := range rule.OneOf {
				if equalJSON(value, candidate) {
					matched = true
					break
				}
			}
		case rule.Prefix != nil:
			v, ok := value.(string)
			matched = ok && strings.HasPrefix(v, *rule.Prefix)
		case rule.Suffix != nil:
			v, ok := value.(string)
			matched = ok && strings.HasSuffix(v, *rule.Suffix)
		case rule.Regex != nil:
			v, ok := value.(string)
			if ok {
				matched, _ = regexp.MatchString(*rule.Regex, v)
			}
		case rule.Contains != nil:
			matched = contains(value, rule.Contains)
		}
		if !matched {
			return fmt.Errorf("claim %q did not satisfy configured policy", name)
		}
	}
	return nil
}

func equalJSON(a, b any) bool {
	// Normalize numbers and map types in configuration adapters consistently.
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	return aerr == nil && berr == nil && reflect.DeepEqual(ab, bb)
}

func contains(container, wanted any) bool {
	switch value := container.(type) {
	case string:
		needle, ok := wanted.(string)
		return ok && strings.Contains(value, needle)
	case []any:
		for _, item := range value {
			if equalJSON(item, wanted) {
				return true
			}
		}
	case map[string]any:
		key, ok := wanted.(string)
		if ok {
			_, ok = value[key]
		}
		return ok
	}
	return false
}
