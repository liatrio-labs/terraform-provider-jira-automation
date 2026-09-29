package normalize

import (
	"encoding/json"
)

// RedactedValue is the placeholder Jira returns for secret fields on GET.
const RedactedValue = "***"

// StripAPIFields recursively removes API-assigned and API-enriched fields from
// rule JSON so Terraform config (which omits them) matches state after refresh.
func StripAPIFields(v interface{}) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return
	}

	delete(m, "id")
	delete(m, "parentId")
	delete(m, "conditionParentId")
	delete(m, "connectionId")

	if children, ok := m["children"].([]interface{}); ok {
		if len(children) == 0 {
			delete(m, "children")
		} else {
			for _, child := range children {
				StripAPIFields(child)
			}
		}
	}
	if conditions, ok := m["conditions"].([]interface{}); ok {
		if len(conditions) == 0 {
			delete(m, "conditions")
		} else {
			for _, cond := range conditions {
				StripAPIFields(cond)
			}
		}
	}

	if val, ok := m["value"].(map[string]interface{}); ok {
		delete(val, "eventFilters")
		delete(val, "eventKey")
		delete(val, "issueEvent")
		delete(val, "urlSecure")
		if headers, ok := val["headers"].([]interface{}); ok {
			for _, h := range headers {
				if hm, ok := h.(map[string]interface{}); ok {
					delete(hm, "id")
				}
			}
		}
	}
}

// RestoreRedactedSecrets copies prior-state values over API placeholders ("***")
// so redacted headers and tokens do not show as Terraform drift.
func RestoreRedactedSecrets(api, prior interface{}) {
	switch a := api.(type) {
	case map[string]interface{}:
		p, ok := prior.(map[string]interface{})
		if !ok {
			return
		}
		for k, av := range a {
			pv, ok := p[k]
			if !ok {
				continue
			}
			if s, ok := av.(string); ok && s == RedactedValue {
				a[k] = pv
				continue
			}
			RestoreRedactedSecrets(av, pv)
		}
	case []interface{}:
		p, ok := prior.([]interface{})
		if !ok {
			return
		}
		for i, av := range a {
			pv := matchPriorElem(av, p, i)
			if pv == nil {
				continue
			}
			if s, ok := av.(string); ok && s == RedactedValue {
				a[i] = pv
				continue
			}
			RestoreRedactedSecrets(av, pv)
		}
	}
}

func matchPriorElem(apiElem interface{}, prior []interface{}, index int) interface{} {
	if am, ok := apiElem.(map[string]interface{}); ok {
		if name, ok := am["name"].(string); ok && name != "" {
			for _, pe := range prior {
				if pm, ok := pe.(map[string]interface{}); ok {
					if pn, ok := pm["name"].(string); ok && pn == name {
						return pe
					}
				}
			}
		}
	}
	if index < len(prior) {
		return prior[index]
	}
	return nil
}

// RestoreRedactedJSON unmarshals apiJSON and priorJSON, copies prior values over
// redacted placeholders, and returns canonical JSON. Empty prior is a no-op.
//
// When the API payload matches the prior config after stripping API-only fields,
// restoring redacted secrets, and filling keys the API omitted, the prior string
// is returned unchanged. Terraform then sees the same bytes it planned. That
// avoids "inconsistent result after apply" on sensitive JSON, where Terraform
// hides the real diff.
func RestoreRedactedJSON(apiJSON, priorJSON string) (string, error) {
	if priorJSON == "" || priorJSON == "null" {
		return apiJSON, nil
	}

	var api interface{}
	if err := json.Unmarshal([]byte(apiJSON), &api); err != nil {
		return "", err
	}
	var prior interface{}
	if err := json.Unmarshal([]byte(priorJSON), &prior); err != nil {
		return apiJSON, nil
	}

	StripAPIFields(api)
	aligned := alignToPrior(api, prior)
	if jsonSemanticallyEqual(aligned, prior) {
		return priorJSON, nil
	}

	out, err := json.Marshal(aligned)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// alignToPrior rebuilds prior's shape from the API value.
// API-only keys are dropped. Redacted secrets and keys the API omitted keep
// the prior value. JSON strings that parse to the same document keep the
// prior text, so customBody key order does not drift.
func alignToPrior(api, prior interface{}) interface{} {
	switch p := prior.(type) {
	case map[string]interface{}:
		am, ok := api.(map[string]interface{})
		if !ok {
			if jql, ok := jqlString(api); ok {
				if s, ok := p["jql"].(string); ok && s == jql {
					return prior
				}
			}
			return prior
		}
		out := make(map[string]interface{}, len(p))
		for k, pv := range p {
			av, exists := am[k]
			if !exists || redacted(av, pv) {
				out[k] = pv
				continue
			}
			out[k] = alignToPrior(av, pv)
		}
		return out
	case []interface{}:
		aa, ok := api.([]interface{})
		if !ok {
			// Jira sometimes returns null for an empty list such as actions or fromStatus.
			if api == nil && len(p) == 0 {
				return prior
			}
			return api
		}
		if len(aa) != len(p) {
			return api
		}
		out := make([]interface{}, len(p))
		for i, pv := range p {
			av := matchAPIElem(pv, aa, i)
			if av == nil {
				out[i] = pv
				continue
			}
			out[i] = alignToPrior(av, pv)
		}
		return out
	case string:
		if as, ok := api.(string); ok && sameJSONText(as, p) {
			return p
		}
		if jql, ok := jqlString(api); ok && jql == p {
			return p
		}
		if redacted(api, p) {
			return p
		}
		return api
	default:
		if redacted(api, p) {
			return p
		}
		return api
	}
}

// matchAPIElem finds the API element that corresponds to a prior element.
func matchAPIElem(priorElem interface{}, api []interface{}, index int) interface{} {
	if pm, ok := priorElem.(map[string]interface{}); ok {
		if name, ok := pm["name"].(string); ok && name != "" {
			for _, ae := range api {
				if am, ok := ae.(map[string]interface{}); ok {
					if an, ok := am["name"].(string); ok && an == name {
						return ae
					}
				}
			}
		}
	}
	if index < len(api) {
		return api[index]
	}
	return nil
}

func redacted(apiVal, priorVal interface{}) bool {
	if apiVal == nil {
		s, ok := priorVal.(string)
		return ok && s != ""
	}
	s, ok := apiVal.(string)
	return ok && s == RedactedValue
}

func jqlString(v interface{}) (string, bool) {
	m, ok := v.(map[string]interface{})
	if !ok || len(m) != 1 {
		return "", false
	}
	s, ok := m["jql"].(string)
	return s, ok
}

func sameJSONText(a, b string) bool {
	var ai, bi interface{}
	if json.Unmarshal([]byte(a), &ai) != nil || json.Unmarshal([]byte(b), &bi) != nil {
		return false
	}
	return jsonSemanticallyEqual(ai, bi)
}

func jsonSemanticallyEqual(a, b interface{}) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}
