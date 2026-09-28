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
// "***" placeholders, and returns canonical JSON. Empty prior is a no-op.
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

	RestoreRedactedSecrets(api, prior)
	out, err := json.Marshal(api)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
