package normalize

import (
	"encoding/json"
	"testing"
)

func TestStripAPIFields_urlSecureAndHeaderID(t *testing.T) {
	raw := `{
		"component": "ACTION",
		"id": "comp-1",
		"parentId": null,
		"conditionParentId": null,
		"connectionId": null,
		"children": [],
		"conditions": [],
		"type": "jira.issue.outgoing.webhook",
		"value": {
			"url": "https://example.com",
			"urlSecure": false,
			"eventFilters": ["ari:cloud:jira::site/x"],
			"headers": [
				{"id": null, "name": "Authorization", "value": "secret", "headerSecure": true}
			]
		}
	}`

	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	StripAPIFields(v)

	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"id", "parentId", "conditionParentId", "connectionId", "children", "conditions"} {
		if _, ok := got[key]; ok {
			t.Errorf("expected %s to be stripped, still present", key)
		}
	}

	val := got["value"].(map[string]interface{})
	if _, ok := val["urlSecure"]; ok {
		t.Error("expected urlSecure to be stripped")
	}
	if _, ok := val["eventFilters"]; ok {
		t.Error("expected eventFilters to be stripped")
	}
	headers := val["headers"].([]interface{})
	h := headers[0].(map[string]interface{})
	if _, ok := h["id"]; ok {
		t.Error("expected header id to be stripped")
	}
	if h["value"] != "secret" {
		t.Errorf("header value: got %v", h["value"])
	}
}

func TestRestoreRedactedSecrets_headersAndWebhookToken(t *testing.T) {
	api := mustJSON(t, `[
		{
			"type": "jira.issue.outgoing.webhook",
			"value": {
				"headers": [
					{"name": "Authorization", "value": "***", "headerSecure": true},
					{"name": "X-Plain", "value": "visible", "headerSecure": false}
				]
			}
		}
	]`)
	prior := mustJSON(t, `[
		{
			"type": "jira.issue.outgoing.webhook",
			"value": {
				"headers": [
					{"name": "Authorization", "value": "real-secret", "headerSecure": true},
					{"name": "X-Plain", "value": "visible", "headerSecure": false}
				]
			}
		}
	]`)

	RestoreRedactedSecrets(api, prior)

	header := api.([]interface{})[0].(map[string]interface{})["value"].(map[string]interface{})["headers"].([]interface{})[0].(map[string]interface{})
	if header["value"] != "real-secret" {
		t.Errorf("secure header: got %v, want real-secret", header["value"])
	}
	plain := api.([]interface{})[0].(map[string]interface{})["value"].(map[string]interface{})["headers"].([]interface{})[1].(map[string]interface{})
	if plain["value"] != "visible" {
		t.Errorf("plain header: got %v, want visible", plain["value"])
	}

	trigAPI := mustJSON(t, `{"type":"jira.incoming.webhook","value":{"webhookToken":"***"}}`)
	trigPrior := mustJSON(t, `{"type":"jira.incoming.webhook","value":{"webhookToken":"whsec-123"}}`)
	RestoreRedactedSecrets(trigAPI, trigPrior)
	token := trigAPI.(map[string]interface{})["value"].(map[string]interface{})["webhookToken"]
	if token != "whsec-123" {
		t.Errorf("webhookToken: got %v, want whsec-123", token)
	}
}

func TestRestoreRedactedJSON_emptyPrior(t *testing.T) {
	api := `{"value":"***"}`
	got, err := RestoreRedactedJSON(api, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != api {
		t.Errorf("empty prior should be a no-op, got %s", got)
	}
}

func mustJSON(t *testing.T, s string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}
