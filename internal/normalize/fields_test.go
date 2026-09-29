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
	api := mustJSON(t, `[{
		"type": "jira.issue.outgoing.webhook",
		"value": {
			"headers": [
				{"name": "Authorization", "value": "***", "headerSecure": true},
				{"name": "X-Plain", "value": "visible", "headerSecure": false}
			]
		}
	}]`)
	prior := mustJSON(t, `[{
		"type": "jira.issue.outgoing.webhook",
		"value": {
			"headers": [
				{"name": "Authorization", "value": "real-secret", "headerSecure": true},
				{"name": "X-Plain", "value": "visible", "headerSecure": false}
			]
		}
	}]`)

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

func TestRestoreRedactedJSON_roundTripKeepsPriorBytes(t *testing.T) {
	prior := `[{"component":"CONDITION","schemaVersion":1,"type":"jira.jql.condition","value":"labels = cursor"},{"component":"ACTION","schemaVersion":1,"type":"jira.issue.outgoing.webhook","value":{"contentType":"custom","continueOnErrorEnabled":false,"customBody":"{\"description\":\"{{issue.description}}\",\"issue_key\":\"{{issue.key}}\"}","headers":[{"headerSecure":true,"name":"Authorization","value":"Bearer secret"},{"headerSecure":false,"name":"Content-Type","value":"application/json"}],"method":"POST","responseEnabled":false,"sendIssue":false,"url":"https://api2.cursor.sh/automations/webhook/abc"}}]`
	// API adds ids, redacts the bearer token, omits false booleans, and reorders customBody keys.
	api := `[{"id":"c1","component":"CONDITION","parentId":null,"conditionParentId":null,"connectionId":null,"children":[],"conditions":[],"schemaVersion":1,"type":"jira.jql.condition","value":{"jql":"labels = cursor"}},{"id":"a1","component":"ACTION","parentId":null,"children":[],"conditions":[],"connectionId":null,"schemaVersion":1,"type":"jira.issue.outgoing.webhook","value":{"url":"https://api2.cursor.sh/automations/webhook/abc","urlSecure":false,"method":"POST","contentType":"custom","customBody":"{\"issue_key\":\"{{issue.key}}\",\"description\":\"{{issue.description}}\"}","headers":[{"id":"h1","name":"Authorization","value":"***","headerSecure":true},{"id":"h2","name":"Content-Type","value":"application/json","headerSecure":false}]}}]`

	got, err := RestoreRedactedJSON(api, prior)
	if err != nil {
		t.Fatal(err)
	}
	if got != prior {
		t.Fatalf("want exact prior JSON\n got %s\nwant %s", got, prior)
	}
}

func TestRestoreRedactedJSON_createdTriggerKeepsEventFields(t *testing.T) {
	prior := `{"component":"TRIGGER","schemaVersion":1,"type":"jira.issue.event.trigger:created","value":{"eventFilters":["ari:cloud:jira:cloud:project/11492"],"eventKey":"jira:issue_created","issueEvent":"issue_created"}}`
	// StripAPIFields removes eventKey, issueEvent, and eventFilters before align.
	api := `{"component":"TRIGGER","id":"t1","schemaVersion":1,"type":"jira.issue.event.trigger:created","value":{"eventFilters":["ari:cloud:jira:cloud:project/11492"],"eventKey":"jira:issue_created","issueEvent":"issue_created"}}`

	got, err := RestoreRedactedJSON(api, prior)
	if err != nil {
		t.Fatal(err)
	}
	if got != prior {
		t.Fatalf("want exact prior JSON\n got %s\nwant %s", got, prior)
	}
}

func TestRestoreRedactedJSON_nullEmptyListKeepsPrior(t *testing.T) {
	prior := `{"actions":[],"changeType":"ANY_CHANGE","fields":[{"type":"field","value":"labels"}]}`
	api := `{"actions":null,"changeType":"ANY_CHANGE","fields":[{"type":"field","value":"labels"}]}`
	got, err := RestoreRedactedJSON(api, prior)
	if err != nil {
		t.Fatal(err)
	}
	if got != prior {
		t.Fatalf("want exact prior JSON\n got %s\nwant %s", got, prior)
	}
}

func TestRestoreRedactedJSON_reportsRealJQLChange(t *testing.T) {
	prior := `[{"type":"jira.jql.condition","value":"labels = cursor"}]`
	api := `[{"type":"jira.jql.condition","value":"labels = other"}]`
	got, err := RestoreRedactedJSON(api, prior)
	if err != nil {
		t.Fatal(err)
	}
	if got == prior {
		t.Fatal("changed JQL must not keep the prior JSON")
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
