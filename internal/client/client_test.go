package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsNotFound(t *testing.T) {
	err := &NotFoundError{Op: "get", UUID: "abc"}
	if !IsNotFound(err) {
		t.Fatal("expected IsNotFound")
	}
	if IsNotFound(nil) {
		t.Fatal("nil should not be not-found")
	}
}

func TestGetRuleRaw_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)

	c := &Client{BaseURL: ts.URL, HTTPClient: ts.Client()}
	_, err := c.GetRuleRaw("missing")
	if !IsNotFound(err) {
		t.Fatalf("got %v, want NotFoundError", err)
	}
}

func TestDeleteRule_successAndNotFound(t *testing.T) {
	var sawContentType string
	var sawMethod string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawContentType = r.Header.Get("Content-Type")
		if strings.HasSuffix(r.URL.Path, "/gone") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)

	c := &Client{BaseURL: ts.URL, HTTPClient: ts.Client()}
	if err := c.DeleteRule("ok"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if sawMethod != http.MethodDelete {
		t.Errorf("method: got %s, want DELETE", sawMethod)
	}
	if sawContentType != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", sawContentType)
	}

	if err := c.DeleteRule("gone"); err != nil {
		t.Fatalf("delete 404 should succeed: %v", err)
	}
}

func TestDeleteRule_error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"enabled"}`)
	}))
	t.Cleanup(ts.Close)

	c := &Client{BaseURL: ts.URL, HTTPClient: ts.Client()}
	err := c.DeleteRule("enabled")
	if err == nil {
		t.Fatal("expected error")
	}
}
