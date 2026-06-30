// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package httpserver_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSpaAndStaticAssets(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	client := ts.Client()

	// 1. Test GET / serves index.html
	res, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected GET / to return 200, got %d", res.StatusCode)
	}
	contentType := res.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type to contain text/html, got %q", contentType)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read GET / body: %v", err)
	}
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, `<div id="app">`) {
		t.Errorf("expected body to contain '<div id=\"app\">', got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `<script type="module" src="/static/app.js">`) {
		t.Errorf("expected body to contain the script tag, got: %s", bodyStr)
	}

	// 2. Test GET /login also serves index.html
	resLogin, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	defer resLogin.Body.Close()

	if resLogin.StatusCode != http.StatusOK {
		t.Errorf("expected GET /login to return 200, got %d", resLogin.StatusCode)
	}
	bodyLoginBytes, _ := io.ReadAll(resLogin.Body)
	if string(bodyLoginBytes) != bodyStr {
		t.Errorf("expected /login to serve exact same index.html as /")
	}

	// 3. Test GET /static/app.js serves the javascript file
	resJS, err := client.Get(ts.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js failed: %v", err)
	}
	defer resJS.Body.Close()

	if resJS.StatusCode != http.StatusOK {
		t.Errorf("expected GET /static/app.js to return 200, got %d", resJS.StatusCode)
	}
	jsBytes, err := io.ReadAll(resJS.Body)
	if err != nil {
		t.Fatalf("failed to read JS body: %v", err)
	}
	if len(jsBytes) == 0 {
		t.Errorf("expected /static/app.js content to be non-empty")
	}
	if !strings.Contains(string(jsBytes), "minecrauth Vue SPA app.js") {
		t.Errorf("expected /static/app.js content to contain our javascript text")
	}

	// 4. Test GET /web/api/config serves JSON and is NOT intercepted by the SPA handler
	resConfig, err := client.Get(ts.URL + "/web/api/config")
	if err != nil {
		t.Fatalf("GET /web/api/config failed: %v", err)
	}
	defer resConfig.Body.Close()

	if resConfig.StatusCode != http.StatusOK {
		t.Errorf("expected GET /web/api/config to return 200, got %d", resConfig.StatusCode)
	}
	configContentType := resConfig.Header.Get("Content-Type")
	if !strings.Contains(configContentType, "application/json") {
		t.Errorf("expected JSON content-type for config endpoint, got %q", configContentType)
	}

	var configMap map[string]interface{}
	if err := json.NewDecoder(resConfig.Body).Decode(&configMap); err != nil {
		t.Errorf("failed to decode config JSON: %v", err)
	}

	if _, ok := configMap["allowSkins"]; !ok {
		t.Errorf("expected config response to contain 'allowSkins' key")
	}
}
