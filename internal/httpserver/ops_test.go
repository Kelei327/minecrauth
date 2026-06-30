// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package httpserver_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOpsEndpoints(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)
	defer ts.Close()

	client := ts.Client()

	// 1. GET /healthz
	t.Run("GET /healthz", func(t *testing.T) {
		res, err := client.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("failed to GET /healthz: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("failed to read /healthz body: %v", err)
		}

		if !strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("expected body to contain status ok, got %s", string(body))
		}

		contentType := res.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			t.Errorf("expected JSON Content-Type, got %s", contentType)
		}
	})

	// 2. GET /readyz
	t.Run("GET /readyz", func(t *testing.T) {
		res, err := client.Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("failed to GET /readyz: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", res.StatusCode)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("failed to read /readyz body: %v", err)
		}

		if !strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("expected body to contain status ok, got %s", string(body))
		}

		contentType := res.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			t.Errorf("expected JSON Content-Type, got %s", contentType)
		}
	})

	// 3. GET /metrics and checking content & assertion on hit count
	t.Run("GET /metrics", func(t *testing.T) {
		// First, fetch /healthz to make sure the metrics middleware registers a hit for that route.
		resHealth, err := client.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("failed to request /healthz for metric increment: %v", err)
		}
		resHealth.Body.Close()

		// Now scrape the metrics
		res, err := client.Get(ts.URL + "/metrics")
		if err != nil {
			t.Fatalf("failed to GET /metrics: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", res.StatusCode)
		}

		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("failed to read /metrics body: %v", err)
		}
		body := string(bodyBytes)

		// Assert body contains required metric definitions
		if !strings.Contains(body, "minecrauth_http_requests_total") {
			t.Errorf("metrics output does not contain minecrauth_http_requests_total")
		}
		if !strings.Contains(body, "minecrauth_http_request_duration_seconds") {
			t.Errorf("metrics output does not contain minecrauth_http_request_duration_seconds")
		}

		// Assert on the scraped text showing a counter value >= 1 for /healthz.
		// Since net/http sets Pattern to "GET /healthz" or "/healthz" depending on the registration style.
		// Let's check for the existence of the label combinations.
		// The route pattern for "GET /healthz" is exactly "GET /healthz" under Go's new mux.
		// So the metric would look like:
		// minecrauth_http_requests_total{method="GET",route="GET /healthz",status="200"}
		expectedMetricLinePart1 := `minecrauth_http_requests_total{`
		expectedMetricLinePart2 := `route="GET /healthz"`

		if !strings.Contains(body, expectedMetricLinePart1) || !strings.Contains(body, expectedMetricLinePart2) {
			t.Errorf("metrics does not contain request count for GET /healthz. Scraped metrics:\n%s", body)
		}
	})
}
