// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics manages the Prometheus metrics registry and the registered metrics vectors.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// New creates and registers the required HTTP metrics.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "minecrauth_http_requests_total",
			Help: "Total number of HTTP requests processed.",
		},
		[]string{"method", "route", "status"},
	)

	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "minecrauth_http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)

	reg.MustRegister(requests)
	reg.MustRegister(duration)

	return &Metrics{
		registry: reg,
		requests: requests,
		duration: duration,
	}
}

// Handler returns an http.Handler that serves the Prometheus metrics page.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Observe records request attributes and latency.
func (m *Metrics) Observe(method, route string, status int, d time.Duration) {
	statusStr := strconv.Itoa(status)
	m.requests.WithLabelValues(method, route, statusStr).Inc()
	m.duration.WithLabelValues(method, route).Observe(d.Seconds())
}
