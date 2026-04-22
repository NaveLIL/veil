// Package metrics centralises Prometheus instrumentation for veil-server.
//
// All metrics are registered against the default registry exposed by
// promhttp.Handler() and use the `veil_` prefix so they namespace cleanly
// alongside other services scraped by the same Prometheus instance.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTPRequestsTotal counts every HTTP request that flows through the
	// gateway, broken down by method, path template and status family.
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "veil_http_requests_total",
			Help: "Total HTTP requests processed by the veil gateway.",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration tracks request latency in seconds.
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "veil_http_request_duration_seconds",
			Help:    "Latency of HTTP requests handled by the veil gateway.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms .. ~4s
		},
		[]string{"method", "path"},
	)

	// WSConnectionsActive is updated by the gateway hub to reflect the
	// current number of established WebSocket connections.
	WSConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "veil_ws_connections_active",
		Help: "Currently established WebSocket connections.",
	})

	// WSConnectionsTotal counts lifetime accepted WS connections.
	WSConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "veil_ws_connections_total",
		Help: "Total WebSocket connections accepted since process start.",
	})

	// WSAuthFailuresTotal counts WS handshake auth failures.
	WSAuthFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "veil_ws_auth_failures_total",
		Help: "Total WebSocket connections rejected due to failed authentication.",
	})

	// WSRefusedTotal counts WS connections refused before/at the upgrade
	// step, broken down by reason ("ip_cap", "upgrade_error", ...).
	WSRefusedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "veil_ws_refused_total",
			Help: "WebSocket connections refused at handshake time.",
		},
		[]string{"reason"},
	)

	// WSMessagesTotal counts inbound protobuf messages from clients.
	WSMessagesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "veil_ws_messages_total",
			Help: "Total inbound WebSocket protocol messages by kind.",
		},
		[]string{"kind"},
	)
)

func init() {
	prometheus.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		WSConnectionsActive,
		WSConnectionsTotal,
		WSAuthFailuresTotal,
		WSRefusedTotal,
		WSMessagesTotal,
	)
}

// Handler returns the http.Handler that exposes registered metrics in
// Prometheus text exposition format.
func Handler() http.Handler { return promhttp.Handler() }

// ObserveHTTP records both the counter and histogram observations for a
// single completed HTTP request. Path is expected to be already normalised
// to a low-cardinality template (e.g. "/v1/messages") to avoid metric
// explosion from id-bearing URLs.
func ObserveHTTP(method, path string, status int, dur time.Duration) {
	HTTPRequestsTotal.WithLabelValues(method, path, strconv.Itoa(status)).Inc()
	HTTPRequestDuration.WithLabelValues(method, path).Observe(dur.Seconds())
}
