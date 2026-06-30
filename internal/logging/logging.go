// Package logging provides utilities for setting up the application's slog logger.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Setup initializes and returns a new slog.Logger configured with the given format and level.
// Valid values for format are "json" (default) or "text".
// Valid values for level are "debug", "info" (default), "warn", "error" (case-insensitive).
//
// Ref: https://pkg.go.dev/log/slog
func Setup(format, level string) *slog.Logger {
	format = strings.ToLower(format)
	levelStr := strings.ToUpper(level)

	var slogLevel slog.Level
	switch levelStr {
	case "DEBUG":
		slogLevel = slog.LevelDebug
	case "INFO":
		slogLevel = slog.LevelInfo
	case "WARN":
		slogLevel = slog.LevelWarn
	case "ERROR":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
