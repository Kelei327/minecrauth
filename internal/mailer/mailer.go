// Package mailer defines the email delivery abstraction and its implementations.
package mailer

import (
	"context"
	"log/slog"
)

// Mailer defines the contract for delivering HTML emails.
type Mailer interface {
	Send(ctx context.Context, to, subject, htmlBody string) error
}

// NoopMailer implements the Mailer interface by logging messages instead of sending them.
type NoopMailer struct{}

// Send logs that email delivery is disabled and returns nil.
func (n *NoopMailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	slog.Info("mailer: email delivery disabled; not sending", "to", to, "subject", subject)
	return nil
}

// Compile-time assertion that NoopMailer implements Mailer.
var _ Mailer = (*NoopMailer)(nil)
