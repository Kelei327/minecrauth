// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wneessen/go-mail"
)

// SMTPConfig holds the configuration for the SMTP mailer.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLSMode  string // "starttls", "tls", or "none"
}

// SMTPMailer delivers HTML emails via SMTP.
type SMTPMailer struct {
	cfg SMTPConfig
}

// NewSMTPMailer constructs a new SMTPMailer after validating the config.
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp: Host is required")
	}
	if cfg.From == "" {
		return nil, errors.New("smtp: From address is required")
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// Send delivers an HTML email with the given subject and body to the recipient.
func (s *SMTPMailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	msg := mail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return fmt.Errorf("smtp: invalid from address %q: %w", s.cfg.From, err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("smtp: invalid recipient address %q: %w", to, err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, htmlBody)

	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
	}

	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password),
		)
	}

	switch strings.ToLower(s.cfg.TLSMode) {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	case "starttls":
		fallthrough
	default:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("smtp: failed to construct client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("smtp: failed to deliver email: %w", err)
	}

	return nil
}

// Compile-time assertion that SMTPMailer implements Mailer.
var _ Mailer = (*SMTPMailer)(nil)
