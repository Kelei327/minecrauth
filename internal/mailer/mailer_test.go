// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"context"
	"testing"
)

func TestNoopMailer_Send(t *testing.T) {
	var m Mailer = &NoopMailer{}
	ctx := context.Background()
	err := m.Send(ctx, "player@example.com", "Welcome!", "<h1>Welcome</h1>")
	if err != nil {
		t.Fatalf("unexpected error from NoopMailer.Send: %v", err)
	}
}

func TestNewSMTPMailer_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SMTPConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
				From: "auth@example.com",
			},
			wantErr: false,
		},
		{
			name: "missing host",
			cfg: SMTPConfig{
				Port: 587,
				From: "auth@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing from",
			cfg: SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSMTPMailer(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSMTPMailer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
