// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
)

// ActionEmailData holds the template fields for delivering a Minecraft-themed email.
type ActionEmailData struct {
	Title       string
	Intro       string
	ButtonLabel string
	ButtonURL   string
	Footer      string
	ServerName  string
}

const actionEmailTmplText = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.Title}}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #1a1a1a; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #1a1a1a; min-height: 100%; padding: 40px 10px;">
    <tr>
      <td align="center" valign="top">
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #2b2b2b; border: 2px solid #0e0e0e; border-top: 4px solid #3d3d3d; border-left: 4px solid #3d3d3d; border-right: 4px solid #111; border-bottom: 4px solid #111;">
          <tr>
            <td style="padding: 40px 30px;">
              <!-- Title -->
              <h1 style="margin: 0 0 20px 0; color: #c8a032; font-family: 'Courier New', Courier, monospace; font-size: 24px; font-weight: bold; text-transform: uppercase; text-align: left;">
                {{.Title}}
              </h1>
              
              <!-- Intro -->
              <p style="margin: 0 0 30px 0; color: #e9e9e9; font-size: 16px; line-height: 1.5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: left;">
                {{.Intro}}
              </p>
              
              <!-- CTA Button -->
              {{if .ButtonURL}}
              <table border="0" cellpadding="0" cellspacing="0" style="margin: 0 0 30px 0;">
                <tr>
                  <td style="background-color: #5b8731; border: 2px solid #0e0e0e; border-top: 3px solid #70b237; border-left: 3px solid #70b237; border-bottom: 3px solid #3e5c20; border-right: 3px solid #3e5c20; text-align: center;">
                    <a href="{{.ButtonURL}}" target="_blank" style="display: inline-block; padding: 12px 24px; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 16px; font-weight: bold; text-decoration: none; text-transform: uppercase;">
                      {{.ButtonLabel}}
                    </a>
                  </td>
                </tr>
              </table>
              {{end}}
              
              <!-- Divider -->
              <hr style="border: 0; border-top: 2px solid #0e0e0e; border-bottom: 2px solid #3d3d3d; margin: 0 0 20px 0;">
              
              <!-- Fallback URL -->
              {{if .ButtonURL}}
              <p style="margin: 0 0 20px 0; color: #9a9a9a; font-size: 13px; line-height: 1.4; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; word-break: break-all; text-align: left;">
                If the button does not work, copy and paste this link into your browser:
                <br>
                <a href="{{.ButtonURL}}" style="color: #c8a032; text-decoration: none;">{{.ButtonURL}}</a>
              </p>
              {{end}}
              
              <!-- Footer -->
              {{if .Footer}}
              <p style="margin: 0 0 10px 0; color: #9a9a9a; font-size: 13px; line-height: 1.4; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: left;">
                {{.Footer}}
              </p>
              {{end}}
              
              <p style="margin: 0; color: #9a9a9a; font-size: 12px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-transform: uppercase; font-weight: bold; letter-spacing: 1px; text-align: left;">
                {{.ServerName}}
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`

var actionEmailTmpl = template.Must(template.New("actionEmail").Parse(actionEmailTmplText))

// RenderActionEmail renders a self-contained HTML email in the Minecraft aesthetic.
// Subject is formatted as "<ServerName>: <Title>". If template execution fails,
// it falls back to a basic formatted string and logs the error.
func RenderActionEmail(data ActionEmailData) (subject, htmlBody string) {
	subject = fmt.Sprintf("%s: %s", data.ServerName, data.Title)

	var buf bytes.Buffer
	if err := actionEmailTmpl.Execute(&buf, data); err != nil {
		slog.Error("mailer: failed to execute action email template", "error", err)
		// Safest fallback
		return subject, fmt.Sprintf("<h1>%s</h1><p>%s</p><p>%s</p>", data.Title, data.Intro, data.ButtonURL)
	}

	return subject, buf.String()
}
