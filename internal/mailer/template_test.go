package mailer

import (
	"strings"
	"testing"
)

func TestRenderActionEmail(t *testing.T) {
	data := ActionEmailData{
		Title:       "Verify <Your> Email",
		Intro:       "Please click the button to verify your email address.",
		ButtonLabel: "Verify Now",
		ButtonURL:   "https://minecrauth.example.com/verify?token=123&user=abc",
		Footer:      "If you did not request this, please ignore.",
		ServerName:  "My Craft Server",
	}

	subject, htmlBody := RenderActionEmail(data)

	// Check Subject
	if !strings.Contains(subject, "Verify <Your> Email") {
		t.Errorf("subject %q should contain Title", subject)
	}
	if !strings.Contains(subject, "My Craft Server") {
		t.Errorf("subject %q should contain ServerName", subject)
	}

	// Check HTML body contains essential components
	if !strings.Contains(htmlBody, "Please click the button to verify your email address.") {
		t.Errorf("htmlBody should contain Intro")
	}
	if !strings.Contains(htmlBody, "Verify Now") {
		t.Errorf("htmlBody should contain ButtonLabel")
	}
	if !strings.Contains(htmlBody, "My Craft Server") {
		t.Errorf("htmlBody should contain ServerName")
	}

	// Check that ButtonURL (href) is in the HTML.
	// Since URL contains "&", we check that it is escaped in href as "&amp;" due to html/template
	escapedURL := "https://minecrauth.example.com/verify?token=123&amp;user=abc"
	if !strings.Contains(htmlBody, escapedURL) {
		t.Errorf("htmlBody should contain escaped ButtonURL: expected %q", escapedURL)
	}

	// Check that HTML special characters in Title are escaped
	escapedTitle := "Verify &lt;Your&gt; Email"
	if !strings.Contains(htmlBody, escapedTitle) {
		t.Errorf("htmlBody should contain escaped Title: expected %q", escapedTitle)
	}

	// Assert no border-radius or linear-gradient to preserve Minecraft style
	if strings.Contains(htmlBody, "border-radius") {
		t.Errorf("htmlBody should not contain 'border-radius'")
	}
	if strings.Contains(htmlBody, "linear-gradient") {
		t.Errorf("htmlBody should not contain 'linear-gradient'")
	}
}
