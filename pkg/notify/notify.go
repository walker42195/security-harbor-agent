// Package notify skickar e-postnotifieringar från brandväggen (Fas 14) —
// t.ex. när en tjänst hamnar i fel-läge eller en IP auto-blockeras.
package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Send skickar ett mejl enligt cfg. security: "starttls" (587), "tls" (465,
// implicit TLS från start) eller "none" (25, ingen kryptering). Blockerar tills
// mejlet skickats eller timeout (10s).
func Send(cfg *config.NotificationConfig, subject, body string) error {
	if cfg == nil || !cfg.Enabled {
		return fmt.Errorf("notifieringar är avstängda")
	}
	if cfg.SMTPHost == "" || cfg.FromAddr == "" || cfg.ToAddr == "" {
		return fmt.Errorf("SMTP-server, avsändare och mottagare måste anges")
	}
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, fmt.Sprintf("%d", port))

	msg := buildMessage(cfg.FromAddr, cfg.ToAddr, subject, body)

	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}

	switch strings.ToLower(cfg.Security) {
	case "tls": // implicit TLS (t.ex. 465)
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS-anslutning misslyckades: %w", err)
		}
		return sendOverConn(conn, cfg.SMTPHost, auth, cfg.FromAddr, cfg.ToAddr, msg)
	case "none": // ingen kryptering (t.ex. 25)
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("anslutning misslyckades: %w", err)
		}
		return sendOverConn(conn, cfg.SMTPHost, auth, cfg.FromAddr, cfg.ToAddr, msg)
	default: // "starttls" (t.ex. 587)
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("anslutning misslyckades: %w", err)
		}
		c, err := smtp.NewClient(conn, cfg.SMTPHost)
		if err != nil {
			conn.Close()
			return err
		}
		defer c.Close()
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS misslyckades: %w", err)
			}
		}
		return finish(c, auth, cfg.FromAddr, cfg.ToAddr, msg)
	}
}

func sendOverConn(conn net.Conn, host string, auth smtp.Auth, from, to string, msg []byte) error {
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	return finish(c, auth, from, to, msg)
}

func finish(c *smtp.Client, auth smtp.Auth, from, to string, msg []byte) error {
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP-autentisering misslyckades: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range splitRecipients(to) {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func splitRecipients(to string) []string {
	parts := strings.FieldsFunc(to, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: Security Harbor <%s>\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
