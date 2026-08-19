package syslog

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestGenerateConfigDisabled(t *testing.T) {
	cfg := &config.Config{}
	conf, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig misslyckades: %v", err)
	}
	if conf != "" {
		t.Fatalf("förväntade tom config när Syslog är nil, fick: %q", conf)
	}

	cfg.Syslog = &config.SyslogConfig{Enabled: false, Host: "10.0.0.50"}
	conf, err = GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig misslyckades: %v", err)
	}
	if conf != "" {
		t.Fatalf("förväntade tom config när Enabled=false, fick: %q", conf)
	}
}

func TestGenerateConfigUDP(t *testing.T) {
	cfg := &config.Config{Syslog: &config.SyslogConfig{
		Enabled:  true,
		Host:     "10.0.0.50",
		Port:     514,
		Protocol: "udp",
	}}
	conf, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig misslyckades: %v", err)
	}
	if !strings.Contains(conf, "*.* @10.0.0.50:514\n") {
		t.Fatalf("förväntade UDP-vidarebefordringsregel (enkelt @), fick: %q", conf)
	}
	if strings.Contains(conf, "@@") {
		t.Fatalf("UDP-config ska inte innehålla @@ (TCP-syntax): %q", conf)
	}
}

func TestGenerateConfigTCP(t *testing.T) {
	cfg := &config.Config{Syslog: &config.SyslogConfig{
		Enabled:  true,
		Host:     "10.0.0.50",
		Port:     6514,
		Protocol: "tcp",
	}}
	conf, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig misslyckades: %v", err)
	}
	if !strings.Contains(conf, "*.* @@10.0.0.50:6514\n") {
		t.Fatalf("förväntade TCP-vidarebefordringsregel (dubbel @@), fick: %q", conf)
	}
}

func TestGenerateConfigDefaultPort(t *testing.T) {
	cfg := &config.Config{Syslog: &config.SyslogConfig{
		Enabled: true,
		Host:    "10.0.0.50",
	}}
	conf, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig misslyckades: %v", err)
	}
	if !strings.Contains(conf, ":514\n") {
		t.Fatalf("förväntade standardport 514 när Port=0, fick: %q", conf)
	}
}

func TestGenerateConfigMissingHost(t *testing.T) {
	cfg := &config.Config{Syslog: &config.SyslogConfig{Enabled: true}}
	if _, err := GenerateConfig(cfg); err == nil {
		t.Fatal("förväntade fel när Host saknas, fick nil")
	}
}
