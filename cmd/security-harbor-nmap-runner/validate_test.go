package main

import "testing"

func TestValidateArgsAcceptsRealHandleNmapOutput(t *testing.T) {
	ok := [][]string{
		{"-n", "8.8.8.8"},
		{"-n", "-sS", "-p-", "-sV", "-sU", "-O", "-T4", "example.com"},
		{"-n", "10.0.0.0/24"},
	}
	for _, args := range ok {
		if err := validateArgs(args); err != nil {
			t.Errorf("skulle accepteras: %v -> %v", args, err)
		}
	}
	bad := [][]string{
		{"-n", "--script=http-shellshock", "10.0.0.1"},
		{"-n", "-oN", "/etc/cron.d/x", "10.0.0.1"},
		{"-n", "-iL", "/etc/passwd"},
		{"-n"},                   // inget mål
		{"-n", "a.com", "b.com"}, // två mål
		{"-n", "; rm -rf /"},
	}
	for _, args := range bad {
		if err := validateArgs(args); err == nil {
			t.Errorf("skulle AVVISAS: %v", args)
		}
	}
}
