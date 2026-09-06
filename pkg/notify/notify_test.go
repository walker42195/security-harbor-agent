package notify

import "testing"

func TestSplitRecipients(t *testing.T) {
	got := splitRecipients("a@x.se, b@y.se;c@z.se d@w.se")
	if len(got) != 4 {
		t.Fatalf("förväntade 4 mottagare, fick %v", got)
	}
}

func TestBuildMessageHeaders(t *testing.T) {
	msg := string(buildMessage("fw@x.se", "me@y.se", "Ämne", "Kropp"))
	for _, want := range []string{"From: Security Harbor <fw@x.se>", "To: me@y.se", "Subject: Ämne", "Content-Type: text/plain; charset=UTF-8", "Kropp"} {
		if !contains(msg, want) {
			t.Errorf("saknar %q i:\n%s", want, msg)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
