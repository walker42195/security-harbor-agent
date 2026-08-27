package traffic

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Category{
		"netflix.com":                       CatStreaming,
		"ipv4-c001.lhr001.ix.nflxvideo.net": CatStreaming,
		"rr3---sn-4g5e6nsz.googlevideo.com": CatStreaming,
		"www.svtplay.se":                    CatStreaming,
		"api.spotify.com":                   CatStreaming,
		"graph.instagram.com":               CatSocial,
		"web.whatsapp.com":                  CatMessaging,
		"steamcdn-a.akamaihd.net":           CatWeb, // akamai är inte spelspecifikt
		"cdn.steamstatic.com":               CatGaming,
		"archive.ubuntu.com":                CatUpdates,
		"stats.g.doubleclick.net":           CatAds,
		"mqtt.tuyaeu.com":                   CatSmartHome,
		"nagot.helt.okant.example":          CatWeb,
		"":                                  CatOther,
	}
	for domain, want := range cases {
		if got := Classify(domain); got != want {
			t.Errorf("Classify(%q) = %q, ville ha %q", domain, got, want)
		}
	}
}

func TestClassifyMatchesOnDotBoundary(t *testing.T) {
	// Suffixmatchning utan punktgräns skulle låta "notspotify.com" träffa
	// regeln för "spotify.com" — precis den sortens tyst felklassificering
	// som gör statistik oanvändbar.
	if got := Classify("notspotify.com"); got == CatStreaming {
		t.Error("notspotify.com klassades som spotify")
	}
	if got := Classify("evil-netflix.com"); got == CatStreaming {
		t.Error("evil-netflix.com klassades som netflix")
	}
	// Men en riktig underdomän ska träffa.
	if got := Classify("api.v2.spotify.com"); got != CatStreaming {
		t.Errorf("api.v2.spotify.com = %q", got)
	}
}

func TestClassifyIsCaseAndDotInsensitive(t *testing.T) {
	// Suricata skriver ibland SNI med avslutande punkt eller versaler.
	for _, d := range []string{"NETFLIX.COM", "netflix.com.", " Netflix.Com "} {
		if got := Classify(d); got != CatStreaming {
			t.Errorf("Classify(%q) = %q", d, got)
		}
	}
}
