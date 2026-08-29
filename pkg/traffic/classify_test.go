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

// Domänerna nedan är de som faktiskt bar trafiken från en Prime Video-strömmande
// enhet på en skarp installation 2026-08-29 (10.0.0.124, 15,1 GB på ett dygn).
// Innan hostPatterns fanns hamnade 15,86 GB av dem i CatWeb och bara 0,01 GB
// (Netflix telemetri på huvuddomänen) i CatStreaming.
func TestClassifyStreamingCDNs(t *testing.T) {
	streaming := []string{
		"a203vod-dash-pv-ta-amazon.akamaized.net",
		"a57vod-dash-pv-ta-amazon.akamaized.net",
		"avoddashs3ww-a.akamaihd.net",
		"a99avoddashs3ww-a.akamaihd.net",
		"abjwbecaaaaaaaamfdyvcdwqyxvt5.vod-dash.main.amazon.pv-cdn.net",
		"abjwbecaaaaaaaamaqemnxccjklfj.ta.mid-pop-vod-dash.main.amazon.pv-cdn.net",
		"piv-ignx-a2cvvmldxggrii-0.api.amazonvideo.com",
		"ab8mt4dd97et.api.amazonvideo.com",
		"pixel.disco.skyshowtime.com",
		"img.tv4.incomet.io",
		"nrdp26.logs.netflix.com",
	}
	for _, d := range streaming {
		if got := Classify(d); got != CatStreaming {
			t.Errorf("Classify(%q) = %q, ville ha %q", d, got, CatStreaming)
		}
	}

	// Delade CDN:er får ALDRIG blanketklassas som streaming — de bär allt.
	// Bara värdnamn med ett streaming-specifikt mönster ska fångas.
	web := []string{
		"images-eu.ssl-images-amazon.com",
		"www.gstatic.com",
		"cdn.example.akamaized.net",
		"static.akamaihd.net",
		"a1234.g.akamai.net",
	}
	for _, d := range web {
		if got := Classify(d); got == CatStreaming {
			t.Errorf("Classify(%q) = %q, skulle INTE vara streaming", d, got)
		}
	}
}
