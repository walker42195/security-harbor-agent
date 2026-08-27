package traffic

import "strings"

// Category är en trafikkategori som den visas för användaren.
type Category string

const (
	CatStreaming Category = "streaming"
	CatSocial    Category = "social"
	CatWeb       Category = "web"
	CatGaming    Category = "gaming"
	CatCloud     Category = "cloud"
	CatUpdates   Category = "updates"
	CatAds       Category = "ads"
	CatMessaging Category = "messaging"
	CatSmartHome Category = "smarthome"
	CatWork      Category = "work"
	CatOther     Category = "other"
)

// AllCategories i den ordning de ska visas.
var AllCategories = []Category{
	CatStreaming, CatSocial, CatMessaging, CatGaming, CatWork,
	CatCloud, CatUpdates, CatSmartHome, CatAds, CatWeb, CatOther,
}

// domainRules mappar domänsuffix till kategori.
//
// Matchningen sker på SUFFIX med punktgräns: "flix.se" får aldrig träffa
// regeln för "netflix.com", och "notspotify.com" får inte träffa "spotify.com".
// Listan är medvetet kort och innehåller de tjänster som faktiskt står för
// merparten av trafiken i ett svenskt hem — en uttömmande lista vore omöjlig
// att underhålla och skulle ändå aldrig bli komplett.
var domainRules = map[string]Category{
	// Streaming (video och ljud)
	"netflix.com": CatStreaming, "nflxvideo.net": CatStreaming, "nflxso.net": CatStreaming,
	"youtube.com": CatStreaming, "googlevideo.com": CatStreaming, "ytimg.com": CatStreaming,
	"svtplay.se": CatStreaming, "svt.se": CatStreaming, "tv4play.se": CatStreaming, "tv4.se": CatStreaming,
	"viaplay.se": CatStreaming, "viaplay.com": CatStreaming, "dplay.se": CatStreaming,
	"hbomax.com": CatStreaming, "max.com": CatStreaming, "disneyplus.com": CatStreaming,
	"primevideo.com": CatStreaming, "aiv-cdn.net": CatStreaming, "twitch.tv": CatStreaming,
	"spotify.com": CatStreaming, "scdn.co": CatStreaming, "sc-cdn.net": CatStreaming,
	"plex.tv": CatStreaming, "sr.se": CatStreaming, "ttvnw.net": CatStreaming,

	// Sociala nätverk
	"facebook.com": CatSocial, "fbcdn.net": CatSocial, "instagram.com": CatSocial,
	"cdninstagram.com": CatSocial, "tiktok.com": CatSocial, "tiktokcdn.com": CatSocial,
	"twitter.com": CatSocial, "x.com": CatSocial, "twimg.com": CatSocial,
	"reddit.com": CatSocial, "redd.it": CatSocial, "linkedin.com": CatSocial,
	"snapchat.com": CatSocial, "pinterest.com": CatSocial,

	// Meddelanden och samtal
	"whatsapp.net": CatMessaging, "whatsapp.com": CatMessaging, "signal.org": CatMessaging,
	"telegram.org": CatMessaging, "t.me": CatMessaging, "discord.com": CatMessaging,
	"discordapp.com": CatMessaging, "messenger.com": CatMessaging,

	// Spel
	"steamcommunity.com": CatGaming, "steampowered.com": CatGaming, "steamstatic.com": CatGaming,
	"epicgames.com": CatGaming, "xboxlive.com": CatGaming, "playstation.net": CatGaming,
	"nintendo.net": CatGaming, "riotgames.com": CatGaming, "battle.net": CatGaming,
	"minecraft.net": CatGaming, "roblox.com": CatGaming,

	// Arbete och möten
	"teams.microsoft.com": CatWork, "zoom.us": CatWork, "slack.com": CatWork,
	"office.com": CatWork, "office365.com": CatWork, "sharepoint.com": CatWork,
	"atlassian.net": CatWork, "github.com": CatWork, "gitlab.com": CatWork,

	// Moln och lagring
	"dropbox.com": CatCloud, "icloud.com": CatCloud, "drive.google.com": CatCloud,
	"onedrive.com": CatCloud, "backblaze.com": CatCloud, "b2-api.com": CatCloud,
	"s3.amazonaws.com": CatCloud, "storage.googleapis.com": CatCloud, "mega.nz": CatCloud,

	// Uppdateringar och paket
	"windowsupdate.com": CatUpdates, "update.microsoft.com": CatUpdates,
	"swcdn.apple.com": CatUpdates, "mesu.apple.com": CatUpdates,
	"archive.ubuntu.com": CatUpdates, "security.ubuntu.com": CatUpdates,
	"debian.org": CatUpdates, "launchpad.net": CatUpdates, "docker.io": CatUpdates,
	"ghcr.io": CatUpdates, "githubusercontent.com": CatUpdates, "npmjs.org": CatUpdates,

	// Annonser och spårning
	"doubleclick.net": CatAds, "googlesyndication.com": CatAds, "googleadservices.com": CatAds,
	"google-analytics.com": CatAds, "googletagmanager.com": CatAds, "scorecardresearch.com": CatAds,
	"adnxs.com": CatAds, "criteo.com": CatAds, "taboola.com": CatAds, "outbrain.com": CatAds,

	// Smarta hem och IoT
	"tuyaeu.com": CatSmartHome, "tuya.com": CatSmartHome, "shelly.cloud": CatSmartHome,
	"philips-hue.com": CatSmartHome, "meethue.com": CatSmartHome, "sonos.com": CatSmartHome,
	"nest.com": CatSmartHome, "ring.com": CatSmartHome, "tplinkcloud.com": CatSmartHome,
	"ewelink.cc": CatSmartHome, "home-assistant.io": CatSmartHome,
}

// Classify avgör kategori för ett domännamn.
//
// Okända domäner blir CatWeb, inte CatOther: en uppslagen domän ÄR
// webbtrafik i någon mening, medan CatOther är reserverad för flöden vi inte
// kunde knyta något namn till alls (t.ex. rå IP-trafik utan TLS-handskakning).
func Classify(domain string) Category {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return CatOther
	}
	// Prova hela namnet och därefter varje kortare suffix: för
	// "a.b.netflix.com" testas i tur och ordning hela namnet, "b.netflix.com"
	// och "netflix.com".
	for {
		if c, ok := domainRules[d]; ok {
			return c
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			break // kvar är bara toppdomänen
		}
	}
	return CatWeb
}
