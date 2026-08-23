// Package updater hanterar självuppdatering av brandväggens firmware-bunt
// (agent-binärer + webb-GUI) från en publik GitHub Release.
//
// Integritet och äkthet säkras med TVÅ oberoende kontroller:
//   - SHA256 mot manifestet (fångar trasig/avbruten nedladdning),
//   - en Ed25519-signatur (minisign-stil) över tarbollen, verifierad mot en
//     INBYGGD publik nyckel (PublicKeyB64). Även ett kapat GitHub-konto som
//     styr både artefakt och manifest kan därför inte pusha en förfalskad
//     uppdatering — den privata nyckeln finns aldrig i repot eller på servern.
//
// Den oprivilegierade agenten laddar ner + verifierar och stagear bunten; den
// faktiska installationen görs av en root-oneshot (systemd) som OM-verifierar
// signaturen som root innan den packar upp och kör install.sh (se
// systemd/update-runner.sh) — agenten är den mindre betrodda parten.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PublicKeyB64 är den inbyggda publika Ed25519-nyckeln som release-bunten
// signeras mot. Den privata motparten hålls HELT utanför repot
// (~/.config/security-harbor/release-signing.key hos den som bygger releaser).
const PublicKeyB64 = "++tmvTzBazVx/7g2McZ+spxww1imKpdUM/iYKFVH7So="

// ManifestURL pekar på den senaste releasens manifest via GitHubs stabila
// "releases/latest/download"-URL (kräver ett publikt repo).
const ManifestURL = "https://github.com/walker42195/security-harbor-agent/releases/latest/download/manifest.json"

// StagingDir är där en nedladdad, verifierad bunt läggs i väntan på att
// root-oneshoten installerar den. Ligger i agentens ReadWritePaths.
const StagingDir = "/var/lib/security-harbor/updates"

// StagedTarball och StagedSig är de fasta filnamnen root-runnern letar efter.
const (
	StagedTarball = "security-harbor-dist.tar.gz"
	StagedSig     = "security-harbor-dist.tar.gz.sig"
)

// Component beskriver en uppdaterbar del i manifestet.
type Component struct {
	Version      string `json:"version"`
	WebUIVersion string `json:"webui_version,omitempty"` // bara för firewall-bunten (webb-GUI:t ligger inuti)
	URL          string `json:"url,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Sig          string `json:"sig,omitempty"` // base64 Ed25519-signatur över tarbollen
}

// Manifest är releasens manifest.json.
type Manifest struct {
	Firewall *Component `json:"firewall,omitempty"` // agent + webb-GUI (installeras på brandväggen)
	Desktop  *Component `json:"desktop,omitempty"`  // desktop-appen (gui-repots egen release)
}

// VerifyEd25519 verifierar en base64-kodad signatur över data mot den inbyggda
// publika nyckeln. Används av BÅDE agenten (före staging) och root-runnern
// (via agent-binärens --verify-update) före installation.
func VerifyEd25519(data []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ogiltig inbyggd publik nyckel")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ogiltig signatur (fel format/längd)")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("signaturen matchar inte den inbyggda publika nyckeln")
	}
	return nil
}

// VerifyFile verifierar en fil på disk mot en signaturfil (base64 i sig-filen).
func VerifyFile(tarballPath, sigPath string) error {
	data, err := os.ReadFile(tarballPath)
	if err != nil {
		return fmt.Errorf("kunde inte läsa bunt: %w", err)
	}
	sigB64, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("kunde inte läsa signaturfil: %w", err)
	}
	return VerifyEd25519(data, string(sigB64))
}

// httpGet hämtar en URL med en rimlig timeout och 200-kontroll.
func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d vid hämtning av %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200*1024*1024)) // tak 200 MB
}

// FetchManifest hämtar och tolkar releasens manifest.
func FetchManifest(ctx context.Context) (*Manifest, error) {
	data, err := httpGet(ctx, ManifestURL)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("kunde inte tolka manifest: %w", err)
	}
	return &m, nil
}

// DownloadAndStage laddar ner firewall-buntens tarboll, verifierar SHA256 och
// Ed25519-signatur, och skriver bunten + signaturen till StagingDir. Returnerar
// fel om något inte stämmer — då stagas ingenting (Uppgradera-knappen ska
// förbli låst).
func DownloadAndStage(ctx context.Context, comp *Component) error {
	if comp == nil || comp.URL == "" || comp.SHA256 == "" || comp.Sig == "" {
		return fmt.Errorf("ofullständig komponent i manifestet (url/sha256/sig saknas)")
	}
	data, err := httpGet(ctx, comp.URL)
	if err != nil {
		return fmt.Errorf("nedladdning misslyckades: %w", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, comp.SHA256) {
		return fmt.Errorf("SHA256 stämmer inte (förväntade %s, fick %s)", comp.SHA256, got)
	}
	if err := VerifyEd25519(data, comp.Sig); err != nil {
		return fmt.Errorf("signaturverifiering misslyckades: %w", err)
	}
	if err := os.MkdirAll(StagingDir, 0o755); err != nil {
		return fmt.Errorf("kunde inte skapa staging-katalog: %w", err)
	}
	if err := os.WriteFile(filepath.Join(StagingDir, StagedTarball), data, 0o644); err != nil {
		return fmt.Errorf("kunde inte skriva bunt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(StagingDir, StagedSig), []byte(comp.Sig+"\n"), 0o644); err != nil {
		return fmt.Errorf("kunde inte skriva signaturfil: %w", err)
	}
	// Skriv den verifierade versionen som markör (informativt, och så GUI:t
	// kan visa vad som är redo att installeras).
	_ = os.WriteFile(filepath.Join(StagingDir, "staged-version.txt"), []byte(comp.Version+"\n"), 0o644)
	return nil
}

// ReadWebUIVersion läser version.json som skrivs in i webb-buntens rot vid
// bygget. Saknas den (äldre bunt) returneras "okänd".
func ReadWebUIVersion(webUIDir string) string {
	data, err := os.ReadFile(filepath.Join(webUIDir, "version.json"))
	if err != nil {
		return "okänd"
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &v) == nil && v.Version != "" {
		return v.Version
	}
	return "okänd"
}

// IsNewer jämför två versionssträngar (semver-ish "x.y.z", numeriskt per del).
// Icke-numeriska/ojämförbara versioner faller tillbaka på strängolikhet.
func IsNewer(available, current string) bool {
	av := parseVersion(available)
	cv := parseVersion(current)
	if av == nil || cv == nil {
		return strings.TrimSpace(available) != "" && available != current
	}
	for i := 0; i < len(av) && i < len(cv); i++ {
		if av[i] != cv[i] {
			return av[i] > cv[i]
		}
	}
	return len(av) > len(cv)
}

func parseVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}
