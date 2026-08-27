package suricata

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// DisableConfPath är filen suricata-update läser för att veta vilka regler som
// ska stängas av. Den regenereras i sin helhet ur konfigurationen vid varje
// applicering — handredigering skrivs alltså över, vilket är avsikten.
//
// Ligger i agentens EGEN datakatalog, inte /etc/suricata. Katalogen
// /etc/suricata ägs av root med rättigheterna 0755, och även om agentens
// systemd-enhet har ReadWritePaths=/etc/suricata lyfter det bara den
// skrivskyddade monteringen — det ändrar inga filrättigheter. install.sh
// gruppskriver bara suricata.yaml, alltså FILEN, inte katalogen, så agenten
// kan läsa och ändra den men aldrig SKAPA något nytt där. Ett försök gav
// "open /etc/suricata/disable.conf.tmp: permission denied" (2026-08-27).
//
// Alternativet hade varit att öppna hela /etc/suricata för tjänstekontot.
// Det vore en onödig utvidgning av vad agenten får röra på en brandvägg —
// suricata-update tar sökvägen som flagga, så det behövs inte.
// Se systemd/security-harbor-suricata-update.service.
const DisableConfPath = "/var/lib/security-harbor/disable.conf"

// RulesPath är den sammanslagna regelfil suricata-update skriver.
const RulesPath = "/var/lib/suricata/rules/suricata.rules"

// Category är en regelkategori som den visas i GUI:t, härledd ur regelns
// msg-prefix ("ET MALWARE", "GPL ATTACK_RESPONSE", "SURICATA"). ET Open
// levereras som EN sammanslagen fil, så det finns ingen filstruktur att
// gruppera på — prefixet är det som faktiskt bär betydelse för en människa.
type Category struct {
	Name    string `json:"name"`
	Total   int    `json:"total"`   // regler i kategorin, oavsett status
	Enabled int    `json:"enabled"` // aktiva just nu
}

// msgRe plockar ut msg-strängen ur en regelrad. Raden kan vara aktiv
// ("alert ...") eller avstängd ("# alert ..."); suricata-update TAR INTE BORT
// avstängda regler utan kommenterar ut dem, så båda formerna måste räknas för
// att en kategori ska kunna visa "3 av 6 087 aktiva".
var msgRe = regexp.MustCompile(`^(#\s*)?(?:alert|drop|pass|reject)\b.*?\bmsg:"([^"]*)"`)

// sidRe plockar ut sid ur en regelrad.
var sidRe = regexp.MustCompile(`\bsid:\s*(\d+)`)

// CategoryOf härleder kategorinamnet ur en regels msg. ET- och GPL-regler har
// formen `ET <KATEGORI> <beskrivning>`; övriga (t.ex. Suricatas egna
// decoder-händelser) har bara ett ledord.
func CategoryOf(msg string) string {
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		return "Övrigt"
	}
	switch fields[0] {
	case "ET", "GPL", "ETPRO":
		if len(fields) >= 2 {
			return fields[0] + " " + fields[1]
		}
		return fields[0]
	default:
		return fields[0]
	}
}

// ListCategories läser regelfilen och summerar per kategori.
func ListCategories(rulesPath string) ([]Category, error) {
	f, err := os.Open(rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []Category{}, nil
		}
		return nil, err
	}
	defer f.Close()

	type counts struct{ total, enabled int }
	agg := map[string]*counts{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		m := msgRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cat := CategoryOf(m[2])
		c := agg[cat]
		if c == nil {
			c = &counts{}
			agg[cat] = c
		}
		c.total++
		// m[1] är "# " om raden är utkommenterad.
		if m[1] == "" {
			c.enabled++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	out := make([]Category, 0, len(agg))
	for name, c := range agg {
		out = append(out, Category{Name: name, Total: c.total, Enabled: c.enabled})
	}
	// Störst först — det är den ordning man vill se dem i när man ska välja
	// bort brus.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// LookupSignature returnerar msg-strängen för ett SID, så att GUI:t kan visa
// vad som tystades. Tom sträng om SID:t inte finns.
func LookupSignature(rulesPath string, sid int) (string, error) {
	f, err := os.Open(rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	want := strconv.Itoa(sid)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		sm := sidRe.FindStringSubmatch(line)
		if sm == nil || sm[1] != want {
			continue
		}
		if m := msgRe.FindStringSubmatch(line); m != nil {
			return m[2], nil
		}
	}
	return "", scanner.Err()
}

// GenerateDisableConf renderar innehållet i disable.conf ur konfigurationen.
//
// Format (suricata-update): en post per rad, antingen ett rent SID eller
// "re:<regex>" som matchas mot hela regeltexten. Kategorier stängs av med ett
// regex mot msg-prefixet, eftersom ET Open levereras sammanslaget och
// "group:<fil>" därför inte är tillgängligt för slutanvändaren.
func GenerateDisableConf(ids *config.IDSConfig) string {
	var b strings.Builder
	b.WriteString("# Genererad av Security Harbor — handredigering skrivs över.\n")
	b.WriteString("# Ändra via GUI:t (IDS -> Regler).\n")

	if ids == nil {
		return b.String()
	}

	if len(ids.DisabledCategories) > 0 {
		b.WriteString("\n# Avstängda kategorier\n")
		cats := append([]string(nil), ids.DisabledCategories...)
		sort.Strings(cats)
		for _, c := range cats {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			// Ankra mot msg:"<kategori> så att "ET INFO" inte också träffar
			// en regel vars beskrivning råkar innehålla orden längre in.
			b.WriteString("re:msg:\"" + regexp.QuoteMeta(c) + " \n")
		}
	}

	if len(ids.DisabledSignatures) > 0 {
		b.WriteString("\n# Tystade enskilda signaturer\n")
		sigs := append([]config.DisabledSignature(nil), ids.DisabledSignatures...)
		sort.Slice(sigs, func(i, j int) bool { return sigs[i].SID < sigs[j].SID })
		for _, s := range sigs {
			if s.SID <= 0 {
				continue
			}
			if s.Signature != "" {
				b.WriteString("# " + sanitizeComment(s.Signature) + "\n")
			}
			b.WriteString(strconv.Itoa(s.SID) + "\n")
		}
	}

	return b.String()
}

// sanitizeComment gör en signaturtext säker att skriva som kommentarrad.
func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// WriteDisableConf skriver disable.conf atomiskt.
func WriteDisableConf(path string, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return fmt.Errorf("kunde inte skriva %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("kunde inte flytta %s till %s: %w", tmp, path, err)
	}
	return nil
}

// UpdateUnit är den privilegierade oneshot-enhet som kör suricata-update och
// därefter laddar om reglerna i den körande Suricata (ExecStartPost).
const UpdateUnit = "security-harbor-suricata-update.service"

// ApplyRuleSelection skriver disable.conf och startar om regeluppdateringen.
//
// Starten sker med --no-block: suricata-update tar ~40-60 s (68 500 regler ska
// läsas, filtreras och skrivas) och ett HTTP-anrop ska inte hänga så länge.
// Anroparen får följa förloppet via RuleUpdateStatus.
func ApplyRuleSelection(ctx context.Context, ids *config.IDSConfig, disableConfPath string) error {
	if disableConfPath == "" {
		disableConfPath = DisableConfPath
	}
	if err := WriteDisableConf(disableConfPath, GenerateDisableConf(ids)); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "systemctl", "start", "--no-block", UpdateUnit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kunde inte starta %s: %w - output: %s", UpdateUnit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RuleUpdateStatus svarar på om regeluppdateringen fortfarande kör.
// "activating"/"active" = pågår, "inactive" = klar, "failed" = misslyckades.
func RuleUpdateStatus(ctx context.Context) string {
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", UpdateUnit).Output()
	st := strings.TrimSpace(string(out))
	if st == "" {
		return "unknown"
	}
	return st
}

// ReadDisableConf läser en befintlig disable.conf och återvinner tystade
// signaturer och kategorier om konfigurationsfilen skulle sakna dem.
func ReadDisableConf(disableConfPath string) ([]config.DisabledSignature, []string) {
	if disableConfPath == "" {
		disableConfPath = DisableConfPath
	}
	f, err := os.Open(disableConfPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var sigs []config.DisabledSignature
	var cats []string
	scanner := bufio.NewScanner(f)
	var lastComment string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if !strings.HasPrefix(comment, "Genererad") && !strings.HasPrefix(comment, "Ändra") && !strings.HasPrefix(comment, "Tystade") && !strings.HasPrefix(comment, "Avstängda") {
				lastComment = comment
			}
			continue
		}
		if strings.HasPrefix(line, "re:msg:\"") {
			raw := strings.TrimPrefix(line, "re:msg:\"")
			raw = strings.TrimSuffix(raw, " ")
			raw = strings.TrimSuffix(raw, "\"")
			if raw != "" {
				cats = append(cats, raw)
			}
			continue
		}
		if sid, err := strconv.Atoi(line); err == nil && sid > 0 {
			sigText := lastComment
			if sigText == "" {
				sigText, _ = LookupSignature(RulesPath, sid)
			}
			sigs = append(sigs, config.DisabledSignature{
				SID:       sid,
				Signature: sigText,
			})
			lastComment = ""
		}
	}
	return sigs, cats
}
