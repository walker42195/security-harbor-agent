# Security Harbor — säkerhetsmodell

Det här dokumentet beskriver hur Security Harbor faktiskt skyddar sig
själv, för den som ska granska eller lita på systemet. Skrivet 2026-08-19
(Fas 12) efter en självgenomförd säkerhetsgranskning + nmap-verifiering —
**se avsnittet "Vad detta INTE är" längst ner innan du drar slutsatser om
produktionslämplighet.**

## Autentisering & sessioner

- Inloggning (`POST /api/v1/auth/login`) verifierar mot `bcrypt`-hashade
  lösenord (`pkg/store/users.go`). Lyckad inloggning ger ett slumpat
  32-bytes hex-token (`crypto/rand`), giltigt 24 timmar, hållet i minnet
  (`pkg/api/auth.go`, `AuthManager.sessions`) — inte en JWT, ingen
  klientverifierbar signatur, bara en server-side opak session-nyckel.
- Brute-force-skydd: **två oberoende räknare** (Fas 12) — en per käll-IP
  och en per användarnamn, vardera 5 misslyckade försök → 15 minuters
  lockout. En inloggning avvisas om ANTINGEN käll-IP:t eller
  användarnamnet för tillfället är låst. Detta stänger igen ett hål som
  fanns t.o.m. Fas 11: en ren IP-baserad spärr går att kringgå genom att
  rotera käll-IP mot samma användarnamn.
- RBAC: två roller, `admin` och `viewer` (Fas 8). Alla tillståndsändrande
  endpoints kräver `admin` (`authMiddlewareAdmin`, `pkg/api/server.go`);
  `viewer` kan bara läsa.

## Kryptering at-rest

- `pkg/store/crypto.go`: AES-256-GCM, per-fil (`users.enc`,
  `wireguard_server.key.enc`, `management_tls.key.enc`,
  `openvpn_ca.key.enc`, `openvpn_server.key.enc`), fräsch slumpad nonce
  per krypteringsanrop.
- Master-nyckeln (32 bytes) **genereras slumpmässigt per installation**
  (`pkg/store/masterkey.go`, `crypto/rand`) och sparas i `baseDir/
  master.key` — INTE hårdkodad i källkoden längre (fixat i samband med att
  repot gjordes publikt, Fas 13, eftersom en hårdkodad, delad nyckel i
  publik källkod hade gjort ALLA installationers krypterade hemligheter
  dekrypterbara av vem som helst). `master.key` är inte i sig krypterad —
  det finns inget att kryptera den under — skyddet kommer från
  filsystemsrättigheter (0600) och systemd-sandboxningen. **Kvarvarande
  känd begränsning:** ingen riktig HSM/TPM/Vault-integration än — det är
  en separat, större nyckelhanteringsförbättring som fortfarande är öppen.
- **Backup-filer (Fas 10) är oberoende av master-nyckeln** — en backup
  krypteras under en scrypt-härledd nyckel från en lösenfras
  administratören själv väljer vid varje backup-tillfälle, aldrig lagrad
  någonstans. Det gör backuper portabla mellan system/binärversioner utan
  att ärva master-nyckel-svagheten ovan.

## Transport

- Management-API:t kräver HTTPS (självsignerat serverleaf-certifikat,
  genererat automatiskt vid första uppstart, `pkg/pki`). Native-klienter
  (Flutter desktop/mobil) littar via **trust-on-first-use (TOFU)
  SHA-256-fingeravtrycks-pinning** — inte en CA-kedja, eftersom det bara
  finns EN server att lita på (den egna brandväggen).
- `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY` och en enkel `Content-Security-Policy` sätts på
  alla svar (Fas 12, `securityHeadersMiddleware`), inklusive den statiska
  webb-UI-filservern.
- Ingen CORS-hantering finns eller behövs: API:t används aldrig
  cross-origin (native-appen pratar direkt mot en känd `baseUrl`, webb-GUI:t
  serveras samma-origin från agenten självt). Ingen CSRF-hantering finns
  eller behövs: autentisering går via `Authorization: Bearer`-header,
  ALDRIG cookies — klassisk CSRF (som bygger på att webbläsaren automatiskt
  skickar med cookies) biter inte på det mönstret.

## Nätverksisolering

- **Hård WAN-management-spärr**: `wanBlockMiddleware` (`pkg/api/server.go`)
  avvisar varje anrop mot Management-API:t/webb-UI:t från WAN-sidan,
  inbyggt på applikationsnivå (utöver ev. brandväggsregler) — går inte att
  konfigurera bort via GUI:t.
- Default-deny vid start: `security-harbor-failsafe.service` applicerar
  ett minimalt, fail-safe nftables-ruleset OBEROENDE av att huvuddaemonen
  ens startat, så en trasig/ej uppstartad agent aldrig lämnar brandväggen
  öppen.

## Minsta möjliga privilegium & sandboxning

`systemd/security-harbor-agent.service`: `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
`MemoryDenyWriteExecute=true`, `RestrictRealtime=true`,
`RestrictNamespaces=true`, en uttrycklig `CapabilityBoundingSet`
(`CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`, inte root) och en snäv
`ReadWritePaths`-lista.

Vissa diagnostikverktyg (nmap SYN/UDP-scan, tcpdump) kräver riktig root för
en raw socket — något huvuddaemonen medvetet INTE har (och `NoNewPrivileges`
blockerar `sudo`/setuid oavsett sudoers-regler). Istället triggas en helt
separat, minimal, ohärdad `Type=oneshot`-hjälptjänst
(`security-harbor-nmap.service`/`security-harbor-tcpdump.service`) via
`systemctl start --wait`, auktoriserad av en polkit-regel scopead till
EXAKT den ena tjänsten och EXAKT `security-harbor`-tjänstekontot
(`systemd/10-security-harbor-*.rules`) — privilegiehöjningen isoleras till
en minimal engångskörning istället för att försvaga huvuddaemonens sandbox.
Samma mönster används för att låta huvuddaemonen (fortfarande utan egen
root-eskalering) be systemd starta om/ladda om `rsyslog.service` och
`suricata.service`.

## Diagnostikverktyg som riskyta

`ping`/`traceroute`/`nmap`/`tcpdump` körs alla admin-only
(`authMiddlewareAdmin`) eftersom de kan användas för intern
nätverksrekognosering FRÅN brandväggen. nmap-host och tcpdump-filter/
interface valideras mot känd konfiguration/avvisar flagg-injektion
(`strings.HasPrefix(host, "-")`-kollen resp. gränssnitts-whitelist mot
`cfg.Interfaces`) innan de skickas vidare till `exec.Command` (som ändå
aldrig går via ett skal, så klassisk shell-injektion är strukturellt
omöjlig oavsett).

## Sårbarhetsscanning

`govulncheck ./...` kört 2026-08-19: **0 exploaterbara sårbarheter** i
kodens faktiska anropsgraf. En känd, oanvänd sårbarhet (GO-2026-5932,
`golang.org/x/crypto/openpgp` — ett unmaintained subpaket vi aldrig
importerar, bara transitivt draget in via modulen) flaggas av verktyget
men berör inte koden i praktiken.

## Vad detta INTE är

- **Inte en oberoende, extern penetrationstest.** Detta är en
  självgenomförd kodgranskning + nmap-verifiering av utvecklaren/AI-
  assistenten själv. Se `pentest_fas12_2026-08-19.md` (Doc-Harbor) för den
  senaste körningen. En riktig tredjeparts-pentest är fortsatt
  rekommenderad innan systemet körs som enda skydd mot internet.
- **Källkoden är publik** (sedan Fas 13) — det innebär att design och
  implementation är öppen för granskning, men betyder INTE att systemet är
  granskat av någon oberoende part (se ovan).
- **Ingen OTA/automatisk uppdatering.** Ett självuppdaterande system som
  hämtar och kör kod från nätet på en brandvägg är en känslig funktion i
  sig — det byggs medvetet inte i det här skedet. Uppdatering är manuell.
