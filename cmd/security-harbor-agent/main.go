package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/dns"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/haproxy"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/suricata"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/syslog"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/api"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/store"
	"github.com/walker42195/security-harbor-agent/pkg/updater"
)

// version sätts vid bygget via -ldflags "-X main.version=<v>" (se
// build_release.sh, som läser VERSION-filen). "dev" i en obyggd binär.
var version = "dev"

func main() {
	configDir := flag.String("data-dir", "/var/lib/security-harbor", "Sökväg till datakatalog")
	bindAddr := flag.String("bind", "0.0.0.0:8443", "IP/Port för Management API (HTTPS). Default 0.0.0.0 = alla gränssnitt (nftables håller porten LAN-only; se HARD WAN DROP), så API:t är nåbart på vilken LAN-IP servern än har.")
	webUIDir := flag.String("webui-dir", "/var/lib/security-harbor/webui", "Sökväg till statiska filer för web-UI (flutter build web)")
	dryRun := flag.Bool("dry-run", false, "Starta i dry-run läge utan att ändra nftables i kärnan")
	seedMode := flag.String("mode", "", "Driftläge för EN HELT NY installation (\"\"/\"gateway\" eller \"host\", Fas 13) — rör bara den allra första uppstarten, ignoreras om running.json redan finns")
	// Kortvalen kommer från installern, där administratören pekar ut dem i en
	// lista över maskinens faktiska nätverkskort. Utelämnade => agenten
	// detekterar själv (se store.resolveSeedDevices). Precis som --mode rör de
	// BARA seedningen av en ny installation.
	seedWANDevice := flag.String("wan-device", "", "Gateway-läge, NY installation: nätverkskort mot internet (t.ex. ens18). Detekteras om det utelämnas")
	seedLANDevice := flag.String("lan-device", "", "Gateway-läge, NY installation: nätverkskort mot det interna nätet (t.ex. ens19). Detekteras om det utelämnas")
	seedHostDevice := flag.String("host-device", "", "Host-läge, NY installation: maskinens enda nätverkskort. Detekteras om det utelämnas")
	showVersion := flag.Bool("version", false, "Skriv ut versionen och avsluta")
	verifyTarball := flag.String("verify-update", "", "Verifiera en release-bunt (Ed25519) mot den inbyggda publika nyckeln och avsluta (0=ok). Används av root-installern.")
	verifySig := flag.String("verify-sig", "", "Signaturfil till --verify-update")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// Verifieringsläge: root-oneshoten (update-runner.sh) anropar den REDAN
	// INSTALLERADE (betrodda) agent-binären för att verifiera den nedladdade
	// buntens signatur som root INNAN installation — den nya, ännu overifierade
	// binären i bunten får aldrig verifiera sig själv.
	if *verifyTarball != "" {
		if err := updater.VerifyFile(*verifyTarball, *verifySig); err != nil {
			fmt.Fprintf(os.Stderr, "verifiering misslyckades: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		return
	}

	fmt.Println("=====================================================")
	fmt.Printf(" SECURITY HARBOR FIREWALL AGENT v%s\n", version)
	fmt.Println("=====================================================")
	if *dryRun {
		fmt.Println("[MODE] DRY-RUN AKTIVT - inga ändringar görs i kärnan!")
	}

	// Master-nyckeln för kryptering at-rest genereras slumpmässigt per
	// installation och sparas i --data-dir (se pkg/store/masterkey.go) —
	// inget hårdkodat här längre.
	st, err := store.NewStore(*configDir, store.SeedOptions{
		Mode:       *seedMode,
		WANDevice:  *seedWANDevice,
		LANDevice:  *seedLANDevice,
		HostDevice: *seedHostDevice,
	})
	if err != nil {
		log.Fatalf("Kunde inte starta store: %v", err)
	}

	nftAdapter := nftables.NewAdapter()
	dhcpAdapter := dhcp.NewAdapter("")
	wgAdapter := wireguard.NewAdapter("")
	ovpnAdapter := openvpn.NewAdapter("")
	dnsAdapter := dns.NewAdapter("")
	syslogAdapter := syslog.NewAdapter("")
	suricataAdapter := suricata.NewAdapter("", "")
	haproxyAdapter := haproxy.NewAdapter("")
	eng := engine.NewEngine(st, nftAdapter, dhcpAdapter, wgAdapter, ovpnAdapter, dnsAdapter, syslogAdapter, suricataAdapter, haproxyAdapter)
	auth := api.NewAuthManager(filepath.Join(*configDir, "sessions.json"))

	// Applicera initial konfiguration vid start (om ej dry-run)
	if !*dryRun {
		fmt.Println("[INIT] Applicerar initial konfiguration (nftables, DHCP, WireGuard)...")
		// 10s räckte när detta bara rörde nftables (se git-historik), men
		// ApplyRunningConfigAtBoot kör numera ALLA backends sekventiellt under
		// samma budget (nftables, DHCP, WireGuard, OpenVPN, DNS, syslog,
		// Suricata, HAProxy) utan att timeouten någonsin följde med. Upptäckt
		// 2026-08-25: Suricata med det fulla ET Open-regelsetet (~68 500
		// regler) hinner inte starta om innan ctx går ut, `systemctl restart
		// suricata.service` dödas mitt i ("signal: killed") och boot-
		// applieringen loggar ett VARNING på i princip varje omstart av
		// agenten i gateway-läge.
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err := eng.ApplyRunningConfigAtBoot(ctx)
		cancel()
		if err != nil {
			log.Printf("[VARNING] Initial applicering misslyckades: %v", err)
		} else {
			fmt.Println("[INIT] Initial konfiguration laddad.")
		}
	}

	// Self-signat TLS-certifikat för Management-API:et — genereras
	// automatiskt vid FÖRSTA uppstarten på en ny installation (samma
	// "generera vid behov, ladda från disk sedan"-mönster som OpenVPN-CA:n),
	// inget manuellt steg krävs. Om LAN-IP:t (bindHost) någon gång ändras
	// måste certifikatet regenereras manuellt (radera
	// management_tls.key.enc + starta om agenten).
	bindHost, _, err := net.SplitHostPort(*bindAddr)
	if err != nil {
		log.Fatalf("Ogiltig --bind-adress %q: %v", *bindAddr, err)
	}
	tlsIPs := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(bindHost); ip != nil && !ip.IsUnspecified() {
		tlsIPs = append(tlsIPs, ip)
	} else {
		// Bind på 0.0.0.0/:: (alla gränssnitt) — ta med maskinens faktiska
		// icke-loopback-IPv4-adresser i certifikatet så klienter som ansluter
		// via LAN-IP:n får en matchande SAN (annars misslyckas
		// hostname-verifieringen mot en fast, kanske obefintlig, IP).
		tlsIPs = append(tlsIPs, localIPv4s()...)
	}
	tlsCert, err := st.EnsureManagementTLSCert(tlsIPs, []string{"localhost"})
	if err != nil {
		log.Fatalf("Kunde inte skapa/läsa TLS-certifikat för Management-API: %v", err)
	}

	server := api.NewServer(*bindAddr, eng, auth, tlsCert, *webUIDir, version)

	// Fas 5: periodisk uppdatering av hot-listor/GeoIP-objekt (Spamhaus,
	// Tor-exit-noder, anpassade URL:er, landsblock). Körs var 15:e minut;
	// varje objekt uppdateras bara när dess egen RefreshHours har passerat
	// (se Engine.RefreshDueObjectSources), så detta är inte en 15-minuters
	// hämtningsfrekvens per lista.
	if !*dryRun {
		threatFeedCtx, cancelThreatFeed := context.WithCancel(context.Background())
		defer cancelThreatFeed()
		go func() {
			ticker := time.NewTicker(15 * time.Minute)
			defer ticker.Stop()
			refresh := func() {
				ctx, cancel := context.WithTimeout(threatFeedCtx, 2*time.Minute)
				defer cancel()
				if n := eng.RefreshDueObjectSources(ctx); n > 0 {
					fmt.Printf("[THREATFEED] Uppdaterade %d hot-lista/GeoIP-objekt\n", n)
				}
				if n := eng.RefreshDueDNSBlocklists(ctx); n > 0 {
					fmt.Printf("[THREATFEED] Uppdaterade %d DNS-domänblocklista(or)\n", n)
				}
			}
			refresh()
			for {
				select {
				case <-threatFeedCtx.Done():
					return
				case <-ticker.C:
					refresh()
				}
			}
		}()
	}

	// Fas 9: periodisk bevakning av Suricata-larm för IDS.AutoBlock (se
	// Engine.ProcessIDSAutoBlock). Var 30:e sekund är gott nog för en
	// "eftersläpande" auto-blockering (paketet som utlöste larmet har redan
	// passerat oavsett) — ingen inline/realtidsblockering byggs i det här
	// steget, se kommentaren i pkg/config/model.go:IDSConfig.
	if !*dryRun {
		idsCtx, cancelIDS := context.WithCancel(context.Background())
		defer cancelIDS()
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-idsCtx.Done():
					return
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(idsCtx, 20*time.Second)
					if err := eng.ProcessIDSAutoBlock(ctx); err != nil {
						log.Printf("[IDS] auto-block misslyckades: %v", err)
					}
					cancel()
				}
			}
		}()
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Trafikmätning per enhet (dashboarden). Kärnan räknar via nftables
	// dynamiska mängder; den här loopen läser bara av dem, lagrar deltan och
	// sparar historiken med jämna mellanrum.
	trafficCtx, stopTraffic := context.WithCancel(context.Background())
	defer stopTraffic()
	go eng.StartTrafficCollection(trafficCtx)

	go func() {
		if err := server.Start(); err != nil {
			log.Printf("API Server stoppad: %v", err)
		}
	}()

	<-stopChan
	fmt.Println("\n[SHUTDOWN] Stänger ner Security Harbor Agent...")
	stopTraffic() // låter trafikloopen spara historiken innan vi går ner

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Stop(ctx)

	fmt.Println("[SHUTDOWN] Agenten avslutad säkert.")
}

// localIPv4s returnerar maskinens icke-loopback-IPv4-adresser. Används för att
// fylla TLS-certifikatets SAN-lista när API:t binder på 0.0.0.0 (alla
// gränssnitt), så att en klient som ansluter via serverns LAN-IP får ett
// certifikat vars IP-SAN matchar — oavsett vilken IP just den servern har.
func localIPv4s() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		out = append(out, ip4)
	}
	return out
}
