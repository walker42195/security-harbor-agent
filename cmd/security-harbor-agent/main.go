package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/dns"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/openvpn"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/wireguard"
	"github.com/walker42195/security-harbor-agent/pkg/api"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

func main() {
	configDir := flag.String("data-dir", "/var/lib/security-harbor", "Sökväg till datakatalog")
	bindAddr := flag.String("bind", "10.0.0.163:8443", "IP/Port för Management API (HTTPS)")
	webUIDir := flag.String("webui-dir", "/var/lib/security-harbor/webui", "Sökväg till statiska filer för web-UI (flutter build web)")
	dryRun := flag.Bool("dry-run", false, "Starta i dry-run läge utan att ändra nftables i kärnan")
	flag.Parse()

	fmt.Println("=====================================================")
	fmt.Println(" SECURITY HARBOR FIREWALL AGENT v0.7.0 (Fas 7)       ")
	fmt.Println("=====================================================")
	if *dryRun {
		fmt.Println("[MODE] DRY-RUN AKTIVT - inga ändringar görs i kärnan!")
	}

	// 32-bytes masterkey (i prod genereras eller hämtas denna från HSM/TPM/Vault)
	masterKey := []byte("SecurityHarborMasterKey2026Secur")

	st, err := store.NewStore(*configDir, masterKey)
	if err != nil {
		log.Fatalf("Kunde inte starta store: %v", err)
	}

	nftAdapter := nftables.NewAdapter()
	dhcpAdapter := dhcp.NewAdapter("")
	wgAdapter := wireguard.NewAdapter("")
	ovpnAdapter := openvpn.NewAdapter("")
	dnsAdapter := dns.NewAdapter("")
	eng := engine.NewEngine(st, nftAdapter, dhcpAdapter, wgAdapter, ovpnAdapter, dnsAdapter)
	auth := api.NewAuthManager()

	// Applicera initial konfiguration vid start (om ej dry-run)
	if !*dryRun {
		fmt.Println("[INIT] Applicerar initial konfiguration (nftables, DHCP, WireGuard)...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	if ip := net.ParseIP(bindHost); ip != nil {
		tlsIPs = append(tlsIPs, ip)
	}
	tlsCert, err := st.EnsureManagementTLSCert(tlsIPs, []string{"localhost"})
	if err != nil {
		log.Fatalf("Kunde inte skapa/läsa TLS-certifikat för Management-API: %v", err)
	}

	server := api.NewServer(*bindAddr, eng, auth, tlsCert, *webUIDir)

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

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.Start(); err != nil {
			log.Printf("API Server stoppad: %v", err)
		}
	}()

	<-stopChan
	fmt.Println("\n[SHUTDOWN] Stänger ner Security Harbor Agent...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Stop(ctx)

	fmt.Println("[SHUTDOWN] Agenten avslutad säkert.")
}
