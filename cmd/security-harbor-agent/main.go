package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/nftables"
	"github.com/walker42195/security-harbor-agent/pkg/api"
	"github.com/walker42195/security-harbor-agent/pkg/engine"
	"github.com/walker42195/security-harbor-agent/pkg/store"
)

func main() {
	configDir := flag.String("data-dir", "/var/lib/security-harbor", "Sökväg till datakatalog")
	bindAddr := flag.String("bind", "0.0.0.0:8443", "IP/Port för Management API")
	dryRun := flag.Bool("dry-run", false, "Starta i dry-run läge utan att ändra nftables i kärnan")
	flag.Parse()

	fmt.Println("=====================================================")
	fmt.Println(" SECURITY HARBOR FIREWALL AGENT v0.1.0 (Fas 0)       ")
	fmt.Println("=====================================================")
	if *dryRun {
		fmt.Println("[MODE] DRY-RUN AKTIVT - inga ändringar görs i kärnan!")
	}

	// 32-bytes masterkey (i prod genereras eller hämtas denna från HSM/TPM/Vault)
	masterKey := []byte("SecurityHarborMasterKey2026Secure")

	st, err := store.NewStore(*configDir, masterKey)
	if err != nil {
		log.Fatalf("Kunde inte starta store: %v", err)
	}

	nftAdapter := nftables.NewAdapter()
	eng := engine.NewEngine(st, nftAdapter)

	// Applicera initial konfiguration vid start (om ej dry-run)
	if !*dryRun {
		runningCfg := st.GetRunningConfig()
		fmt.Println("[INIT] Applicerar initial konfiguration på nftables...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := nftAdapter.ApplyConfig(ctx, runningCfg, false)
		cancel()
		if err != nil {
			log.Printf("[VARNING] Initial nftables applicering misslyckades: %v", err)
		} else {
			fmt.Println("[INIT] Initial konfiguration laddad i nftables.")
		}
	}

	server := api.NewServer(*bindAddr, st, eng)

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
	_ = server.Shutdown(ctx)

	fmt.Println("[SHUTDOWN] Agenten avslutad säkert.")
}
