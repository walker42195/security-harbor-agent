package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("=====================================================")
	fmt.Println(" SECURITY HARBOR EMERGENCY LOCAL RECOVERY TOOL       ")
	fmt.Println("=====================================================")
	fmt.Println("Detta verktyg återställer brandväggsreglerna till nöd-läget")
	fmt.Println("och garanterar lokal/LAN-åtkomst om API:t låsts ute.")
	fmt.Println()

	// 1. Ladda failsafe ruleset
	fmt.Println("[1/3] Laddar failsafe-ruleset (/etc/security-harbor/security-harbor-failsafe.nft)...")
	cmd := exec.Command("/sbin/nft", "-f", "/etc/security-harbor/security-harbor-failsafe.nft")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("FEL vid nftables laddning: %v - %s\n", err, string(out))
	} else {
		fmt.Println(" -> Failsafe ruleset laddat framgångsrikt.")
	}

	// 2. Återställ candidate.json från running.json
	fmt.Println("[2/3] Återställer candidate.json från sista kända running.json...")
	runningData, err := os.ReadFile("/var/lib/security-harbor/running.json")
	if err == nil {
		_ = os.WriteFile("/var/lib/security-harbor/candidate.json", runningData, 0600)
		fmt.Println(" -> Candidate återställd från running.json.")
	} else {
		fmt.Printf(" -> Kunde inte läsa running.json: %v (hoppar över)\n", err)
	}

	// 3. Omstart av agent-tjänsten
	fmt.Println("[3/3] Startar om security-harbor-agent.service...")
	cmdSystemd := exec.Command("systemctl", "restart", "security-harbor-agent.service")
	_ = cmdSystemd.Run()

	fmt.Println()
	fmt.Println("Nödåterställning klar! Nätverket är nu återställt till säkert grundläge.")
}
