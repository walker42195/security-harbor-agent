// security-harbor-nmap-runner är en isolerad, syftesbyggd hjälptjänst för
// nmap-skanningar (SYN/UDP/OS-detektion kräver riktig root — verifierat
// att Ubuntu-paketets nmap saknar libcap-ng-stöd och därför inte kan
// använda Linux-capabilities istället för root, se
// pkg/api/server.go:handleNmap). Den härdade huvuddaemonen
// (security-harbor-agent.service) kör med NoNewPrivileges=true, vilket
// kategoriskt blockerar sudo oavsett sudoers-regler — istället triggar
// den denna HELT SEPARATA, ohärdade systemd-engångstjänst via
// `systemctl start --wait`, så privilegiehöjningen är isolerad till en
// minimal komponent istället för att försvaga hela agentens sandbox.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// maxRunTime är ett internt säkerhetsnät oberoende av systemds
// TimeoutStartSec (se systemd/security-harbor-nmap.service) — hittat
// under en säkerhetsgranskning 2026-08-19: en tung skanning
// (-sS -p- -sV -sU -O) kunde tidigare köra OBEGRÄNSAT (varken
// huvuddaemonens 5-minuters context-timeout eller något i den här
// processen satte någon gräns alls), vilket lämnade
// security-harbor-nmap.service i "activating"-läge i 23 timmar och
// blockerade ALLA efterföljande skanningar tills den dödades manuellt.
const maxRunTime = 4 * time.Minute

const (
	requestPath = "/run/security-harbor/nmap-request.json"
	resultPath  = "/run/security-harbor/nmap-result.json"
)

type request struct {
	Args []string `json:"args"`
}

type result struct {
	Output string `json:"output"`
}

func main() {
	data, err := os.ReadFile(requestPath)
	if err != nil {
		writeResult(fmt.Sprintf("nmap-runner: kunde inte läsa request-fil: %v", err))
		return
	}

	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		writeResult(fmt.Sprintf("nmap-runner: ogiltig request-fil: %v", err))
		return
	}
	if len(req.Args) == 0 {
		writeResult("nmap-runner: inga argument angivna")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), maxRunTime)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nmap", req.Args...).CombinedOutput()
	text := string(out)
	if ctx.Err() == context.DeadlineExceeded {
		text += fmt.Sprintf("\nnmap-runner: avbruten efter %s (tidsgräns)", maxRunTime)
	} else if err != nil && text == "" {
		text = fmt.Sprintf("nmap-runner: nmap misslyckades: %v", err)
	}
	writeResult(text)
}

func writeResult(output string) {
	data, err := json.Marshal(result{Output: output})
	if err != nil {
		return
	}
	// 0644: resultatet är ofarligt (bara nmap-utdata) och måste kunna läsas
	// tillbaka av den ohärdade security-harbor-agent-processen, som körs
	// som en annan Unix-användare än denna hjälptjänst (root).
	_ = os.WriteFile(resultPath, data, 0644)
}
