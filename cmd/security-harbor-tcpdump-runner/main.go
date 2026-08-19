// security-harbor-tcpdump-runner är en isolerad, syftesbyggd hjälptjänst för
// paketfångst (tcpdump kräver CAP_NET_RAW/riktig root för att öppna en raw
// socket). Den härdade huvuddaemonen (security-harbor-agent.service) kör
// med NoNewPrivileges=true, vilket kategoriskt blockerar sudo oavsett
// sudoers-regler — istället triggar den denna HELT SEPARATA, ohärdade
// systemd-engångstjänst via `systemctl start --wait`, exakt samma mönster
// som cmd/security-harbor-nmap-runner, så privilegiehöjningen är isolerad
// till en minimal komponent istället för att försvaga hela agentens
// sandbox. Se pkg/api/server.go:handleTcpdumpCapture.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	requestPath = "/run/security-harbor/tcpdump-request.json"
	resultPath  = "/run/security-harbor/tcpdump-result.json"
)

type request struct {
	Interface   string `json:"interface"`
	Filter      string `json:"filter"`
	PacketCount int    `json:"packet_count"`
	DurationSec int    `json:"duration_sec"`
}

type result struct {
	Output string `json:"output"`
}

func main() {
	data, err := os.ReadFile(requestPath)
	if err != nil {
		writeResult(fmt.Sprintf("tcpdump-runner: kunde inte läsa request-fil: %v", err))
		return
	}

	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		writeResult(fmt.Sprintf("tcpdump-runner: ogiltig request-fil: %v", err))
		return
	}
	if req.Interface == "" {
		writeResult("tcpdump-runner: inget gränssnitt angivet")
		return
	}

	args := []string{"-i", req.Interface, "-n", "-tttt"}
	if req.PacketCount > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", req.PacketCount))
	}
	if req.Filter != "" {
		args = append(args, req.Filter)
	}

	duration := time.Duration(req.DurationSec) * time.Second
	if duration <= 0 {
		duration = 12 * time.Second
	}

	cmd := exec.Command("tcpdump", args...)
	out, err := runWithTimeout(cmd, duration)
	text := out
	if err != nil && text == "" {
		text = fmt.Sprintf("tcpdump-runner: tcpdump misslyckades: %v", err)
	}
	writeResult(text)
}

// runWithTimeout kör tcpdump och avbryter den med SIGTERM efter durationen
// om -c (antal paket) inte redan gjort att den avslutat sig själv — tcpdump
// utan -c avslutar annars aldrig av sig självt.
func runWithTimeout(cmd *exec.Cmd, duration time.Duration) (string, error) {
	var outBuf, errBuf []byte
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 0, 64*1024)
		tmp := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if rerr != nil {
				break
			}
		}
		outBuf = buf
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return string(outBuf) + string(errBuf), err
	case <-time.After(duration):
		_ = cmd.Process.Kill()
		<-done
		return string(outBuf) + string(errBuf), nil
	}
}

func writeResult(output string) {
	data, err := json.Marshal(result{Output: output})
	if err != nil {
		return
	}
	// 0644: resultatet är ofarligt (bara tcpdump-utdata) och måste kunna
	// läsas tillbaka av den ohärdade security-harbor-agent-processen, som
	// körs som en annan Unix-användare än denna hjälptjänst (root).
	_ = os.WriteFile(resultPath, data, 0644)
}
