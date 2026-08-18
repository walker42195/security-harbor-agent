// security-harbor-reset-password är ett engångs-CLI-verktyg för
// nödlägen: återställer en administrationsanvändares lösenord direkt i
// den krypterade users.enc-filen, utan att gå via Management-API:t (som
// ju kräver att man redan kan logga in). Körs manuellt via SSH på
// brandväggsservern, aldrig som en långlivad process.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/walker42195/security-harbor-agent/pkg/store"
)

func main() {
	configDir := flag.String("data-dir", "/var/lib/security-harbor", "Sökväg till datakatalog")
	username := flag.String("username", "master", "Användarnamn att återställa")
	newPassword := flag.String("password", "", "Nytt lösenord (minst 8 tecken)")
	flag.Parse()

	if *newPassword == "" {
		log.Fatal("--password krävs")
	}

	masterKey := []byte("SecurityHarborMasterKey2026Secur")
	st, err := store.NewStore(*configDir, masterKey)
	if err != nil {
		log.Fatalf("Kunde inte öppna store: %v", err)
	}

	user, err := st.Users.FindByUsername(*username)
	if err != nil {
		log.Fatalf("Hittade inte användaren %q: %v", *username, err)
	}
	if err := st.Users.ChangePassword(user.ID, *newPassword); err != nil {
		log.Fatalf("Kunde inte byta lösenord: %v", err)
	}
	fmt.Printf("Lösenordet för %q har återställts.\n", *username)
}
