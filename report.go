package report

import (
	"encoding/json"
	"os"

	"example.com/ch10gate/internal/rules"
)

func SaveAcceptanceJSON(rep rules.AcceptanceReport, out string) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil { return err }
	return os.WriteFile(out, b, 0644)
}
