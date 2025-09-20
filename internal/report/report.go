package report

import (
	"encoding/json"
	"os"

	"example.com/ch10gate/internal/rules"
)

func SaveAcceptanceJSON(rep rules.AcceptanceReport, out string) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0644)
}

func LoadAcceptanceJSON(path string) (rules.AcceptanceReport, error) {
	var rep rules.AcceptanceReport
	b, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	err = json.Unmarshal(b, &rep)
	return rep, err
}
