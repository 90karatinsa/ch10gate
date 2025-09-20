package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"

	"example.com/ch10gate/internal/rules"
)

// SaveAcceptancePDF renders the given acceptance report into a PDF document.
func SaveAcceptancePDF(rep rules.AcceptanceReport, out string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Acceptance Report", false)
	pdf.SetAuthor("ch10ctl", false)
	pdf.SetCreator("ch10ctl", false)
	pdf.SetMargins(15, 20, 15)
	pdf.SetAutoPageBreak(true, 20)
	pdf.AddPage()

	addPDFTitle(pdf, "Acceptance Report")
	addSummarySection(pdf, rep)
	addGateMatrixSection(pdf, rep.GateMatrix)
	addDictionarySection(pdf, rep.DictionaryCompliance)
	addFindingsSection(pdf, rep.Findings)

	if pdf.Err() {
		return pdf.Error()
	}
	return pdf.OutputFileAndClose(out)
}

func addPDFTitle(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 18)
	pdf.Cell(0, 10, title)
	pdf.Ln(12)
}

func addSummarySection(pdf *gofpdf.Fpdf, rep rules.AcceptanceReport) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Summary")
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 11)
	items := []struct {
		label string
		value string
	}{
		{label: "Total Findings", value: strconv.Itoa(rep.Summary.Total)},
		{label: "Errors", value: strconv.Itoa(rep.Summary.Errors)},
		{label: "Warnings", value: strconv.Itoa(rep.Summary.Warnings)},
		{label: "Overall", value: passLabel(rep.Summary.Pass)},
	}
	for _, item := range items {
		pdf.CellFormat(50, 6, item.label, "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, item.value, "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)
}

func addGateMatrixSection(pdf *gofpdf.Fpdf, rows []rules.GateResult) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Gate Matrix")
	pdf.Ln(9)

	headers := []string{"Stage", "Severity", "Rule", "Name", "Pass", "Findings"}
	widths := []float64{28, 22, 36, 68, 18, 18}

	pdf.SetFillColor(240, 240, 240)
	pdf.SetFont("Helvetica", "B", 10)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 7, h, "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 9)
	lineHeight := 5.0
	for _, row := range rows {
		values := []string{
			stageLabel(row.Stage),
			severityLabel(row.Severity),
			row.RuleId,
			emptyFallback(row.Name, "-"),
			passLabel(row.Pass),
			strconv.Itoa(row.Findings),
		}
		renderTableRow(pdf, widths, values, lineHeight)
	}
	pdf.Ln(4)
}

func addDictionarySection(pdf *gofpdf.Fpdf, rep rules.DictionaryComplianceReport) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Dictionary Compliance")
	pdf.Ln(9)

	if len(rep.MIL1553) == 0 && len(rep.A429) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.MultiCell(0, 6, "No dictionary mismatches detected.", "", "L", false)
		pdf.Ln(4)
		return
	}

	if len(rep.MIL1553) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.Cell(0, 6, "MIL-STD-1553")
		pdf.Ln(7)

		headers := []string{"Channel", "RT/SA", "Observed", "Expected", "Name", "Severity", "Count", "Issue"}
		widths := []float64{14, 20, 20, 20, 32, 18, 16, 40}

		pdf.SetFillColor(240, 240, 240)
		pdf.SetFont("Helvetica", "B", 10)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 7, h, "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)

		pdf.SetFont("Helvetica", "", 9)
		for _, row := range rep.MIL1553 {
			observed := "-"
			expected := "-"
			if row.WordCount != nil {
				observed = fmt.Sprintf("WC=%d", *row.WordCount)
			} else if row.ModeCode != nil {
				observed = fmt.Sprintf("MC=%d", *row.ModeCode)
			}
			if row.ExpectedWordCount != nil {
				expected = fmt.Sprintf("WC=%d", *row.ExpectedWordCount)
			} else if row.ExpectedModeCode != nil {
				expected = fmt.Sprintf("MC=%d", *row.ExpectedModeCode)
			}
			values := []string{
				strconv.FormatUint(uint64(row.ChannelID), 10),
				fmt.Sprintf("%02d/%02d", row.RT, row.SA),
				observed,
				expected,
				strings.TrimSpace(row.Name),
				severityLabel(row.Severity),
				strconv.Itoa(row.Occurrences),
				strings.TrimSpace(row.Issue),
			}
			renderTableRow(pdf, widths, values, 5.0)
		}
		pdf.Ln(5)
	}

	if len(rep.A429) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.Cell(0, 6, "ARINC-429")
		pdf.Ln(7)

		headers := []string{"Channel", "Label", "SDI", "Name", "Severity", "Count", "Issue"}
		widths := []float64{14, 20, 16, 40, 18, 16, 56}

		pdf.SetFillColor(240, 240, 240)
		pdf.SetFont("Helvetica", "B", 10)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 7, h, "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)

		pdf.SetFont("Helvetica", "", 9)
		for _, row := range rep.A429 {
			values := []string{
				strconv.FormatUint(uint64(row.ChannelID), 10),
				fmt.Sprintf("0x%02X", row.Label),
				strconv.Itoa(int(row.SDI)),
				strings.TrimSpace(row.Name),
				severityLabel(row.Severity),
				strconv.Itoa(row.Occurrences),
				strings.TrimSpace(row.Issue),
			}
			renderTableRow(pdf, widths, values, 5.0)
		}
		pdf.Ln(4)
	}
}

func addFindingsSection(pdf *gofpdf.Fpdf, findings []rules.Diagnostic) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Findings")
	pdf.Ln(9)

	if len(findings) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.MultiCell(0, 6, "No findings recorded.", "", "L", false)
		return
	}

	for i, d := range findings {
		pdf.SetFont("Helvetica", "B", 10)
		header := fmt.Sprintf("%d. %s (%s)", i+1, d.RuleId, severityLabel(d.Severity))
		pdf.MultiCell(0, 5, header, "", "L", false)

		if msg := strings.TrimSpace(d.Message); msg != "" {
			pdf.SetFont("Helvetica", "", 10)
			pdf.MultiCell(0, 5, msg, "", "L", false)
		}

		meta := findingMetadata(d)
		if meta != "" {
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 4, meta, "", "L", false)
		}

		if len(d.Refs) > 0 {
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 4, "Refs: "+strings.Join(d.Refs, ", "), "", "L", false)
		}

		pdf.Ln(2)
	}
}

func renderTableRow(pdf *gofpdf.Fpdf, widths []float64, values []string, lineHeight float64) {
	xStart := pdf.GetX()
	yStart := pdf.GetY()
	maxLines := 1
	splitCols := make([][]string, len(values))
	for i, val := range values {
		text := strings.TrimSpace(val)
		if text == "" {
			text = "-"
		}
		lines := pdf.SplitText(text, widths[i]-2)
		if len(lines) == 0 {
			lines = []string{""}
		}
		splitCols[i] = lines
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
	}
	rowHeight := float64(maxLines) * lineHeight
	x := xStart
	for i, lines := range splitCols {
		pdf.SetXY(x, yStart)
		cellText := strings.Join(lines, "\n")
		pdf.MultiCell(widths[i], lineHeight, cellText, "1", "L", false)
		x += widths[i]
	}
	pdf.SetXY(xStart, yStart+rowHeight)
}

func passLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func stageLabel(stage rules.RuleStage) string {
	switch stage {
	case rules.StageHeader:
		return "Header"
	case rules.StageTime:
		return "Time"
	case rules.StageTypeSpecific:
		return "Type-Specific"
	case rules.StageTMATS:
		return "TMATS"
	case rules.StageStructWrite:
		return "Struct Write"
	default:
		if s := strings.TrimSpace(string(stage)); s != "" {
			return s
		}
		return "-"
	}
}

func severityLabel(sev rules.Severity) string {
	if s := strings.TrimSpace(string(sev)); s != "" {
		return s
	}
	return "UNKNOWN"
}

func emptyFallback(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func findingMetadata(d rules.Diagnostic) string {
	parts := make([]string, 0, 6)
	if !d.Ts.IsZero() {
		parts = append(parts, d.Ts.Format(time.RFC3339))
	}
	if d.File != "" {
		parts = append(parts, d.File)
	}
	if d.ChannelId != 0 {
		parts = append(parts, fmt.Sprintf("Channel %d", d.ChannelId))
	}
	if d.PacketIndex != 0 {
		parts = append(parts, fmt.Sprintf("Packet %d", d.PacketIndex))
	}
	if d.Offset != "" {
		parts = append(parts, "Offset "+d.Offset)
	}
	if d.TimestampUs != nil {
		parts = append(parts, fmt.Sprintf("Timestamp %dµs", *d.TimestampUs))
	}
	if d.TimestampSource != nil && *d.TimestampSource != "" {
		parts = append(parts, "Source "+*d.TimestampSource)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ")
}
