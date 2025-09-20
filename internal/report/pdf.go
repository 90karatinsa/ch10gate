package report

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"

	"example.com/ch10gate/internal/rules"
)

// PDFOptions controls how acceptance reports are rendered to PDF.
type PDFOptions struct {
	Lang         Language
	ManifestHash string
	GeneratedAt  time.Time
}

// SaveAcceptancePDF renders the given acceptance report into a PDF document.
func SaveAcceptancePDF(rep rules.AcceptanceReport, out string, opts PDFOptions) error {
	if opts.Lang == "" {
		opts.Lang = LangEnglish
	}
	translator := NewTranslator(opts.Lang)
	opts.ManifestHash = sanitizeHash(opts.ManifestHash)
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now()
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(translator.T("pdf.title"), false)
	pdf.SetAuthor("ch10ctl", false)
	pdf.SetCreator("ch10ctl", false)
	pdf.SetMargins(15, 20, 15)
	pdf.SetAutoPageBreak(true, 25)
	registerFooter(pdf, translator, opts)
	pdf.AddPage()

	addPDFTitle(pdf, translator.T("pdf.title"))
	addSummarySection(pdf, translator, rep)
	addManifestSection(pdf, translator, opts.ManifestHash)
	addGateMatrixSection(pdf, translator, rep.GateMatrix)
	addDictionarySection(pdf, translator, rep.DictionaryCompliance)
	addFindingsSection(pdf, translator, rep.Findings)

	if pdf.Err() {
		return pdf.Error()
	}
	return pdf.OutputFileAndClose(out)
}

func registerFooter(pdf *gofpdf.Fpdf, tr Translator, opts PDFOptions) {
	pdf.SetFooterFunc(func() {
		pdf.SetY(-18)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(120, 120, 120)

		generated := fmt.Sprintf("%s • %s", tr.T("footer.generated_by"), opts.GeneratedAt.Format("2006-01-02 15:04"))
		pdf.CellFormat(0, 4, generated, "", 0, "L", false, 0, "")

		pageText := tr.Format("footer.page", pdf.PageNo())
		pdf.CellFormat(0, 4, pageText, "", 0, "R", false, 0, "")

		if opts.ManifestHash != "" {
			pdf.Ln(4)
			pdf.CellFormat(0, 4, fmt.Sprintf(tr.T("footer.hash"), formatHashForDisplay(opts.ManifestHash)), "", 0, "L", false, 0, "")
		}

		pdf.SetTextColor(0, 0, 0)
	})
}

func addPDFTitle(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 18)
	pdf.Cell(0, 10, title)
	pdf.Ln(12)
}

func addSummarySection(pdf *gofpdf.Fpdf, tr Translator, rep rules.AcceptanceReport) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, tr.T("summary.title"))
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 11)
	items := []struct {
		label string
		value string
	}{
		{label: tr.T("summary.total"), value: strconv.Itoa(rep.Summary.Total)},
		{label: tr.T("summary.errors"), value: strconv.Itoa(rep.Summary.Errors)},
		{label: tr.T("summary.warnings"), value: strconv.Itoa(rep.Summary.Warnings)},
		{label: tr.T("summary.overall"), value: passLabel(tr, rep.Summary.Pass)},
	}
	for _, item := range items {
		pdf.CellFormat(50, 6, item.label, "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, item.value, "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)
}

func addManifestSection(pdf *gofpdf.Fpdf, tr Translator, manifestHash string) {
	if manifestHash == "" {
		return
	}

	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, tr.T("manifest.title"))
	pdf.Ln(9)

	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 6, fmt.Sprintf("%s: %s", tr.T("manifest.hash_label"), formatHashForDisplay(manifestHash)), "", "L", false)
	pdf.Ln(2)

	png, err := ManifestHashToQR(manifestHash, 256)
	if err != nil {
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, fmt.Sprintf("%s (%v)", tr.T("manifest.qr_error"), err), "", "L", false)
		pdf.Ln(4)
		return
	}

	imgName := fmt.Sprintf("manifest-qr-%d", time.Now().UnixNano())
	opt := gofpdf.ImageOptions{ImageType: "PNG"}
	pdf.RegisterImageOptionsReader(imgName, opt, bytes.NewReader(png))

	x := pdf.GetX()
	y := pdf.GetY()
	qrSize := 35.0
	pdf.ImageOptions(imgName, x, y, qrSize, qrSize, false, opt, 0, "")
	pdf.SetXY(x+qrSize+4, y)
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, tr.T("manifest.qr_caption"), "", "L", false)
	pdf.SetY(y + qrSize + 2)
	pdf.Ln(4)
}

func addGateMatrixSection(pdf *gofpdf.Fpdf, tr Translator, rows []rules.GateResult) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, tr.T("gate.title"))
	pdf.Ln(9)

	headers := []string{tr.T("gate.stage"), tr.T("gate.severity"), tr.T("gate.rule"), tr.T("gate.name"), tr.T("gate.pass"), tr.T("gate.findings"), tr.T("gate.ref")}
	widths := []float64{23, 20, 32, 54, 16, 16, 19}

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
			stageLabel(tr, row.Stage),
			severityLabel(row.Severity),
			row.RuleId,
			emptyFallback(row.Name, "-"),
			passLabel(tr, row.Pass),
			strconv.Itoa(row.Findings),
			strings.Join(row.Refs, "\n"),
		}
		renderTableRow(pdf, widths, values, lineHeight)
	}
	pdf.Ln(4)
}

func addDictionarySection(pdf *gofpdf.Fpdf, tr Translator, rep rules.DictionaryComplianceReport) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, tr.T("dictionary.title"))
	pdf.Ln(9)

	if len(rep.MIL1553) == 0 && len(rep.A429) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.MultiCell(0, 6, tr.T("dictionary.none"), "", "L", false)
		pdf.Ln(4)
		return
	}

	if len(rep.MIL1553) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.Cell(0, 6, tr.T("dictionary.mil1553"))
		pdf.Ln(7)

		headers := []string{tr.T("dictionary.channel"), tr.T("dictionary.rtsa"), tr.T("dictionary.observed"), tr.T("dictionary.expected"), tr.T("dictionary.name"), tr.T("dictionary.severity"), tr.T("dictionary.count"), tr.T("dictionary.issue")}
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
		pdf.Cell(0, 6, tr.T("dictionary.a429"))
		pdf.Ln(7)

		headers := []string{tr.T("dictionary.channel"), tr.T("dictionary.label"), tr.T("dictionary.sdi"), tr.T("dictionary.name"), tr.T("dictionary.severity"), tr.T("dictionary.count"), tr.T("dictionary.issue")}
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

func addFindingsSection(pdf *gofpdf.Fpdf, tr Translator, findings []rules.Diagnostic) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, tr.T("findings.title"))
	pdf.Ln(9)

	if len(findings) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.MultiCell(0, 6, tr.T("findings.none"), "", "L", false)
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

		if meta := findingMetadata(tr, d); meta != "" {
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 4, meta, "", "L", false)
		}

		if len(d.Refs) > 0 {
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 4, tr.T("findings.refs")+strings.Join(d.Refs, ", "), "", "L", false)
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

func passLabel(tr Translator, pass bool) string {
	if pass {
		return tr.T("pass.true")
	}
	return tr.T("pass.false")
}

func stageLabel(tr Translator, stage rules.RuleStage) string {
	switch stage {
	case rules.StageHeader:
		return tr.T("stage.header")
	case rules.StageTime:
		return tr.T("stage.time")
	case rules.StageTypeSpecific:
		return tr.T("stage.type_specific")
	case rules.StageTMATS:
		return tr.T("stage.tmats")
	case rules.StageStructWrite:
		return tr.T("stage.struct_write")
	default:
		if s := strings.TrimSpace(string(stage)); s != "" {
			return s
		}
		return tr.T("stage.unknown")
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

func findingMetadata(tr Translator, d rules.Diagnostic) string {
	parts := make([]string, 0, 6)
	if !d.Ts.IsZero() {
		parts = append(parts, d.Ts.Format(time.RFC3339))
	}
	if d.File != "" {
		parts = append(parts, d.File)
	}
	if d.ChannelId != 0 {
		parts = append(parts, tr.Format("metadata.channel", d.ChannelId))
	}
	if d.PacketIndex != 0 {
		parts = append(parts, tr.Format("metadata.packet", d.PacketIndex))
	}
	if d.Offset != "" {
		parts = append(parts, tr.Format("metadata.offset", d.Offset))
	}
	if d.TimestampUs != nil {
		parts = append(parts, tr.Format("metadata.timestamp", *d.TimestampUs))
	}
	if d.TimestampSource != nil && *d.TimestampSource != "" {
		parts = append(parts, tr.Format("metadata.source", *d.TimestampSource))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ")
}

func formatHashForDisplay(hash string) string {
	cleaned := sanitizeHash(hash)
	if cleaned == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range cleaned {
		if i > 0 && i%4 == 0 {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
