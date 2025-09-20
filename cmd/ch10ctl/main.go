package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"example.com/ch10gate/internal/common"
	"example.com/ch10gate/internal/crypto"
	"example.com/ch10gate/internal/manifest"
	"example.com/ch10gate/internal/report"
	"example.com/ch10gate/internal/rules"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	if _, err := common.RequireValidLicense(); err != nil {
		fmt.Fprintf(os.Stderr, "license error: %v\n", err)
		fmt.Fprintf(os.Stderr, "machine hash: %s\n", machineHashForError())
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "validate":
		validateCmd(os.Args[2:])
	case "autofix":
		autofixCmd(os.Args[2:])
	case "report":
		reportCmd(os.Args[2:])
	case "manifest":
		manifestCmd(os.Args[2:])
	case "verify-signature":
		verifySignatureCmd(os.Args[2:])
	case "batch":
		batchCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Printf(`ch10ctl %s (built %s) <command> [options]

Commands:
  validate  --in <file> --profile <profile> --rules <rulepack.json> --tmats <file> --out <diagnostics.jsonl> --acceptance <acceptance.json>
  autofix   --in <file> --profile <profile> --rules <rulepack.json> --tmats <file>
  report    --diagnostics <diagnostics.jsonl> --acceptance <acceptance.json>
  manifest  --inputs <comma-separated> --out <manifest.json> [--sign --key <key.pem> --cert <cert.pem> --jws-out <file>]
  verify-signature --manifest <manifest.json> --jws <signature.jws> --cert <cert.pem>
  batch     --in <dir> --profile <profile> --rules <rulepack.json> --out-dir <dir>
`, version, buildDate)
}

func machineHashForError() string {
	hash, err := common.MachineFingerprint()
	if err != nil {
		return fmt.Sprintf("unavailable (%v)", err)
	}
	return hash
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	in := fs.String("in", "", "input .ch10")
	tmats := fs.String("tmats", "", "TMATS file")
	profile := fs.String("profile", "106-15", "profile")
	rulesPath := fs.String("rules", "", "rulepack.json")
	outDiag := fs.String("out", "diagnostics.jsonl", "diagnostics output")
	outAcc := fs.String("acceptance", "acceptance_report.json", "acceptance json")
	includeTimestamps := fs.Bool("diag-include-timestamps", true, "include timestamp metadata in diagnostics output")
	concurrency := fs.Int("concurrency", runtime.NumCPU(), "maximum concurrent channel evaluations")
	metricsFlag := fs.Bool("metrics", false, "print validation throughput metrics")
	progressFlag := fs.Bool("progress", false, "display validation progress updates")
	fs.Parse(args)

	if *in == "" || *rulesPath == "" {
		fmt.Println("required: --in, --rules")
		os.Exit(1)
	}

	var metrics *common.Metrics
	if *metricsFlag || *progressFlag {
		metrics = common.NewMetrics()
		if info, err := os.Stat(*in); err == nil {
			metrics.SetTotalBytes(info.Size())
		}
	}

	rp, err := rules.LoadRulePack(*rulesPath)
	if err != nil {
		fmt.Println("load rulepack:", err)
		os.Exit(1)
	}
	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConfigValue("diag.include_timestamps", *includeTimestamps)
	engine.SetConcurrency(*concurrency)

	ctx := &rules.Context{InputFile: *in, TMATSFile: *tmats, Profile: *profile, Metrics: metrics}
	if metrics != nil {
		metrics.Start()
	}
	var stopProgress func()
	if metrics != nil && *progressFlag {
		stopProgress = common.StartProgressPrinter(os.Stderr, metrics, 500*time.Millisecond)
	}
	diags, err := engine.Eval(ctx)
	if stopProgress != nil {
		stopProgress()
	}
	if metrics != nil {
		metrics.Stop()
	}
	if err != nil {
		fmt.Println("eval:", err)
		os.Exit(1)
	}

	if err := engine.WriteDiagnosticsNDJSON(*outDiag); err != nil {
		fmt.Println("write diags:", err)
		os.Exit(1)
	}
	rep := engine.MakeAcceptance()
	if err := report.SaveAcceptanceJSON(rep, *outAcc); err != nil {
		fmt.Println("write report:", err)
		os.Exit(1)
	}
	fmt.Printf("PASS=%v, errors=%d, warnings=%d, diagnostics=%d\n", rep.Summary.Pass, rep.Summary.Errors, rep.Summary.Warnings, len(diags))
	if metrics != nil && *metricsFlag {
		snap := metrics.Snapshot()
		throughputBps := snap.ThroughputBytesPerSecond()
		gbPerMin := throughputBps * 60 / 1_000_000_000
		mbPerSec := throughputBps / 1_000_000
		fmt.Printf("Metrics: duration=%s packets=%d resyncs=%d processed=%s throughput=%.2f GB/min (%.2f MB/s)\n",
			snap.Duration.Round(10*time.Millisecond),
			snap.Packets,
			snap.Resyncs,
			common.FormatBytes(snap.Bytes),
			gbPerMin,
			mbPerSec,
		)
	}
}

func autofixCmd(args []string) {
	fs := flag.NewFlagSet("autofix", flag.ExitOnError)
	in := fs.String("in", "", "input .ch10")
	tmats := fs.String("tmats", "", "TMATS file")
	profile := fs.String("profile", "106-15", "profile")
	rulesPath := fs.String("rules", "", "rulepack.json")
	includeTimestamps := fs.Bool("diag-include-timestamps", true, "include timestamp metadata in diagnostics output")
	concurrency := fs.Int("concurrency", 1, "maximum concurrent channel evaluations")
	fs.Parse(args)

	if *in == "" || *rulesPath == "" {
		fmt.Println("required: --in, --rules")
		os.Exit(1)
	}

	rp, err := rules.LoadRulePack(*rulesPath)
	if err != nil {
		fmt.Println("load rulepack:", err)
		os.Exit(1)
	}
	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConfigValue("diag.include_timestamps", *includeTimestamps)
	engine.SetConcurrency(*concurrency)

	ctx := &rules.Context{InputFile: *in, TMATSFile: *tmats, Profile: *profile}
	diags, err := engine.Eval(ctx)
	if err != nil {
		fmt.Println("eval:", err)
		os.Exit(1)
	}

	fixes := 0
	for _, d := range diags {
		if !d.FixApplied {
			continue
		}
		fixes++
		if d.FixPatchId != "" {
			fmt.Printf("%s: wrote %s\n", d.RuleId, d.FixPatchId)
		}
	}
	if fixes == 0 {
		fmt.Println("No fixes applied")
	}
}

func reportCmd(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	diagPath := fs.String("diagnostics", "", "diagnostics.jsonl")
	accPath := fs.String("acceptance", "", "acceptance_report.json")
	pdfPath := fs.String("pdf", "", "output acceptance report PDF")
	fs.Parse(args)
	if *pdfPath != "" {
		if *accPath == "" {
			fmt.Println("--pdf requires --acceptance")
			os.Exit(1)
		}
		rep, err := report.LoadAcceptanceJSON(*accPath)
		if err != nil {
			fmt.Println("load acceptance:", err)
			os.Exit(1)
		}
		if err := report.SaveAcceptancePDF(rep, *pdfPath); err != nil {
			fmt.Println("write pdf:", err)
			os.Exit(1)
		}
		fmt.Println("Wrote PDF:", *pdfPath)
	}
	fmt.Println("Diagnostics:", *diagPath)
	fmt.Println("Acceptance:", *accPath)
}

func manifestCmd(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	inputs := fs.String("inputs", "", "comma-separated paths")
	out := fs.String("out", "manifest.json", "output json")
	sign := fs.Bool("sign", false, "sign manifest (detached JWS over JSON)")
	keyPath := fs.String("key", "", "PEM private key for signing (requires --sign)")
	certPath := fs.String("cert", "", "PEM certificate describing signer (requires --sign)")
	jwsOut := fs.String("jws-out", "", "output JWS file (defaults to manifest path with .jws)")
	fs.Parse(args)

	if *inputs == "" {
		fmt.Println("required: --inputs")
		os.Exit(1)
	}

	var paths []string
	for _, p := range strings.Split(*inputs, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		fmt.Println("no input paths specified")
		os.Exit(1)
	}

	m, err := manifest.Build(paths)
	if err != nil {
		fmt.Println("manifest build:", err)
		os.Exit(1)
	}

	if !*sign {
		if err := manifest.Save(m, *out); err != nil {
			fmt.Println("manifest save:", err)
			os.Exit(1)
		}
		fmt.Println("Wrote", *out)
		return
	}

	if *keyPath == "" || *certPath == "" {
		fmt.Println("--sign requires --key and --cert")
		os.Exit(1)
	}

	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Println("read key:", err)
		os.Exit(1)
	}
	certBytes, err := os.ReadFile(*certPath)
	if err != nil {
		fmt.Println("read cert:", err)
		os.Exit(1)
	}

	sigPath := *jwsOut
	if sigPath == "" {
		base := *out
		ext := filepath.Ext(base)
		if ext != "" {
			sigPath = base[:len(base)-len(ext)] + ".jws"
		} else {
			sigPath = base + ".jws"
		}
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		fmt.Println("parse cert: no PEM block found")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("parse cert:", err)
		os.Exit(1)
	}

	m.Signature = &manifest.Signature{
		Type:          "jws-detached",
		CertSubject:   cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SignatureFile: sigPath,
	}

	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Println("manifest marshal:", err)
		os.Exit(1)
	}

	jws, err := crypto.SignDetachedJWS(payload, keyBytes)
	if err != nil {
		fmt.Println("manifest sign:", err)
		os.Exit(1)
	}
	jwsBytes, err := json.MarshalIndent(jws, "", "  ")
	if err != nil {
		fmt.Println("jws marshal:", err)
		os.Exit(1)
	}

	if err := os.WriteFile(sigPath, jwsBytes, 0644); err != nil {
		fmt.Println("write jws:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, payload, 0644); err != nil {
		fmt.Println("write manifest:", err)
		os.Exit(1)
	}

	fmt.Println("Wrote", *out)
	fmt.Println("Wrote signature", sigPath)
}

func verifySignatureCmd(args []string) {
	fs := flag.NewFlagSet("verify-signature", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "manifest JSON file")
	jwsPath := fs.String("jws", "", "manifest JWS signature file")
	certPath := fs.String("cert", "", "signer certificate (PEM)")
	fs.Parse(args)

	if *manifestPath == "" || *jwsPath == "" || *certPath == "" {
		fmt.Println("required: --manifest, --jws, --cert")
		os.Exit(1)
	}

	manifestBytes, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Println("read manifest:", err)
		os.Exit(1)
	}
	jwsBytes, err := os.ReadFile(*jwsPath)
	if err != nil {
		fmt.Println("read jws:", err)
		os.Exit(1)
	}
	certBytes, err := os.ReadFile(*certPath)
	if err != nil {
		fmt.Println("read cert:", err)
		os.Exit(1)
	}

	var jwsObj crypto.JWS
	if err := json.Unmarshal(jwsBytes, &jwsObj); err != nil {
		fmt.Println("parse jws:", err)
		os.Exit(1)
	}

	if err := crypto.VerifyDetachedJWS(manifestBytes, jwsObj, certBytes); err != nil {
		fmt.Println("verify signature:", err)
		os.Exit(1)
	}
	fmt.Println("Signature OK")
}

func batchCmd(args []string) {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	inDir := fs.String("in", ".", "input directory")
	profile := fs.String("profile", "106-15", "profile")
	rulesPath := fs.String("rules", "", "rulepack.json")
	outDir := fs.String("out-dir", "out", "results directory")
	fs.Parse(args)
	_ = inDir
	_ = profile
	_ = rulesPath
	_ = outDir
	fmt.Println("Batch mode placeholder: iterate files and call validate")
}
