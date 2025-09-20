package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"example.com/ch10gate/internal/common"
	"example.com/ch10gate/internal/crypto"
	"example.com/ch10gate/internal/dict"
	"example.com/ch10gate/internal/manifest"
	"example.com/ch10gate/internal/report"
	"example.com/ch10gate/internal/rules"
	"example.com/ch10gate/internal/tmats"
	"example.com/ch10gate/internal/update"
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
	case "undo":
		undoCmd(os.Args[2:])
	case "rulepack":
		rulepackCmd(os.Args[2:])
	case "update":
		updateCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Printf(`ch10ctl %s (built %s) <command> [options]

Commands:
  validate  --in <file> --profile <profile> [--rules <rulepack.json> | --rulepack-id <id> [--rulepack-version <version>]] [--dict <dict.json>] --tmats <file> --out <diagnostics.jsonl> --acceptance <acceptance.json>
  autofix   --in <file> --profile <profile> [--rules <rulepack.json> | --rulepack-id <id> [--rulepack-version <version>]] [--dict <dict.json>] --tmats <file>
  report    --diagnostics <diagnostics.jsonl> --acceptance <acceptance.json> [--pdf <report.pdf> --lang <en|tr> --manifest <manifest.json>]
  manifest  --inputs <comma-separated> --out <manifest.json> [--sign --key <key.pem> --cert <cert.pem> --jws-out <file>]
  verify-signature --manifest <manifest.json> --jws <signature.jws> --cert <cert.pem>
  batch     --in <dir> --profile <profile> [--rules <rulepack.json> | --rulepack-id <id> [--rulepack-version <version>]] [--dict <dict.json>] [--tmats-dir <dir>] [--allow-unsigned-rulepack] --out-dir <dir>
  undo      --in <file.fixed.ch10> --audit <audit.jsonl> --out <restored.ch10>
  rulepack  <install|list|remove|verify|set-default> [...]
  update    --from <dir> [--install-root <dir> --bin-dir <dir> --cert <file>]
`, version, buildDate)
}

func machineHashForError() string {
	hash, err := common.MachineFingerprint()
	if err != nil {
		return fmt.Sprintf("unavailable (%v)", err)
	}
	return hash
}

type validationOptions struct {
	InputFile         string
	TMATSFile         string
	Profile           string
	RulesPath         string
	RulePackID        string
	RulePackVersion   string
	AllowUnsigned     bool
	DictPath          string
	OutDiagnostics    string
	OutAcceptance     string
	IncludeTimestamps bool
	Concurrency       int
	Metrics           *common.Metrics
	Progress          bool
	ProgressWriter    io.Writer
}

type validationResult struct {
	RulePack       rules.RulePack
	RulePackSource rules.RulePackSource
	Acceptance     rules.AcceptanceReport
	Diagnostics    []rules.Diagnostic
}

func ensureParentDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func runValidation(opts validationOptions) (validationResult, error) {
	var result validationResult

	rp, source, err := rules.ResolveRulePack(rules.RulePackRequest{
		Path:          opts.RulesPath,
		RulePackId:    opts.RulePackID,
		Version:       opts.RulePackVersion,
		Profile:       opts.Profile,
		AllowUnsigned: opts.AllowUnsigned,
	})
	if err != nil {
		return result, fmt.Errorf("resolve rulepack: %w", err)
	}
	result.RulePack = rp
	result.RulePackSource = source

	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConfigValue("diag.include_timestamps", opts.IncludeTimestamps)
	if opts.Concurrency > 0 {
		engine.SetConcurrency(opts.Concurrency)
	}

	ctx := &rules.Context{InputFile: opts.InputFile, TMATSFile: opts.TMATSFile, Profile: opts.Profile, Metrics: opts.Metrics}
	if err := configureDictionaries(ctx, opts.DictPath); err != nil {
		return result, fmt.Errorf("dictionary: %w", err)
	}

	if opts.Metrics != nil {
		opts.Metrics.Start()
	}
	var stopProgress func()
	if opts.Progress && opts.Metrics != nil {
		progressWriter := opts.ProgressWriter
		if progressWriter == nil {
			progressWriter = os.Stderr
		}
		stopProgress = common.StartProgressPrinter(progressWriter, opts.Metrics, 500*time.Millisecond)
	}

	diags, err := engine.Eval(ctx)
	if stopProgress != nil {
		stopProgress()
	}
	if opts.Metrics != nil {
		opts.Metrics.Stop()
	}
	if err != nil {
		return result, fmt.Errorf("eval: %w", err)
	}

	if err := ensureParentDir(opts.OutDiagnostics); err != nil {
		return result, fmt.Errorf("prepare diagnostics output: %w", err)
	}
	if opts.OutDiagnostics != "" {
		if err := engine.WriteDiagnosticsNDJSON(opts.OutDiagnostics); err != nil {
			return result, fmt.Errorf("write diags: %w", err)
		}
	}

	rep := engine.MakeAcceptance()
	result.Acceptance = rep
	result.Diagnostics = diags

	if err := ensureParentDir(opts.OutAcceptance); err != nil {
		return result, fmt.Errorf("prepare acceptance output: %w", err)
	}
	if opts.OutAcceptance != "" {
		if err := report.SaveAcceptanceJSON(rep, opts.OutAcceptance); err != nil {
			return result, fmt.Errorf("write report: %w", err)
		}
	}

	return result, nil
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	in := fs.String("in", "", "input .ch10")
	tmats := fs.String("tmats", "", "TMATS file")
	profile := fs.String("profile", "106-15", "profile")
	rulesPath := fs.String("rules", "", "rulepack.json")
	rulePackID := fs.String("rulepack-id", "", "installed rule pack identifier")
	rulePackVersion := fs.String("rulepack-version", "", "installed rule pack version")
	allowUnsigned := fs.Bool("allow-unsigned-rulepack", false, "allow validation with unsigned rule packs")
	outDiag := fs.String("out", "diagnostics.jsonl", "diagnostics output")
	outAcc := fs.String("acceptance", "acceptance_report.json", "acceptance json")
	includeTimestamps := fs.Bool("diag-include-timestamps", true, "include timestamp metadata in diagnostics output")
	concurrency := fs.Int("concurrency", runtime.NumCPU(), "maximum concurrent channel evaluations")
	metricsFlag := fs.Bool("metrics", false, "print validation throughput metrics")
	progressFlag := fs.Bool("progress", false, "display validation progress updates")
	dictPath := fs.String("dict", "", "dictionary JSON file")
	fs.Parse(args)

	if *in == "" {
		fmt.Println("required: --in")
		os.Exit(1)
	}
	if *rulesPath != "" && *rulePackID != "" {
		fmt.Println("--rules and --rulepack-id cannot be used together")
		os.Exit(1)
	}
	if *rulePackVersion != "" && *rulePackID == "" {
		fmt.Println("--rulepack-version requires --rulepack-id")
		os.Exit(1)
	}

	var metrics *common.Metrics
	if *metricsFlag || *progressFlag {
		metrics = common.NewMetrics()
		if info, err := os.Stat(*in); err == nil {
			metrics.SetTotalBytes(info.Size())
		}
	}

	result, err := runValidation(validationOptions{
		InputFile:         *in,
		TMATSFile:         *tmats,
		Profile:           *profile,
		RulesPath:         *rulesPath,
		RulePackID:        *rulePackID,
		RulePackVersion:   *rulePackVersion,
		AllowUnsigned:     *allowUnsigned,
		DictPath:          *dictPath,
		OutDiagnostics:    *outDiag,
		OutAcceptance:     *outAcc,
		IncludeTimestamps: *includeTimestamps,
		Concurrency:       *concurrency,
		Metrics:           metrics,
		Progress:          *progressFlag,
		ProgressWriter:    os.Stderr,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if result.RulePackSource.FromRepository {
		fmt.Printf("Using rule pack %s@%s (profile %s)\n", result.RulePackSource.RulePackId, result.RulePackSource.Version, result.RulePack.Profile)
		if result.RulePackSource.Unsigned {
			fmt.Println("WARNING: rule pack is unsigned")
		}
	}

	fmt.Printf("PASS=%v, errors=%d, warnings=%d, diagnostics=%d\n", result.Acceptance.Summary.Pass, result.Acceptance.Summary.Errors, result.Acceptance.Summary.Warnings, len(result.Diagnostics))
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
	rulePackID := fs.String("rulepack-id", "", "installed rule pack identifier")
	rulePackVersion := fs.String("rulepack-version", "", "installed rule pack version")
	allowUnsigned := fs.Bool("allow-unsigned-rulepack", false, "allow validation with unsigned rule packs")
	includeTimestamps := fs.Bool("diag-include-timestamps", true, "include timestamp metadata in diagnostics output")
	concurrency := fs.Int("concurrency", 1, "maximum concurrent channel evaluations")
	auditPath := fs.String("audit", "", "audit log output (jsonl)")
	dictPath := fs.String("dict", "", "dictionary JSON file")
	fs.Parse(args)

	if *in == "" {
		fmt.Println("required: --in")
		os.Exit(1)
	}
	if *rulesPath != "" && *rulePackID != "" {
		fmt.Println("--rules and --rulepack-id cannot be used together")
		os.Exit(1)
	}
	if *rulePackVersion != "" && *rulePackID == "" {
		fmt.Println("--rulepack-version requires --rulepack-id")
		os.Exit(1)
	}

	auditLogPath := *auditPath
	if auditLogPath == "" {
		auditLogPath = *in + ".audit.jsonl"
	}

	rp, source, err := rules.ResolveRulePack(rules.RulePackRequest{
		Path:          *rulesPath,
		RulePackId:    *rulePackID,
		Version:       *rulePackVersion,
		Profile:       *profile,
		AllowUnsigned: *allowUnsigned,
	})
	if err != nil {
		fmt.Println("resolve rulepack:", err)
		os.Exit(1)
	}
	if source.FromRepository {
		fmt.Printf("Using rule pack %s@%s (profile %s)\n", source.RulePackId, source.Version, rp.Profile)
		if source.Unsigned {
			fmt.Println("WARNING: rule pack is unsigned")
		}
	}
	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConfigValue("diag.include_timestamps", *includeTimestamps)
	engine.SetConcurrency(*concurrency)

	ctx := &rules.Context{InputFile: *in, TMATSFile: *tmats, Profile: *profile}
	if err := configureDictionaries(ctx, *dictPath); err != nil {
		fmt.Println("dictionary:", err)
		os.Exit(1)
	}
	if auditLogPath != "" {
		ctx.AuditLog = common.NewPatchLog(auditLogPath)
	}
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
		return
	}
	if ctx.AuditLog != nil {
		fmt.Printf("Audit log: %s\n", ctx.AuditLog.Path())
	}
}

func configureDictionaries(ctx *rules.Context, flagValue string) error {
	if ctx == nil {
		return nil
	}
	path := strings.TrimSpace(flagValue)
	if path != "" {
		store, err := dict.EnsureLoaded(path)
		if err != nil {
			return fmt.Errorf("load dictionary %s: %w", path, err)
		}
		ctx.DictionaryPath = path
		ctx.Dictionaries = store
		return nil
	}
	if strings.TrimSpace(ctx.TMATSFile) == "" {
		return nil
	}
	doc, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		return fmt.Errorf("parse TMATS %s: %w", ctx.TMATSFile, err)
	}
	raw, ok := dict.PathFromTMATS(doc)
	if !ok {
		return nil
	}
	resolved := dict.ResolveTMATSPath(ctx.TMATSFile, raw)
	store, err := dict.EnsureLoaded(resolved)
	if err != nil {
		return fmt.Errorf("load dictionary %s: %w", resolved, err)
	}
	ctx.DictionaryPath = resolved
	ctx.Dictionaries = store
	return nil
}

func undoCmd(args []string) {
	fs := flag.NewFlagSet("undo", flag.ExitOnError)
	in := fs.String("in", "", "fixed Chapter 10 file")
	audit := fs.String("audit", "", "audit log (jsonl)")
	out := fs.String("out", "", "restored output file")
	fs.Parse(args)

	if *in == "" || *audit == "" || *out == "" {
		fmt.Println("required: --in, --audit, --out")
		os.Exit(1)
	}

	entries, err := common.ReadPatchLog(*audit)
	if err != nil {
		fmt.Println("read audit:", err)
		os.Exit(1)
	}
	if len(entries) == 0 {
		fmt.Println("audit log is empty")
		os.Exit(1)
	}

	patchedHash, _, err := common.Sha256OfFile(*in)
	if err != nil {
		fmt.Println("hash input:", err)
		os.Exit(1)
	}

	if err := copyFile(*in, *out); err != nil {
		fmt.Println("copy input:", err)
		os.Exit(1)
	}

	f, err := os.OpenFile(*out, os.O_RDWR, 0)
	if err != nil {
		fmt.Println("open output:", err)
		os.Exit(1)
	}
	defer f.Close()

	mismatches := 0
	applied := 0
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		before, err := entry.BeforeBytes()
		if err != nil {
			fmt.Printf("skip entry %d: decode beforeHex failed: %v\n", i, err)
			continue
		}
		after, err := entry.AfterBytes()
		if err != nil {
			fmt.Printf("skip entry %d: decode afterHex failed: %v\n", i, err)
			continue
		}
		if entry.Offset < 0 {
			fmt.Printf("skip entry %d: invalid offset %d\n", i, entry.Offset)
			continue
		}
		mismatch := false
		if len(after) != len(before) {
			mismatch = true
		}
		if len(after) > 0 {
			buf := make([]byte, len(after))
			if _, err := f.ReadAt(buf, entry.Offset); err != nil || !bytes.Equal(buf, after) {
				mismatch = true
			}
		}
		if len(before) > 0 {
			if _, err := f.WriteAt(before, entry.Offset); err != nil {
				fmt.Println("write patch:", err)
				os.Exit(1)
			}
		}
		if mismatch {
			mismatches++
		}
		applied++
	}

	if err := f.Sync(); err != nil {
		fmt.Println("sync output:", err)
		os.Exit(1)
	}

	restoredHash, _, err := common.Sha256OfFile(*out)
	if err != nil {
		fmt.Println("hash restored:", err)
		os.Exit(1)
	}

	fmt.Printf("Restored %d patch(es) to %s\n", applied, *out)
	fmt.Printf("Patched SHA256: %s\n", patchedHash)
	fmt.Printf("Restored SHA256: %s\n", restoredHash)
	if mismatches > 0 {
		fmt.Printf("Warning: %d patch(es) did not match expected fixed bytes; original bytes reapplied regardless.\n", mismatches)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func reportCmd(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	diagPath := fs.String("diagnostics", "", "diagnostics.jsonl")
	accPath := fs.String("acceptance", "", "acceptance_report.json")
	pdfPath := fs.String("pdf", "", "output acceptance report PDF")
	langFlag := fs.String("lang", "en", "PDF language (en or tr)")
	manifestPath := fs.String("manifest", "", "manifest JSON used to derive QR hash")
	fs.Parse(args)
	if *pdfPath != "" {
		if *accPath == "" {
			fmt.Println("--pdf requires --acceptance")
			os.Exit(1)
		}
		lang, err := report.ParseLanguage(*langFlag)
		if err != nil {
			fmt.Println("lang:", err)
			os.Exit(1)
		}
		rep, err := report.LoadAcceptanceJSON(*accPath)
		if err != nil {
			fmt.Println("load acceptance:", err)
			os.Exit(1)
		}
		opts := report.PDFOptions{Lang: lang}
		if *manifestPath != "" {
			hash, err := manifestShortHash(*manifestPath)
			if err != nil {
				fmt.Println("manifest hash:", err)
				os.Exit(1)
			}
			opts.ManifestHash = hash
		}
		if err := report.SaveAcceptancePDF(rep, *pdfPath, opts); err != nil {
			fmt.Println("write pdf:", err)
			os.Exit(1)
		}
		fmt.Println("Wrote PDF:", *pdfPath)
	}
	fmt.Println("Diagnostics:", *diagPath)
	fmt.Println("Acceptance:", *accPath)
}

func manifestShortHash(path string) (string, error) {
	sum, _, err := common.Sha256OfFile(path)
	if err != nil {
		return "", err
	}
	if len(sum) < 32 {
		return "", fmt.Errorf("manifest hash too short: %d", len(sum))
	}
	return strings.ToUpper(sum[:32]), nil
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

func updateCmd(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	fromDir := fs.String("from", "", "directory containing .update.zip")
	installRoot := fs.String("install-root", update.DefaultInstallRoot, "installation root directory")
	binDir := fs.String("bin-dir", update.DefaultBinDir, "directory for binary symlinks")
	certPath := fs.String("cert", update.DefaultCertPath, "trusted signer certificate (PEM)")
	fs.Parse(args)

	if *fromDir == "" {
		fmt.Println("required: --from")
		os.Exit(1)
	}

	archivePath, err := update.FindArchive(*fromDir)
	if err != nil {
		fmt.Println("locate update:", err)
		os.Exit(1)
	}

	installer, err := update.NewInstaller(update.Options{
		InstallRoot: *installRoot,
		BinDir:      *binDir,
		CertPath:    *certPath,
	})
	if err != nil {
		fmt.Println("initialise installer:", err)
		os.Exit(1)
	}

	result, err := installer.InstallFromArchive(archivePath)
	if err != nil {
		fmt.Println("install update:", err)
		os.Exit(1)
	}
	if result.PreviousVersion != "" {
		fmt.Printf("Updated %s -> %s\n", result.PreviousVersion, result.Version)
	} else {
		fmt.Printf("Installed version %s\n", result.Version)
	}
}

func batchCmd(args []string) {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	inDir := fs.String("in", ".", "input directory")
	profile := fs.String("profile", "106-15", "profile")
	rulesPath := fs.String("rules", "", "rulepack.json")
	rulePackID := fs.String("rulepack-id", "", "installed rule pack identifier")
	rulePackVersion := fs.String("rulepack-version", "", "installed rule pack version")
	allowUnsigned := fs.Bool("allow-unsigned-rulepack", false, "allow validation with unsigned rule packs")
	dictPath := fs.String("dict", "", "dictionary JSON file")
	tmatsDir := fs.String("tmats-dir", "", "directory containing TMATS files")
	outDir := fs.String("out-dir", "out", "results directory")
	includeTimestamps := fs.Bool("diag-include-timestamps", true, "include timestamp metadata in diagnostics output")
	concurrency := fs.Int("concurrency", runtime.NumCPU(), "maximum concurrent channel evaluations")
	fs.Parse(args)

	if *rulesPath != "" && *rulePackID != "" {
		fmt.Println("--rules and --rulepack-id cannot be used together")
		os.Exit(1)
	}
	if *rulePackVersion != "" && *rulePackID == "" {
		fmt.Println("--rulepack-version requires --rulepack-id")
		os.Exit(1)
	}
	if strings.TrimSpace(*inDir) == "" {
		fmt.Println("required: --in")
		os.Exit(1)
	}
	if strings.TrimSpace(*outDir) == "" {
		fmt.Println("required: --out-dir")
		os.Exit(1)
	}

	if info, err := os.Stat(*inDir); err != nil {
		fmt.Println("input directory:", err)
		os.Exit(1)
	} else if !info.IsDir() {
		fmt.Println("--in must point to a directory")
		os.Exit(1)
	}

	var inputs []string
	if err := filepath.WalkDir(*inDir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".ch10") {
			inputs = append(inputs, path)
		}
		return nil
	}); err != nil {
		fmt.Println("walk input:", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Printf("No .ch10 files found in %s\n", *inDir)
		return
	}
	sort.Strings(inputs)

	type batchFileResult struct {
		Input       string
		OutputDir   string
		Acceptance  rules.AcceptanceReport
		Diagnostics int
		Err         error
	}

	var results []batchFileResult
	printedRulePack := false

	for _, ch10Path := range inputs {
		res := batchFileResult{Input: ch10Path}
		func() {
			tmatsPath := findMatchingTMATS(ch10Path, *tmatsDir)
			workDir, err := os.MkdirTemp("", "ch10ctl-batch-")
			if err != nil {
				res.Err = fmt.Errorf("create temp workspace: %w", err)
				fmt.Fprintf(os.Stderr, "prepare workspace for %s: %v\n", ch10Path, err)
				return
			}
			defer os.RemoveAll(workDir)

			diagOut := filepath.Join(workDir, "diagnostics.jsonl")
			accOut := filepath.Join(workDir, "acceptance.json")
			result, err := runValidation(validationOptions{
				InputFile:         ch10Path,
				TMATSFile:         tmatsPath,
				Profile:           *profile,
				RulesPath:         *rulesPath,
				RulePackID:        *rulePackID,
				RulePackVersion:   *rulePackVersion,
				AllowUnsigned:     *allowUnsigned,
				DictPath:          *dictPath,
				OutDiagnostics:    diagOut,
				OutAcceptance:     accOut,
				IncludeTimestamps: *includeTimestamps,
				Concurrency:       *concurrency,
			})
			if err != nil {
				res.Err = err
				fmt.Fprintf(os.Stderr, "validate %s: %v\n", ch10Path, err)
				return
			}

			if result.RulePackSource.FromRepository && !printedRulePack {
				fmt.Printf("Using rule pack %s@%s (profile %s)\n", result.RulePackSource.RulePackId, result.RulePackSource.Version, result.RulePack.Profile)
				if result.RulePackSource.Unsigned {
					fmt.Println("WARNING: rule pack is unsigned")
				}
				printedRulePack = true
			}

			base := strings.TrimSuffix(filepath.Base(ch10Path), filepath.Ext(ch10Path))
			finalDir := filepath.Join(*outDir, base)
			if err := os.MkdirAll(finalDir, 0o755); err != nil {
				res.Err = fmt.Errorf("prepare output directory: %w", err)
				fmt.Fprintf(os.Stderr, "prepare output for %s: %v\n", ch10Path, err)
				return
			}
			if err := copyFile(diagOut, filepath.Join(finalDir, "diagnostics.jsonl")); err != nil {
				res.Err = fmt.Errorf("write diagnostics: %w", err)
				fmt.Fprintf(os.Stderr, "write diagnostics for %s: %v\n", ch10Path, err)
				return
			}
			if err := copyFile(accOut, filepath.Join(finalDir, "acceptance.json")); err != nil {
				res.Err = fmt.Errorf("write acceptance: %w", err)
				fmt.Fprintf(os.Stderr, "write acceptance for %s: %v\n", ch10Path, err)
				return
			}

			fmt.Printf("Validated %s -> %s\n", ch10Path, finalDir)
			res.OutputDir = finalDir
			res.Acceptance = result.Acceptance
			res.Diagnostics = len(result.Diagnostics)
		}()
		results = append(results, res)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tSTATUS\tERRORS\tWARNINGS\tDIAGNOSTICS\tOUTPUT")
	failed := false
	for _, r := range results {
		display := r.Input
		if rel, err := filepath.Rel(*inDir, r.Input); err == nil {
			display = rel
		}
		if r.Err != nil {
			fmt.Fprintf(w, "%s\tERROR\t-\t-\t-\t%s\n", display, r.Err)
			failed = true
			continue
		}
		status := "PASS"
		if !r.Acceptance.Summary.Pass {
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n", display, status, r.Acceptance.Summary.Errors, r.Acceptance.Summary.Warnings, r.Diagnostics, r.OutputDir)
	}
	w.Flush()
	if failed {
		os.Exit(1)
	}
}

func findMatchingTMATS(ch10Path, tmatsDir string) string {
	baseName := strings.TrimSuffix(filepath.Base(ch10Path), filepath.Ext(ch10Path))
	sameDir := filepath.Join(filepath.Dir(ch10Path), baseName+".tmats")
	if info, err := os.Stat(sameDir); err == nil && !info.IsDir() {
		return sameDir
	}
	if strings.TrimSpace(tmatsDir) != "" {
		candidate := filepath.Join(tmatsDir, baseName+".tmats")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func rulepackCmd(args []string) {
	if len(args) == 0 {
		rulepackUsage()
		os.Exit(1)
	}
	sub := args[0]
	switch sub {
	case "install":
		rulepackInstallCmd(args[1:])
	case "list":
		rulepackListCmd(args[1:])
	case "remove":
		rulepackRemoveCmd(args[1:])
	case "verify":
		rulepackVerifyCmd(args[1:])
	case "set-default":
		rulepackSetDefaultCmd(args[1:])
	default:
		fmt.Println("unknown rulepack subcommand")
		rulepackUsage()
		os.Exit(1)
	}
}

func rulepackUsage() {
	fmt.Println("rulepack commands:")
	fmt.Println("  install --file <package.rpkg.zip> [--allow-unsigned]")
	fmt.Println("  list")
	fmt.Println("  remove --id <rulepack> --version <version>")
	fmt.Println("  verify --id <rulepack> --version <version>")
	fmt.Println("  set-default --profile <profile> --id <rulepack> --version <version>")
}

func rulepackInstallCmd(args []string) {
	fs := flag.NewFlagSet("rulepack install", flag.ExitOnError)
	file := fs.String("file", "", "path to .rpkg.zip package")
	allowUnsigned := fs.Bool("allow-unsigned", false, "allow installing unsigned packages")
	fs.Parse(args)

	if *file == "" {
		fmt.Println("required: --file")
		os.Exit(1)
	}
	repo, err := rules.DefaultRepository()
	if err != nil {
		fmt.Println("open repository:", err)
		os.Exit(1)
	}
	installed, err := repo.InstallPackage(*file, *allowUnsigned)
	if err != nil {
		fmt.Println("install rule pack:", err)
		os.Exit(1)
	}
	fmt.Printf("Installed %s@%s (profile %s)\n", installed.RulePack.RulePackId, installed.RulePack.Version, installed.RulePack.Profile)
	if installed.Signed {
		if installed.Signer != "" {
			fmt.Printf("Signer: %s\n", installed.Signer)
		}
	} else {
		fmt.Println("Package installed without signature")
	}
}

func rulepackListCmd(args []string) {
	fs := flag.NewFlagSet("rulepack list", flag.ExitOnError)
	fs.Parse(args)
	repo, err := rules.DefaultRepository()
	if err != nil {
		fmt.Println("open repository:", err)
		os.Exit(1)
	}
	entries, err := repo.ListInstalled()
	if err != nil {
		fmt.Println("list rule packs:", err)
		os.Exit(1)
	}
	defaults, err := repo.Defaults()
	if err != nil {
		fmt.Println("load defaults:", err)
		os.Exit(1)
	}
	if len(entries) == 0 {
		fmt.Println("No rule packs installed")
		return
	}
	byKey := make(map[string][]string)
	for profile, ref := range defaults {
		key := ref.RulePackId + "@" + ref.Version
		byKey[key] = append(byKey[key], profile)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tVERSION\tPROFILE\tSIGNED\tDEFAULT FOR\tSIGNER")
	for _, entry := range entries {
		key := entry.RulePack.RulePackId + "@" + entry.RulePack.Version
		profiles := byKey[key]
		sort.Strings(profiles)
		signed := "yes"
		if !entry.Signed {
			signed = "no"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			entry.RulePack.RulePackId,
			entry.RulePack.Version,
			entry.RulePack.Profile,
			signed,
			strings.Join(profiles, ","),
			entry.Signer,
		)
	}
	w.Flush()
}

func rulepackRemoveCmd(args []string) {
	fs := flag.NewFlagSet("rulepack remove", flag.ExitOnError)
	id := fs.String("id", "", "rule pack identifier")
	version := fs.String("version", "", "rule pack version")
	fs.Parse(args)

	if *id == "" || *version == "" {
		fmt.Println("required: --id, --version")
		os.Exit(1)
	}
	repo, err := rules.DefaultRepository()
	if err != nil {
		fmt.Println("open repository:", err)
		os.Exit(1)
	}
	if err := repo.Remove(*id, *version); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("rule pack not found")
		} else {
			fmt.Println("remove rule pack:", err)
		}
		os.Exit(1)
	}
	fmt.Printf("Removed %s@%s\n", *id, *version)
}

func rulepackVerifyCmd(args []string) {
	fs := flag.NewFlagSet("rulepack verify", flag.ExitOnError)
	id := fs.String("id", "", "rule pack identifier")
	version := fs.String("version", "", "rule pack version")
	fs.Parse(args)

	if *id == "" || *version == "" {
		fmt.Println("required: --id, --version")
		os.Exit(1)
	}
	repo, err := rules.DefaultRepository()
	if err != nil {
		fmt.Println("open repository:", err)
		os.Exit(1)
	}
	_, source, err := repo.Load(*id, *version, false)
	if err != nil {
		fmt.Println("verify rule pack:", err)
		os.Exit(1)
	}
	msg := "Signature OK"
	if source.Signer != "" {
		msg += fmt.Sprintf(" (signed by %s)", source.Signer)
	}
	fmt.Println(msg)
}

func rulepackSetDefaultCmd(args []string) {
	fs := flag.NewFlagSet("rulepack set-default", flag.ExitOnError)
	profile := fs.String("profile", "", "profile name")
	id := fs.String("id", "", "rule pack identifier")
	version := fs.String("version", "", "rule pack version")
	fs.Parse(args)

	if *profile == "" || *id == "" || *version == "" {
		fmt.Println("required: --profile, --id, --version")
		os.Exit(1)
	}
	repo, err := rules.DefaultRepository()
	if err != nil {
		fmt.Println("open repository:", err)
		os.Exit(1)
	}
	rp, source, err := repo.Load(*id, *version, true)
	if err != nil {
		fmt.Println("load rule pack:", err)
		os.Exit(1)
	}
	if source.Unsigned {
		fmt.Println("WARNING: selected rule pack is unsigned")
	}
	if rp.Profile != "" && rp.Profile != *profile {
		fmt.Printf("Warning: rule pack profile is %s\n", rp.Profile)
	}
	if err := repo.SetDefaultForProfile(*profile, rules.RulePackRef{RulePackId: *id, Version: *version}); err != nil {
		fmt.Println("set default:", err)
		os.Exit(1)
	}
	fmt.Printf("Default for profile %s set to %s@%s\n", *profile, *id, *version)
}
