package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"example.com/ch10gate/internal/manifest"
	"example.com/ch10gate/internal/report"
	"example.com/ch10gate/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
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
	case "batch":
		batchCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Print(`ch10ctl <command> [options]

Commands:
  validate  --in <file> --profile <profile> --rules <rulepack.json> --tmats <file> --out <diagnostics.jsonl> --acceptance <acceptance.json>
  autofix   --in <file> --profile <profile> --rules <rulepack.json> --tmats <file>
  report    --diagnostics <diagnostics.jsonl> --acceptance <acceptance.json>
  manifest  --inputs <comma-separated> --out <manifest.json> [--sign]
  batch     --in <dir> --profile <profile> --rules <rulepack.json> --out-dir <dir>
`)
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

	ctx := &rules.Context{InputFile: *in, TMATSFile: *tmats, Profile: *profile}
	diags, err := engine.Eval(ctx)
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
}

func autofixCmd(args []string) {
	validateCmd(args)
}

func reportCmd(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	diagPath := fs.String("diagnostics", "", "diagnostics.jsonl")
	accPath := fs.String("acceptance", "", "acceptance_report.json")
	fs.Parse(args)
	fmt.Println("Diagnostics:", *diagPath)
	fmt.Println("Acceptance:", *accPath)
}

func manifestCmd(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	inputs := fs.String("inputs", "", "comma-separated paths")
	out := fs.String("out", "manifest.json", "output json")
	sign := fs.Bool("sign", false, "sign manifest (detached JWS over JSON)")
	fs.Parse(args)

	paths := strings.Split(*inputs, ",")
	m, err := manifest.Build(paths)
	if err != nil {
		fmt.Println("manifest build:", err)
		os.Exit(1)
	}

	// Signing placeholder: left as future step using internal/crypto
	_ = sign

	if err := manifest.Save(m, *out); err != nil {
		fmt.Println("manifest save:", err)
		os.Exit(1)
	}
	fmt.Println("Wrote", *out)
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
