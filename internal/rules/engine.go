package rules

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"example.com/ch10gate/internal/ch10"
)

type Severity string

const (
	ERROR Severity = "ERROR"
	WARN  Severity = "WARN"
	INFO  Severity = "INFO"
)

type Rule struct {
	RuleId    string         `json:"ruleId"`
	Name      string         `json:"name,omitempty"`
	Scope     string         `json:"scope"` // packet|channel|file|tmats
	AppliesTo map[string]any `json:"appliesTo,omitempty"`
	Severity  Severity       `json:"severity"`
	Fixable   bool           `json:"fixable"`
	FixFunc   string         `json:"fixFunction,omitempty"`
	Refs      []string       `json:"refs"`
	Params    map[string]any `json:"params,omitempty"`
	Message   string         `json:"message"`
}

type RulePack struct {
	RulePackId string `json:"rulePackId"`
	Version    string `json:"version"`
	Profile    string `json:"profile"`
	Rules      []Rule `json:"rules"`
}

type Diagnostic struct {
	Ts              time.Time `json:"ts"`
	File            string    `json:"file"`
	ChannelId       int       `json:"channelId,omitempty"`
	PacketIndex     int       `json:"packetIndex,omitempty"`
	Offset          string    `json:"offset,omitempty"`
	RuleId          string    `json:"ruleId"`
	Severity        Severity  `json:"severity"`
	Message         string    `json:"message"`
	Refs            []string  `json:"refs"`
	FixSuggested    bool      `json:"fixSuggested"`
	FixApplied      bool      `json:"fixApplied"`
	FixPatchId      string    `json:"fixPatchId,omitempty"`
	TimestampUs     *int64    `json:"timestamp_us"`
	TimestampSource *string   `json:"timestamp_source"`
}

type AcceptanceReport struct {
	Summary struct {
		Total    int  `json:"total"`
		Errors   int  `json:"errors"`
		Warnings int  `json:"warnings"`
		Pass     bool `json:"pass"`
	} `json:"summary"`
	GateMatrix []map[string]any `json:"gateMatrix"`
	Findings   []Diagnostic     `json:"findings,omitempty"`
}

type Context struct {
	InputFile string
	TMATSFile string
	Profile   string

	PrimaryHeader *ch10.PacketHeader
	Index         *ch10.FileIndex
}

func (ctx *Context) EnsureFileIndex() error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if ctx.InputFile == "" {
		return nil
	}
	if ctx.Index != nil {
		return nil
	}
	reader, err := ch10.NewReader(ctx.InputFile)
	if err != nil {
		return err
	}
	defer reader.Close()
	for {
		_, _, err := reader.Next()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return err
	}
	hdr, ok := reader.PrimaryHeader()
	if !ok {
		return ch10.ErrNoSync
	}
	idx := reader.Index()
	ctx.Index = &idx
	ctx.PrimaryHeader = &hdr
	return nil
}

type Engine struct {
	rulePack               RulePack
	registry               map[string]FixFunc
	diagnostics            []Diagnostic
	includeTimestampFields bool
}

func NewEngine(rp RulePack) *Engine {
	return &Engine{
		rulePack:               rp,
		registry:               make(map[string]FixFunc),
		includeTimestampFields: true,
	}
}

type FixFunc func(ctx *Context, rule Rule) (Diagnostic, bool, error)

func (e *Engine) Register(name string, f FixFunc) {
	e.registry[name] = f
}

func (e *Engine) Eval(ctx *Context) ([]Diagnostic, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		return nil, err
	}
	var diags []Diagnostic
	for _, r := range e.rulePack.Rules {
		if r.FixFunc == "" {
			continue
		}
		fn, ok := e.registry[r.FixFunc]
		if !ok {
			diags = append(diags, Diagnostic{
				Ts: time.Now(), File: ctx.InputFile, RuleId: r.RuleId, Severity: WARN,
				Message: "no function for rule", Refs: r.Refs, FixSuggested: false,
			})
			continue
		}
		d, applied, err := fn(ctx, r)
		if err != nil {
			d.Severity = ERROR
			d.Message = d.Message + " (" + err.Error() + ")"
		}
		d.FixApplied = applied
		diags = append(diags, d)
	}
	e.diagnostics = diags
	return diags, nil
}

func (e *Engine) WriteDiagnosticsNDJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	for _, d := range e.diagnostics {
		var b []byte
		if e.includeTimestampFields {
			b, _ = json.Marshal(d)
		} else {
			b, _ = json.Marshal(d.toNoTimestamp())
		}
		w.Write(b)
		w.WriteString("\n")
	}
	return nil
}

type diagnosticNoTimestamp struct {
	Ts           time.Time `json:"ts"`
	File         string    `json:"file"`
	ChannelId    int       `json:"channelId,omitempty"`
	PacketIndex  int       `json:"packetIndex,omitempty"`
	Offset       string    `json:"offset,omitempty"`
	RuleId       string    `json:"ruleId"`
	Severity     Severity  `json:"severity"`
	Message      string    `json:"message"`
	Refs         []string  `json:"refs"`
	FixSuggested bool      `json:"fixSuggested"`
	FixApplied   bool      `json:"fixApplied"`
	FixPatchId   string    `json:"fixPatchId,omitempty"`
}

func (d Diagnostic) toNoTimestamp() diagnosticNoTimestamp {
	return diagnosticNoTimestamp{
		Ts:           d.Ts,
		File:         d.File,
		ChannelId:    d.ChannelId,
		PacketIndex:  d.PacketIndex,
		Offset:       d.Offset,
		RuleId:       d.RuleId,
		Severity:     d.Severity,
		Message:      d.Message,
		Refs:         d.Refs,
		FixSuggested: d.FixSuggested,
		FixApplied:   d.FixApplied,
		FixPatchId:   d.FixPatchId,
	}
}

func (e *Engine) SetConfigValue(key string, value any) {
	if e == nil {
		return
	}
	switch key {
	case "diag.include_timestamps":
		switch v := value.(type) {
		case bool:
			e.includeTimestampFields = v
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				e.includeTimestampFields = b
			}
		default:
			if s, ok := value.(fmt.Stringer); ok {
				if b, err := strconv.ParseBool(s.String()); err == nil {
					e.includeTimestampFields = b
				}
			}
		}
	}
}

func (e *Engine) MakeAcceptance() AcceptanceReport {
	var rep AcceptanceReport
	var errs, warns int
	for _, d := range e.diagnostics {
		switch d.Severity {
		case ERROR:
			errs++
		case WARN:
			warns++
		}
	}
	rep.Summary.Total = len(e.diagnostics)
	rep.Summary.Errors = errs
	rep.Summary.Warnings = warns
	rep.Summary.Pass = errs == 0
	rep.Findings = e.diagnostics
	return rep
}

func LoadRulePack(path string) (RulePack, error) {
	var rp RulePack
	b, err := os.ReadFile(path)
	if err != nil {
		return rp, err
	}
	err = json.Unmarshal(b, &rp)
	return rp, err
}

var ErrNotImplemented = errors.New("fix not implemented yet")
