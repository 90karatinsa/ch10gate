package rules

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/common"
)

type Severity string

const (
	ERROR Severity = "ERROR"
	WARN  Severity = "WARN"
	INFO  Severity = "INFO"
)

type RuleStage string

const (
	StageHeader       RuleStage = "header"
	StageTime         RuleStage = "time"
	StageTypeSpecific RuleStage = "type-specific"
	StageTMATS        RuleStage = "tmats"
	StageStructWrite  RuleStage = "struct-write"
)

var stageOrder = []RuleStage{
	StageHeader,
	StageTime,
	StageTypeSpecific,
	StageTMATS,
	StageStructWrite,
}

func (s RuleStage) normalize() RuleStage {
	switch s {
	case StageHeader, StageTime, StageTypeSpecific, StageTMATS, StageStructWrite:
		return s
	default:
		return StageTypeSpecific
	}
}

type AppliesTo struct {
	Channels  []uint16 `json:"channels,omitempty"`
	DataTypes []uint16 `json:"dataTypes,omitempty"`
}

type Rule struct {
	RuleId    string         `json:"ruleId"`
	Name      string         `json:"name,omitempty"`
	Scope     string         `json:"scope"` // packet|channel|file|tmats
	AppliesTo AppliesTo      `json:"appliesTo,omitempty"`
	Stage     RuleStage      `json:"stage,omitempty"`
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

type GateResult struct {
	RuleId   string    `json:"ruleId"`
	Name     string    `json:"name,omitempty"`
	Stage    RuleStage `json:"stage,omitempty"`
	Severity Severity  `json:"severity"`
	Pass     bool      `json:"pass"`
	Findings int       `json:"findings"`
	Refs     []string  `json:"refs,omitempty"`
}

type AcceptanceReport struct {
	Summary struct {
		Total    int  `json:"total"`
		Errors   int  `json:"errors"`
		Warnings int  `json:"warnings"`
		Pass     bool `json:"pass"`
	} `json:"summary"`
	GateMatrix []GateResult `json:"gateMatrix"`
	Findings   []Diagnostic `json:"findings,omitempty"`
}

type Context struct {
	InputFile string
	TMATSFile string
	Profile   string

	PrimaryHeader *ch10.PacketHeader
	Index         *ch10.FileIndex

	Metrics *common.Metrics
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
	if ctx.Metrics != nil {
		reader.SetMetrics(ctx.Metrics)
	}
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
	concurrency            int

	stageBuckets map[RuleStage][]Rule
	ruleIndex    map[string]Rule

	diagnosticCallback func(Diagnostic) error
	diagnosticErr      error
}

func NewEngine(rp RulePack) *Engine {
	eng := &Engine{
		rulePack:               rp,
		registry:               make(map[string]FixFunc),
		includeTimestampFields: true,
		concurrency:            1,
	}
	eng.rebuildStageBuckets()
	return eng
}

type FixFunc func(ctx *Context, rule Rule) (Diagnostic, bool, error)

func (e *Engine) Register(name string, f FixFunc) {
	e.registry[name] = f
}

func (e *Engine) SetConcurrency(n int) {
	if n <= 0 {
		n = 1
	}
	e.concurrency = n
}

func (e *Engine) SetDiagnosticCallback(cb func(Diagnostic) error) {
	if e == nil {
		return
	}
	e.diagnosticCallback = cb
}

func (e *Engine) rebuildStageBuckets() {
	buckets := make(map[RuleStage][]Rule)
	index := make(map[string]Rule)
	for _, r := range e.rulePack.Rules {
		stage := r.Stage.normalize()
		r.Stage = stage
		buckets[stage] = append(buckets[stage], r)
		index[r.RuleId] = r
	}
	e.stageBuckets = buckets
	e.ruleIndex = index
}

func (e *Engine) Eval(ctx *Context) ([]Diagnostic, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := ctx.EnsureFileIndex(); err != nil {
		return nil, err
	}
	if e.stageBuckets == nil {
		e.rebuildStageBuckets()
	}
	baseIdx := ctx.Index
	var diags []Diagnostic
	e.diagnosticErr = nil
	for _, stage := range stageOrder {
		rules := e.stageBuckets[stage]
		if len(rules) == 0 {
			continue
		}
		for _, r := range rules {
			if r.FixFunc == "" {
				continue
			}
			fn, ok := e.registry[r.FixFunc]
			if !ok {
				diag := Diagnostic{
					Ts: time.Now(), File: ctx.InputFile, RuleId: r.RuleId, Severity: WARN,
					Message: "no function for rule", Refs: r.Refs, FixSuggested: false,
				}
				e.emitDiagnostic(diag)
				diags = append(diags, diag)
				continue
			}
			stageDiags := e.evaluateRule(ctx, baseIdx, r, fn)
			diags = append(diags, stageDiags...)
			if e.diagnosticErr != nil {
				e.diagnostics = diags
				return diags, e.diagnosticErr
			}
		}
	}
	e.diagnostics = diags
	if e.diagnosticErr != nil {
		return diags, e.diagnosticErr
	}
	return diags, nil
}

func (e *Engine) evaluateRule(ctx *Context, baseIdx *ch10.FileIndex, rule Rule, fn FixFunc) []Diagnostic {
	allowFilter := rule.Stage == StageTypeSpecific
	allowParallel := allowFilter && !rule.Fixable && e.concurrency > 1
	if allowParallel && (len(rule.AppliesTo.Channels) > 0 || len(rule.AppliesTo.DataTypes) > 0) {
		filters := buildChannelFilters(baseIdx, rule)
		if len(filters) > 1 {
			return e.evaluateRuleParallel(ctx, baseIdx, rule, fn, filters)
		}
	}
	diag, executed := e.runRuleOnce(ctx, baseIdx, rule, fn, ruleFilter{channels: rule.AppliesTo.Channels, dataTypes: rule.AppliesTo.DataTypes}, allowFilter)
	if !executed || diag.RuleId == "" {
		return nil
	}
	e.emitDiagnostic(diag)
	return []Diagnostic{diag}
}

func (e *Engine) evaluateRuleParallel(ctx *Context, baseIdx *ch10.FileIndex, rule Rule, fn FixFunc, filters []ruleFilter) []Diagnostic {
	workerCount := e.concurrency
	if workerCount > len(filters) {
		workerCount = len(filters)
	}
	if workerCount <= 1 {
		return e.evaluateRule(ctx, baseIdx, rule, fn)
	}
	type result struct {
		diag     Diagnostic
		executed bool
	}
	jobs := make(chan ruleFilter)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filter := range jobs {
				diag, executed := e.runRuleOnce(ctx, baseIdx, rule, fn, filter, true)
				if executed && diag.RuleId != "" {
					results <- result{diag: diag, executed: true}
				}
			}
		}()
	}
	go func() {
		for _, filter := range filters {
			jobs <- filter
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var diags []Diagnostic
	for res := range results {
		if res.executed {
			diags = append(diags, res.diag)
		}
	}
	if len(diags) == 0 {
		return nil
	}
	chosen := chooseBestDiagnostic(diags)
	if chosen == nil {
		return nil
	}
	e.emitDiagnostic(*chosen)
	return []Diagnostic{*chosen}
}

func (e *Engine) emitDiagnostic(diag Diagnostic) {
	if e == nil {
		return
	}
	if diag.RuleId == "" {
		return
	}
	if e.diagnosticCallback == nil {
		return
	}
	if e.diagnosticErr != nil {
		return
	}
	if err := e.diagnosticCallback(diag); err != nil {
		e.diagnosticErr = err
	}
}

func chooseBestDiagnostic(diags []Diagnostic) *Diagnostic {
	if len(diags) == 0 {
		return nil
	}
	rank := func(s Severity) int {
		switch s {
		case ERROR:
			return 3
		case WARN:
			return 2
		case INFO:
			return 1
		default:
			return 0
		}
	}
	var best *Diagnostic
	for i := range diags {
		d := diags[i]
		if best == nil {
			copy := d
			best = &copy
			continue
		}
		br := rank(best.Severity)
		dr := rank(d.Severity)
		if dr > br {
			copy := d
			best = &copy
			continue
		}
		if dr < br {
			continue
		}
		if d.PacketIndex >= 0 && (best.PacketIndex < 0 || d.PacketIndex < best.PacketIndex) {
			copy := d
			best = &copy
			continue
		}
		if d.PacketIndex == best.PacketIndex && d.ChannelId != 0 && (best.ChannelId == 0 || d.ChannelId < best.ChannelId) {
			copy := d
			best = &copy
		}
	}
	return best
}

type ruleFilter struct {
	channels  []uint16
	dataTypes []uint16
}

func (f ruleFilter) empty() bool {
	return len(f.channels) == 0 && len(f.dataTypes) == 0
}

func (f ruleFilter) matches(pkt ch10.PacketIndex) bool {
	if len(f.channels) > 0 {
		matched := false
		for _, ch := range f.channels {
			if pkt.ChannelID == ch {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(f.dataTypes) > 0 {
		matched := false
		for _, dt := range f.dataTypes {
			if pkt.DataType == dt {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (f ruleFilter) apply(base *ch10.FileIndex) (*ch10.FileIndex, []int, bool) {
	if base == nil {
		return nil, nil, false
	}
	if f.empty() {
		return base, nil, len(base.Packets) > 0
	}
	filtered := &ch10.FileIndex{}
	mapping := make([]int, 0, len(base.Packets))
	for idx, pkt := range base.Packets {
		if !f.matches(pkt) {
			continue
		}
		filtered.Packets = append(filtered.Packets, pkt)
		mapping = append(mapping, idx)
		if pkt.IsTimePacket {
			filtered.HasTimePacket = true
		}
		if base.TimeSeenBeforeDynamic {
			filtered.TimeSeenBeforeDynamic = true
		}
	}
	if len(filtered.Packets) == 0 {
		return &ch10.FileIndex{}, nil, false
	}
	return filtered, mapping, true
}

func buildChannelFilters(base *ch10.FileIndex, rule Rule) []ruleFilter {
	if base == nil || len(base.Packets) == 0 {
		return nil
	}
	dtSet := make(map[uint16]struct{})
	for _, dt := range rule.AppliesTo.DataTypes {
		dtSet[dt] = struct{}{}
	}
	chSet := make(map[uint16]struct{})
	for _, ch := range rule.AppliesTo.Channels {
		chSet[ch] = struct{}{}
	}
	matches := make(map[uint16]struct{})
	for _, pkt := range base.Packets {
		if len(dtSet) > 0 {
			if _, ok := dtSet[pkt.DataType]; !ok {
				continue
			}
		}
		if len(chSet) > 0 {
			if _, ok := chSet[pkt.ChannelID]; !ok {
				continue
			}
		}
		matches[pkt.ChannelID] = struct{}{}
	}
	if len(matches) <= 1 {
		return nil
	}
	channels := make([]uint16, 0, len(matches))
	for ch := range matches {
		channels = append(channels, ch)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i] < channels[j] })
	filters := make([]ruleFilter, 0, len(channels))
	for _, ch := range channels {
		filters = append(filters, ruleFilter{
			channels:  []uint16{ch},
			dataTypes: rule.AppliesTo.DataTypes,
		})
	}
	return filters
}

func cloneContext(ctx *Context) *Context {
	if ctx == nil {
		return nil
	}
	dup := *ctx
	return &dup
}

func (e *Engine) runRuleOnce(ctx *Context, baseIdx *ch10.FileIndex, rule Rule, fn FixFunc, filter ruleFilter, allowFilter bool) (Diagnostic, bool) {
	taskCtx := cloneContext(ctx)
	var mapping []int
	if allowFilter {
		idx, mapIdx, _ := filter.apply(baseIdx)
		if idx != nil {
			taskCtx.Index = idx
			mapping = mapIdx
		} else {
			taskCtx.Index = baseIdx
		}
	} else {
		taskCtx.Index = baseIdx
	}
	diag, applied, err := fn(taskCtx, rule)
	if err != nil {
		diag.Severity = ERROR
		if diag.Message == "" {
			diag.Message = err.Error()
		} else {
			diag.Message = fmt.Sprintf("%s (%v)", diag.Message, err)
		}
	}
	diag.FixApplied = applied
	if len(mapping) > 0 && diag.PacketIndex >= 0 && diag.PacketIndex < len(mapping) {
		diag.PacketIndex = mapping[diag.PacketIndex]
	}
	return diag, true
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
	rep.GateMatrix = e.buildGateMatrix()
	rep.Findings = e.diagnostics
	return rep
}

func (e *Engine) buildGateMatrix() []GateResult {
	if e.ruleIndex == nil || e.stageBuckets == nil {
		e.rebuildStageBuckets()
	}
	diagByRule := make(map[string][]Diagnostic)
	for _, d := range e.diagnostics {
		diagByRule[d.RuleId] = append(diagByRule[d.RuleId], d)
	}
	results := make([]GateResult, 0, len(e.rulePack.Rules))
	for _, stage := range stageOrder {
		rules := e.stageBuckets[stage]
		if len(rules) == 0 {
			continue
		}
		for _, r := range rules {
			entry := GateResult{
				RuleId:   r.RuleId,
				Name:     r.Name,
				Stage:    r.Stage,
				Severity: r.Severity,
				Refs:     append([]string(nil), r.Refs...),
				Pass:     true,
			}
			if diags, ok := diagByRule[r.RuleId]; ok {
				entry.Findings = len(diags)
				for _, d := range diags {
					if d.Severity == ERROR || d.Severity == WARN {
						entry.Pass = false
						break
					}
				}
			}
			results = append(results, entry)
		}
	}
	return results
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
