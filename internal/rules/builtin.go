package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/tmats"
)

func (e *Engine) RegisterBuiltins() {
	e.Register("CheckSyncPattern", CheckSyncPattern)
	e.Register("FixHeaderChecksum", FixHeaderChecksum)
	e.Register("FixDataChecksumOrTrailer", FixDataChecksumOrTrailer)
	e.Register("SyncSecondaryHeaderFlag", SyncSecondaryHeaderFlag)
	e.Register("FixLengths", FixLengths)
	e.Register("RemapChannelIds", RemapChannelIds)
	e.Register("RenumberSeq", RenumberSeq)
	e.Register("BlockUnknownDataType", BlockUnknownDataType)
	e.Register("EnsureTimePacket", EnsureTimePacket)
	e.Register("FixPCMAlign", FixPCMAlign)
	e.Register("Check1553IpdhLen", Check1553IpdhLen)
	e.Register("Warn1553Ttb", Warn1553Ttb)
	e.Register("FixA429Gap", FixA429Gap)
	e.Register("WarnA429Parity", WarnA429Parity)
	e.Register("AddEthIPH", AddEthIPH)
	e.Register("FixA664Lens", FixA664Lens)
	e.Register("UpdateTMATSDigest", UpdateTMATSDigest)
	e.Register("NormalizeTMATSChannelMap", NormalizeTMATSChannelMap)
	e.Register("SyncSecondaryTimeFmt", SyncSecondaryTimeFmt)
	e.Register("FixFileExtension", FixFileExtension)
}

func CheckSyncPattern(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	hdr, _, err := ch10.ScanFileMin(ctx.InputFile)
	if err != nil {
		return Diagnostic{
			Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR,
			Message: "cannot parse first header", Refs: rule.Refs, FixSuggested: false,
		}, false, err
	}
	if hdr.Sync != 0xEB25 {
		return Diagnostic{
			Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR,
			Message: "sync pattern not 0xEB25", Refs: rule.Refs, FixSuggested: false,
		}, false, nil
	}
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "sync pattern ok", Refs: rule.Refs, FixSuggested: false,
	}, false, nil
}

func FixHeaderChecksum(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN,
		Message: "header checksum check/fix not implemented yet", Refs: rule.Refs, FixSuggested: false,
	}, false, ErrNotImplemented
}

func FixDataChecksumOrTrailer(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN,
		Message: "data checksum fix not implemented yet", Refs: rule.Refs,
	}, false, ErrNotImplemented
}

func SyncSecondaryHeaderFlag(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "secondary header flag sync skipped (not implemented)", Refs: rule.Refs,
	}, false, nil
}

func FixLengths(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN,
		Message: "packet/data length recompute not implemented yet", Refs: rule.Refs,
	}, false, ErrNotImplemented
}

func RemapChannelIds(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN,
		Message: "channel id remap not implemented yet", Refs: rule.Refs,
	}, false, ErrNotImplemented
}

func RenumberSeq(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{
		Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO,
		Message: "sequence renumber planned", Refs: rule.Refs,
	}, false, nil
}

func BlockUnknownDataType(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	hdr, _, err := ch10.ScanFileMin(ctx.InputFile)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot parse", Refs: rule.Refs}, false, err
	}
	if hdr.DataType > 0x80 {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: fmt.Sprintf("unknown data type 0x%X", hdr.DataType), Refs: rule.Refs}, false, nil
	}
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "data type within provisional range", Refs: rule.Refs}, false, nil
}

func EnsureTimePacket(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "time packet check deferred (iteration not implemented)", Refs: rule.Refs}, false, nil
}

func FixPCMAlign(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "PCM alignment fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func Check1553IpdhLen(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "1553 IPDH len check deferred", Refs: rule.Refs}, false, nil
}

func Warn1553Ttb(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "TTB warning (placeholder)", Refs: rule.Refs}, false, nil
}

func FixA429Gap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "ARINC-429 gap fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func WarnA429Parity(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "ARINC-429 parity flagged (placeholder)", Refs: rule.Refs}, false, nil
}

func AddEthIPH(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "Ethernet IPH add not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func FixA664Lens(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "A664 length fix not implemented", Refs: rule.Refs}, false, ErrNotImplemented
}

func UpdateTMATSDigest(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	if ctx.TMATSFile == "" {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: WARN, Message: "no TMATS provided", Refs: rule.Refs}, false, nil
	}
	t, err := tmats.Parse(ctx.TMATSFile)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "TMATS parse failed", Refs: rule.Refs}, false, err
	}
	d, err := tmats.ComputeDigest(t)
	if err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "digest compute failed", Refs: rule.Refs}, false, err
	}
	out := tmats.WithDigest(t, d)
	outPath := ctx.TMATSFile + ".fixed"
	if err := os.WriteFile(outPath, []byte(out), 0644); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot write fixed TMATS", Refs: rule.Refs}, false, err
	}
	return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS digest updated, wrote " + filepath.Base(outPath), Refs: rule.Refs, FixSuggested: true}, true, nil
}

func NormalizeTMATSChannelMap(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.TMATSFile, RuleId: rule.RuleId, Severity: INFO, Message: "TMATS channel map normalization deferred", Refs: rule.Refs}, false, nil
}

func SyncSecondaryTimeFmt(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "secondary time format sync deferred", Refs: rule.Refs}, false, nil
}

func FixFileExtension(ctx *Context, rule Rule) (Diagnostic, bool, error) {
	ext := filepath.Ext(ctx.InputFile)
	if ext == ".ch10" || ext == ".tf10" || ext == ".df10" {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "extension ok", Refs: rule.Refs}, false, nil
	}
	newPath := ctx.InputFile + ".ch10"
	if err := copyFile(ctx.InputFile, newPath); err != nil {
		return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: ERROR, Message: "cannot copy with .ch10", Refs: rule.Refs}, false, err
	}
	return Diagnostic{Ts: time.Now(), File: ctx.InputFile, RuleId: rule.RuleId, Severity: INFO, Message: "copied to " + filepath.Base(newPath), Refs: rule.Refs, FixSuggested: true}, true, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1024*1024)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}
