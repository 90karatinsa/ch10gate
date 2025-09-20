package samples

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/tmats"
)

const (
	profile10615        = "106-15"
	primaryHeaderSize   = 20
	secondaryHeaderSize = 12
	secondaryTimeBytes  = 8
	timeFormatIRIG106   = 0x00

	baseTimestampUs      int64  = 123_456_789
	iptsOffsetUs         uint64 = 2_500
	secondaryTimestampUs int64  = baseTimestampUs + 25_000

	// File names exposed for generator consumers.
	Chapter10FileName = "sample.ch10"
	TMATSFileName     = "sample.tmats"
)

const (
	// Exported constants simplify tests and documentation when referencing
	// the deterministic timestamps embedded in the sample capture.
	BaseTimestampUS      int64  = baseTimestampUs
	IPTSOffsetUS         uint64 = iptsOffsetUs
	SecondaryTimestampUS int64  = secondaryTimestampUs
)

// BuildChapter10 constructs the deterministic Chapter 10 sample capture.
func BuildChapter10() ([]byte, error) {
	timePacket, err := ch10.BuildTimePacket(profile10615, 1, timeFormatIRIG106, baseTimestampUs)
	if err != nil {
		return nil, fmt.Errorf("build time packet: %w", err)
	}

	iptsPayload := make([]byte, 8)
	binary.BigEndian.PutUint64(iptsPayload, iptsOffsetUs)
	dynamicPacket, err := buildDataPacket(profile10615, 2, 0x08, 1, 0x00, nil, iptsPayload)
	if err != nil {
		return nil, fmt.Errorf("build ipts packet: %w", err)
	}

	secHdr, err := buildSecondaryHeader(profile10615, timeFormatIRIG106, secondaryTimestampUs)
	if err != nil {
		return nil, fmt.Errorf("build secondary header: %w", err)
	}
	secondaryPacket, err := buildDataPacket(profile10615, 3, 0x08, 2, 0x80|timeFormatIRIG106, secHdr, []byte{0xAA, 0x55, 0xAA, 0x55})
	if err != nil {
		return nil, fmt.Errorf("build secondary packet: %w", err)
	}

	capture := make([]byte, 0, len(timePacket)+len(dynamicPacket)+len(secondaryPacket))
	capture = append(capture, timePacket...)
	capture = append(capture, dynamicPacket...)
	capture = append(capture, secondaryPacket...)
	return capture, nil
}

func buildDataPacket(profile string, channelID uint16, dataType uint16, seq uint8, flags uint8, secondary, payload []byte) ([]byte, error) {
	totalLen := primaryHeaderSize + len(secondary) + len(payload)
	header := make([]byte, primaryHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], 0xEB25)
	binary.BigEndian.PutUint16(header[2:4], channelID)
	binary.BigEndian.PutUint32(header[4:8], uint32(totalLen-4))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(secondary)+len(payload)))
	binary.BigEndian.PutUint16(header[12:14], dataType)
	header[14] = seq
	header[15] = flags
	checksum, err := ch10.ComputeHeaderChecksum(profile, header)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(header[16:18], checksum)

	packet := make([]byte, totalLen)
	copy(packet, header)
	offset := primaryHeaderSize
	if len(secondary) > 0 {
		if len(secondary) != secondaryHeaderSize {
			return nil, fmt.Errorf("secondary header len %d, want %d", len(secondary), secondaryHeaderSize)
		}
		copy(packet[offset:], secondary)
		offset += len(secondary)
	}
	if len(payload) > 0 {
		copy(packet[offset:], payload)
	}
	return packet, nil
}

func buildSecondaryHeader(profile string, timeFormat uint8, timestampUs int64) ([]byte, error) {
	timeField, err := encodeTimeField(profile, timeFormat, timestampUs)
	if err != nil {
		return nil, err
	}
	secondary := make([]byte, secondaryHeaderSize)
	copy(secondary, timeField)
	// Time source / date fields remain zero for a minimal example.
	// The final two bytes store the checksum across the preceding words.
	checksum := computeSecondaryHeaderChecksum(secondary)
	binary.BigEndian.PutUint16(secondary[secondaryHeaderSize-2:], checksum)
	return secondary, nil
}

func encodeTimeField(profile string, timeFormat uint8, timestampUs int64) ([]byte, error) {
	packet, err := ch10.BuildTimePacket(profile, 0, timeFormat, timestampUs)
	if err != nil {
		return nil, err
	}
	if len(packet) < primaryHeaderSize+secondaryTimeBytes {
		return nil, fmt.Errorf("time packet shorter than expected: %d", len(packet))
	}
	field := make([]byte, secondaryTimeBytes)
	copy(field, packet[primaryHeaderSize:primaryHeaderSize+secondaryTimeBytes])
	return field, nil
}

func computeSecondaryHeaderChecksum(sec []byte) uint16 {
	if len(sec) < 2 {
		return 0
	}
	var sum uint32
	limit := len(sec) - 2
	for i := 0; i < limit; i += 2 {
		word := binary.BigEndian.Uint16(sec[i : i+2])
		sum += uint32(word)
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum & 0xFFFF)
}

// BuildTMATS constructs the matching TMATS document and applies its digest.
func BuildTMATS() ([]byte, error) {
	var builder strings.Builder
	for _, line := range tmatsLines() {
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	docWithoutDigest := builder.String()
	digest, err := tmats.ComputeDigest(docWithoutDigest)
	if err != nil {
		return nil, fmt.Errorf("compute digest: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(docWithoutDigest)
	buf.WriteString(fmt.Sprintf("G\\SHA:%s;\n", digest))
	return buf.Bytes(), nil
}

func tmatsLines() []string {
	return []string{
		"# CH10 Gate sample TMATS (generated)",
		"# Regenerate with `go generate ./examples`",
		"G\\DSI:ch10gate deterministic sample;",
		"G\\DSF:examples/cmd/generate_samples;",
		"R-1\\ID:Gate Bundle Demo;",
		"R-1\\NOF:3;",
		"R-1\\CHE-1:1;",
		"R-1\\CDT-1:TIME;",
		"R-1\\DSI-1:Primary time reference;",
		"R-1\\CHE-2:2;",
		"R-1\\CDT-2:PCM;",
		fmt.Sprintf("R-1\\DSI-2:IPTS payload (%d us);", iptsOffsetUs),
		"R-1\\CHE-3:3;",
		"R-1\\CDT-3:PCM;",
		"R-1\\DSI-3:Secondary header timestamp;",
	}
}

// WriteFiles materializes the generated assets under dir.
func WriteFiles(dir string) error {
	ch10Data, err := BuildChapter10()
	if err != nil {
		return err
	}
	tmatsData, err := BuildTMATS()
	if err != nil {
		return err
	}

	if err := writeFileIfChanged(filepath.Join(dir, Chapter10FileName), ch10Data); err != nil {
		return err
	}
	if err := writeFileIfChanged(filepath.Join(dir, TMATSFileName), tmatsData); err != nil {
		return err
	}
	return nil
}

func writeFileIfChanged(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, data) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
