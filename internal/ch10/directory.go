package ch10

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	directoryMagic      = "FORTYtwo"
	directoryHeaderSize = 64
	directoryEntrySize  = 112
)

var (
	// ErrNoDirectory indicates no directory magic was found within the file.
	ErrNoDirectory = errors.New("directory not found")
)

// DirectoryEntry describes a single data file entry stored in a directory block.
type DirectoryEntry struct {
	Name           string
	RawName        [56]byte
	FileStart      uint64
	FileBlockCount uint64
	FileSize       uint64
	CreateDate     [8]byte
	CreateTime     [8]byte
	CloseTime      [8]byte
	TimeType       byte
	Reserved       [7]byte
}

// StartOffset returns the byte offset of the associated data file given the block size.
func (e DirectoryEntry) StartOffset(blockSize uint32) int64 {
	return int64(e.FileStart) * int64(blockSize)
}

// DeclaredSize returns the declared data length for the file. When the stored size is
// absent (all bits set), the reserved block length is returned instead.
func (e DirectoryEntry) DeclaredSize(blockSize uint32) int64 {
	if e.FileSize == ^uint64(0) {
		return int64(e.FileBlockCount) * int64(blockSize)
	}
	return int64(e.FileSize)
}

// DirectoryBlock captures the parsed contents of a directory block.
type DirectoryBlock struct {
	Offset      int64
	BlockIndex  uint64
	Revision    byte
	Shutdown    byte
	NumEntries  uint16
	BlockSize   uint32
	VolumeName  string
	ForwardLink uint64
	ReverseLink uint64
	Entries     []DirectoryEntry
}

// DirectoryImage represents the full directory chain within a transfer or directory
// file. Blocks are ordered according to their forward links.
type DirectoryImage struct {
	Offset    int64
	BlockSize uint32
	Blocks    []DirectoryBlock
}

// TotalBytes returns the length in bytes occupied by the directory blocks.
func (img DirectoryImage) TotalBytes() int64 {
	if img.BlockSize == 0 {
		return 0
	}
	return int64(len(img.Blocks)) * int64(img.BlockSize)
}

// Entries flattens the directory into a single ordered slice of entries.
func (img DirectoryImage) Entries() []DirectoryEntry {
	var out []DirectoryEntry
	for _, blk := range img.Blocks {
		out = append(out, blk.Entries...)
	}
	return out
}

// Marshal serializes the directory blocks into their raw byte representation.
func (img DirectoryImage) Marshal() ([]byte, error) {
	if img.BlockSize < directoryHeaderSize {
		return nil, fmt.Errorf("invalid block size %d", img.BlockSize)
	}
	buf := bytes.NewBuffer(make([]byte, 0, img.TotalBytes()))
	for _, blk := range img.Blocks {
		raw, err := marshalDirectoryBlock(blk, img.BlockSize)
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(raw); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func marshalDirectoryBlock(blk DirectoryBlock, blockSize uint32) ([]byte, error) {
	if blockSize < directoryHeaderSize {
		return nil, fmt.Errorf("block size %d too small", blockSize)
	}
	maxEntries := int((blockSize - directoryHeaderSize) / directoryEntrySize)
	if len(blk.Entries) > maxEntries {
		return nil, fmt.Errorf("block cannot hold %d entries (max %d)", len(blk.Entries), maxEntries)
	}
	buf := make([]byte, blockSize)
	copy(buf[0:8], []byte(directoryMagic))
	buf[8] = blk.Revision
	buf[9] = blk.Shutdown
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(blk.Entries)))
	binary.BigEndian.PutUint32(buf[12:16], blk.BlockSize)
	encodeBCS(buf[16:48], blk.VolumeName)
	binary.BigEndian.PutUint64(buf[48:56], blk.ForwardLink)
	binary.BigEndian.PutUint64(buf[56:64], blk.ReverseLink)
	cursor := directoryHeaderSize
	for _, entry := range blk.Entries {
		if cursor+directoryEntrySize > int(blockSize) {
			return nil, fmt.Errorf("entry spill in block")
		}
		copy(buf[cursor:cursor+56], entry.RawName[:])
		binary.BigEndian.PutUint64(buf[cursor+56:cursor+64], entry.FileStart)
		binary.BigEndian.PutUint64(buf[cursor+64:cursor+72], entry.FileBlockCount)
		binary.BigEndian.PutUint64(buf[cursor+72:cursor+80], entry.FileSize)
		copy(buf[cursor+80:cursor+88], entry.CreateDate[:])
		copy(buf[cursor+88:cursor+96], entry.CreateTime[:])
		buf[cursor+96] = entry.TimeType
		copy(buf[cursor+97:cursor+104], entry.Reserved[:])
		copy(buf[cursor+104:cursor+112], entry.CloseTime[:])
		cursor += directoryEntrySize
	}
	for cursor < int(blockSize) {
		buf[cursor] = 0xFF
		cursor++
	}
	return buf, nil
}

// ReadDirectoryImage parses the directory blocks within the provided path.
func ReadDirectoryImage(path string) (DirectoryImage, error) {
	var img DirectoryImage
	f, err := os.Open(path)
	if err != nil {
		return img, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return img, err
	}
	size := info.Size()

	offset, err := findDirectoryOffset(f, size)
	if err != nil {
		return img, err
	}
	img.Offset = offset

	type blockRef struct {
		offset int64
		index  uint64
	}
	visited := make(map[uint64]bool)
	current := blockRef{offset: offset, index: 0}
	for {
		blk, next, err := parseDirectoryBlock(f, current.offset, size)
		if err != nil {
			return img, err
		}
		if visited[blk.BlockIndex] {
			return img, fmt.Errorf("directory loop detected at block %d", blk.BlockIndex)
		}
		visited[blk.BlockIndex] = true
		if img.BlockSize == 0 {
			img.BlockSize = blk.BlockSize
		} else if img.BlockSize != blk.BlockSize {
			return img, fmt.Errorf("directory block size mismatch: %d vs %d", img.BlockSize, blk.BlockSize)
		}
		img.Blocks = append(img.Blocks, blk)
		if next < 0 {
			break
		}
		current = blockRef{offset: next, index: blk.ForwardLink}
	}
	return img, nil
}

func findDirectoryOffset(f *os.File, size int64) (int64, error) {
	buf := make([]byte, 64*1024)
	var offset int64
	for offset < size {
		toRead := int64(len(buf))
		if remaining := size - offset; remaining < toRead {
			toRead = remaining
		}
		n, err := f.ReadAt(buf[:toRead], offset)
		if n <= 0 {
			if err != nil {
				return 0, err
			}
			break
		}
		idx := bytes.Index(buf[:n], []byte(directoryMagic))
		if idx >= 0 {
			candidate := offset + int64(idx)
			// Ensure there are at least header bytes available.
			if candidate+directoryHeaderSize <= size {
				return candidate, nil
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		offset += int64(n - len(directoryMagic) + 1)
	}
	return 0, ErrNoDirectory
}

func parseDirectoryBlock(f *os.File, offset int64, size int64) (DirectoryBlock, int64, error) {
	var blk DirectoryBlock
	header := make([]byte, directoryHeaderSize)
	if _, err := f.ReadAt(header, offset); err != nil {
		return blk, -1, err
	}
	if string(header[0:8]) != directoryMagic {
		return blk, -1, fmt.Errorf("invalid directory magic at offset %d", offset)
	}
	blk.Offset = offset
	blk.Revision = header[8]
	blk.Shutdown = header[9]
	blk.NumEntries = binary.BigEndian.Uint16(header[10:12])
	blk.BlockSize = binary.BigEndian.Uint32(header[12:16])
	blk.VolumeName = decodeBCS(header[16:48])
	blk.ForwardLink = binary.BigEndian.Uint64(header[48:56])
	blk.ReverseLink = binary.BigEndian.Uint64(header[56:64])
	if blk.BlockSize < directoryHeaderSize {
		return blk, -1, fmt.Errorf("directory block size %d too small", blk.BlockSize)
	}
	blockBuf := make([]byte, blk.BlockSize)
	if _, err := f.ReadAt(blockBuf, offset); err != nil {
		return blk, -1, err
	}
	blk.BlockIndex = uint64((offset - offset%int64(blk.BlockSize)) / int64(blk.BlockSize))
	maxEntries := int((blk.BlockSize - directoryHeaderSize) / directoryEntrySize)
	if int(blk.NumEntries) > maxEntries {
		return blk, -1, fmt.Errorf("declared entries %d exceed capacity %d", blk.NumEntries, maxEntries)
	}
	cursor := directoryHeaderSize
	blk.Entries = make([]DirectoryEntry, 0, blk.NumEntries)
	for i := 0; i < int(blk.NumEntries); i++ {
		if cursor+directoryEntrySize > len(blockBuf) {
			return blk, -1, fmt.Errorf("directory entry overrun")
		}
		var entry DirectoryEntry
		copy(entry.RawName[:], blockBuf[cursor:cursor+56])
		entry.Name = decodeBCS(entry.RawName[:])
		entry.FileStart = binary.BigEndian.Uint64(blockBuf[cursor+56 : cursor+64])
		entry.FileBlockCount = binary.BigEndian.Uint64(blockBuf[cursor+64 : cursor+72])
		entry.FileSize = binary.BigEndian.Uint64(blockBuf[cursor+72 : cursor+80])
		copy(entry.CreateDate[:], blockBuf[cursor+80:cursor+88])
		copy(entry.CreateTime[:], blockBuf[cursor+88:cursor+96])
		entry.TimeType = blockBuf[cursor+96]
		copy(entry.Reserved[:], blockBuf[cursor+97:cursor+104])
		copy(entry.CloseTime[:], blockBuf[cursor+104:cursor+112])
		blk.Entries = append(blk.Entries, entry)
		cursor += directoryEntrySize
	}
	if blk.ForwardLink == blk.BlockIndex {
		return blk, -1, nil
	}
	nextOffset := int64(blk.ForwardLink) * int64(blk.BlockSize)
	if nextOffset < 0 || nextOffset+int64(blk.BlockSize) > size {
		return blk, -1, fmt.Errorf("forward link 0x%X out of range", nextOffset)
	}
	return blk, nextOffset, nil
}

// ValidateDirectory verifies the integrity of a parsed directory image.
func ValidateDirectory(img DirectoryImage, fileSize int64) error {
	if img.BlockSize == 0 {
		return errors.New("directory block size unspecified")
	}
	if len(img.Blocks) == 0 {
		return errors.New("no directory blocks found")
	}
	entriesPerBlock := int((img.BlockSize - directoryHeaderSize) / directoryEntrySize)
	if entriesPerBlock <= 0 {
		return errors.New("directory block too small for entries")
	}
	for i := range img.Blocks {
		blk := img.Blocks[i]
		if len(blk.Entries) != int(blk.NumEntries) {
			return fmt.Errorf("block %d declared %d entries but parsed %d", blk.BlockIndex, blk.NumEntries, len(blk.Entries))
		}
		if blk.NumEntries > uint16(entriesPerBlock) {
			return fmt.Errorf("block %d exceeds entry capacity", blk.BlockIndex)
		}
		if i == 0 {
			if blk.ReverseLink != blk.BlockIndex {
				return fmt.Errorf("block %d reverse link mismatch", blk.BlockIndex)
			}
		} else {
			prev := img.Blocks[i-1]
			if blk.ReverseLink != prev.BlockIndex {
				return fmt.Errorf("block %d reverse link %d != %d", blk.BlockIndex, blk.ReverseLink, prev.BlockIndex)
			}
			if prev.ForwardLink != blk.BlockIndex {
				return fmt.Errorf("block %d forward link %d != %d", prev.BlockIndex, prev.ForwardLink, blk.BlockIndex)
			}
		}
		if i == len(img.Blocks)-1 {
			if blk.ForwardLink != blk.BlockIndex {
				return fmt.Errorf("terminal block %d forward link %d invalid", blk.BlockIndex, blk.ForwardLink)
			}
		}
	}

	dirBytes := img.TotalBytes()
	for _, entry := range img.Entries() {
		if entry.FileBlockCount == 0 {
			continue
		}
		if err := validateBCSName(entry.Name); err != nil {
			return fmt.Errorf("entry %q: %w", entry.Name, err)
		}
		start := entry.StartOffset(img.BlockSize)
		if start < dirBytes {
			return fmt.Errorf("entry %q start offset %d overlaps directory", entry.Name, start)
		}
		reserved := int64(entry.FileBlockCount) * int64(img.BlockSize)
		if start+reserved > fileSize {
			return fmt.Errorf("entry %q extends beyond file", entry.Name)
		}
	}
	return nil
}

func validateBCSName(name string) error {
	if name == "" {
		return errors.New("empty name")
	}
	if strings.HasPrefix(name, ".") {
		return errors.New("leading period not allowed")
	}
	if strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ") {
		return errors.New("leading or trailing space")
	}
	for _, r := range name {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("invalid character 0x%X", r)
		}
		if isForbiddenBCSRune(r) {
			return fmt.Errorf("character %q not allowed", r)
		}
	}
	return nil
}

func isForbiddenBCSRune(r rune) bool {
	switch r {
	case '"', '\'', '*', '/', ':', ';', '<', '=', '>', '?', '\\', ']', '[', '|':
		return true
	default:
		return false
	}
}

// DirectoryBuildEntry describes a file to include while rebuilding the directory.
type DirectoryBuildEntry struct {
	Name        string
	StartOffset int64
	Size        int64
	Template    *DirectoryEntry
}

// DirectoryBuildPlan collects parameters required to rebuild a directory.
type DirectoryBuildPlan struct {
	BlockSize  uint32
	Revision   byte
	Shutdown   byte
	VolumeName string
	Entries    []DirectoryBuildEntry
}

// BuildDirectory constructs a directory image satisfying the provided plan. The dataOffset
// specifies the byte position of the first data byte following the directory blocks.
func BuildDirectory(plan DirectoryBuildPlan, dataOffset int64) (DirectoryImage, error) {
	var img DirectoryImage
	if plan.BlockSize < directoryHeaderSize {
		return img, fmt.Errorf("block size %d too small", plan.BlockSize)
	}
	if dataOffset <= 0 {
		return img, fmt.Errorf("invalid data offset %d", dataOffset)
	}
	if dataOffset%int64(plan.BlockSize) != 0 {
		return img, fmt.Errorf("data offset %d not aligned to block size %d", dataOffset, plan.BlockSize)
	}
	entriesPerBlock := int((plan.BlockSize - directoryHeaderSize) / directoryEntrySize)
	if entriesPerBlock <= 0 {
		return img, fmt.Errorf("block size %d cannot hold any entries", plan.BlockSize)
	}
	blockCount := int(dataOffset / int64(plan.BlockSize))
	if blockCount <= 0 {
		return img, fmt.Errorf("data offset %d too small for block size %d", dataOffset, plan.BlockSize)
	}
	if entriesPerBlock*blockCount < len(plan.Entries) {
		return img, fmt.Errorf("directory capacity insufficient for %d entries", len(plan.Entries))
	}

	img.BlockSize = plan.BlockSize
	img.Blocks = make([]DirectoryBlock, blockCount)
	for i := range img.Blocks {
		blk := &img.Blocks[i]
		blk.BlockSize = plan.BlockSize
		blk.BlockIndex = uint64(i)
		blk.Offset = int64(i) * int64(plan.BlockSize)
		blk.Revision = plan.Revision
		blk.Shutdown = plan.Shutdown
		blk.VolumeName = plan.VolumeName
		if i == blockCount-1 {
			blk.ForwardLink = uint64(i)
		} else {
			blk.ForwardLink = uint64(i + 1)
		}
		if i == 0 {
			blk.ReverseLink = uint64(i)
		} else {
			blk.ReverseLink = uint64(i - 1)
		}
	}

	// Assign entries sequentially across blocks.
	entryIdx := 0
	for i := range img.Blocks {
		blk := &img.Blocks[i]
		capacity := entriesPerBlock
		if entryIdx < len(plan.Entries) {
			remaining := len(plan.Entries) - entryIdx
			if remaining < capacity {
				capacity = remaining
			}
			blk.Entries = make([]DirectoryEntry, 0, capacity)
			for j := 0; j < capacity; j++ {
				src := plan.Entries[entryIdx]
				entryIdx++
				dirEntry, err := buildDirectoryEntry(src, plan.BlockSize)
				if err != nil {
					return img, err
				}
				blk.Entries = append(blk.Entries, dirEntry)
			}
			blk.NumEntries = uint16(len(blk.Entries))
		}
	}
	return img, nil
}

func buildDirectoryEntry(src DirectoryBuildEntry, blockSize uint32) (DirectoryEntry, error) {
	var entry DirectoryEntry
	if src.Size < 0 {
		return entry, fmt.Errorf("negative size for %q", src.Name)
	}
	if src.StartOffset < 0 {
		return entry, fmt.Errorf("negative offset for %q", src.Name)
	}
	start := src.StartOffset / int64(blockSize)
	if src.StartOffset%int64(blockSize) != 0 {
		return entry, fmt.Errorf("offset %d not aligned to block size %d", src.StartOffset, blockSize)
	}
	blocks := uint64((src.Size + int64(blockSize) - 1) / int64(blockSize))
	if blocks == 0 {
		blocks = 1
	}
	sanitized := sanitizeName(src.Name, len(entry.RawName))
	if !strings.HasSuffix(strings.ToLower(sanitized), ".ch10") {
		if len(sanitized)+5 <= len(entry.RawName) {
			sanitized += ".ch10"
		}
	}
	encodeBCS(entry.RawName[:], sanitized)
	entry.Name = decodeBCS(entry.RawName[:])
	entry.FileStart = uint64(start)
	entry.FileBlockCount = blocks
	entry.FileSize = uint64(src.Size)
	fillDashes(entry.CreateDate[:])
	fillDashes(entry.CreateTime[:])
	fillDashes(entry.CloseTime[:])
	for i := range entry.Reserved {
		entry.Reserved[i] = 0xFF
	}
	entry.TimeType = 0xFF
	if src.Template != nil {
		entry.TimeType = src.Template.TimeType
		entry.FileSize = src.Template.FileSize
		entry.FileBlockCount = src.Template.FileBlockCount
		entry.FileStart = src.Template.FileStart
		entry.CreateDate = src.Template.CreateDate
		entry.CreateTime = src.Template.CreateTime
		entry.CloseTime = src.Template.CloseTime
		entry.Reserved = src.Template.Reserved
		if src.Template.FileSize == ^uint64(0) {
			entry.FileSize = uint64(src.Size)
		}
		if entry.FileBlockCount == 0 {
			entry.FileBlockCount = blocks
		}
		if entry.FileStart == 0 {
			entry.FileStart = uint64(start)
		}
		if sanitized != "" {
			encodeBCS(entry.RawName[:], sanitized)
			entry.Name = decodeBCS(entry.RawName[:])
		}
	}
	return entry, nil
}

func fillDashes(dst []byte) {
	for i := range dst {
		dst[i] = 0x2D
	}
}

// FindFirstPacketOffset scans for the first Chapter 10 packet header within the file.
func FindFirstPacketOffset(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	if size < primaryHeaderSize {
		return 0, io.EOF
	}
	buf := make([]byte, 256*1024)
	var offset int64
	for offset < size {
		toRead := int64(len(buf))
		if remain := size - offset; remain < toRead {
			toRead = remain
		}
		n, err := f.ReadAt(buf[:toRead], offset)
		if n <= 0 {
			if err != nil {
				return 0, err
			}
			break
		}
		limit := n - primaryHeaderSize
		if limit < 0 {
			limit = 0
		}
		for i := 0; i <= limit; i++ {
			if buf[i] != 0xEB || buf[i+1] != 0x25 {
				continue
			}
			candidate := offset + int64(i)
			header := make([]byte, primaryHeaderSize)
			if _, err := f.ReadAt(header, candidate); err != nil {
				continue
			}
			if _, err := ParsePrimaryHeader(header); err == nil {
				return candidate, nil
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		offset += int64(n - primaryHeaderSize + 1)
	}
	return 0, errors.New("no chapter 10 packets found")
}

// BuildDirectoryPlanFromImage constructs a build plan using entries derived from
// the provided directory image. The returned plan attempts to preserve entry
// metadata while sanitizing names.
func BuildDirectoryPlanFromImage(img DirectoryImage, fileSize int64) DirectoryBuildPlan {
	plan := DirectoryBuildPlan{
		BlockSize:  img.BlockSize,
		Revision:   0x0F,
		Shutdown:   0xFF,
		VolumeName: sanitizeVolumeName(img.Blocks[0].VolumeName),
	}
	if len(img.Blocks) > 0 {
		plan.Revision = img.Blocks[0].Revision
		if plan.Revision == 0 {
			plan.Revision = 0x0F
		}
		if img.Blocks[0].Shutdown != 0 {
			plan.Shutdown = img.Blocks[0].Shutdown
		}
	}
	entries := img.Entries()
	type fileInfo struct {
		entry DirectoryEntry
		start int64
	}
	var files []fileInfo
	for _, e := range entries {
		if e.FileBlockCount == 0 {
			continue
		}
		start := e.StartOffset(img.BlockSize)
		files = append(files, fileInfo{entry: e, start: start})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].start < files[j].start })
	for i := range files {
		start := files[i].start
		var size int64
		if i+1 < len(files) {
			size = files[i+1].start - start
		} else {
			size = fileSize - start
		}
		if size < 0 {
			size = 0
		}
		plan.Entries = append(plan.Entries, DirectoryBuildEntry{
			Name:        files[i].entry.Name,
			StartOffset: start,
			Size:        size,
			Template:    &files[i].entry,
		})
	}
	return plan
}

func sanitizeName(name string, maxLen int) string {
	name = strings.TrimSpace(name)
	name = strings.TrimLeft(name, ".")
	if name == "" {
		name = "DATA"
	}
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7E {
			continue
		}
		if isForbiddenBCSRune(r) {
			b.WriteRune('_')
			continue
		}
		b.WriteRune(r)
	}
	sanitized := b.String()
	if sanitized == "" {
		sanitized = "DATA"
	}
	if len(sanitized) > maxLen {
		sanitized = truncateWithExtension(sanitized, maxLen)
	}
	return sanitized
}

func sanitizeVolumeName(name string) string {
	sanitized := sanitizeName(name, 32)
	if len(sanitized) > 0 {
		return sanitized
	}
	return "VOLUME"
}

func truncateWithExtension(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return name[:maxLen]
	}
	ext := name[dot:]
	base := name[:dot]
	if len(ext) >= maxLen {
		return name[:maxLen]
	}
	keep := maxLen - len(ext)
	if len(base) > keep {
		base = base[:keep]
	}
	return base + ext
}

func encodeBCS(dst []byte, value string) {
	for i := range dst {
		dst[i] = 0
	}
	value = strings.TrimSpace(value)
	copy(dst, []byte(value))
}

func decodeBCS(buf []byte) string {
	end := len(buf)
	for i, b := range buf {
		if b == 0 {
			end = i
			break
		}
	}
	return strings.TrimSpace(string(buf[:end]))
}

// SelectBlockSize attempts to choose a sensible block size given an observed data offset.
func SelectBlockSize(offset int64) uint32 {
	candidates := []int64{4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1}
	for _, c := range candidates {
		if c <= 0 {
			continue
		}
		if offset%c == 0 {
			return uint32(c)
		}
	}
	if offset <= 0 {
		return 512
	}
	if offset > int64(^uint32(0)) {
		return 512
	}
	return uint32(offset)
}

// DeriveDataOffset determines the minimal start offset among entries.
func DeriveDataOffset(img DirectoryImage) int64 {
	entries := img.Entries()
	min := int64(-1)
	for _, e := range entries {
		if e.FileBlockCount == 0 {
			continue
		}
		off := e.StartOffset(img.BlockSize)
		if min < 0 || off < min {
			min = off
		}
	}
	if min < 0 {
		return img.TotalBytes()
	}
	return min
}

// BaseNameFromPath returns a sanitized base name for directory entries derived from
// the input path.
func BaseNameFromPath(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		base = "DATA"
	}
	return sanitizeName(base, 32)
}
