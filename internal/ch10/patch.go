package ch10

import (
	"fmt"
	"io"
	"os"
	"sort"
)

// PatchEdit represents an in-place modification to a Chapter 10 file.
type PatchEdit struct {
	Offset int64
	Data   []byte
}

// ApplyPatch applies the provided edits to path. Each edit must stay within the
// bounds of the file and does not change its length.
func ApplyPatch(path string, edits []PatchEdit) error {
	if len(edits) == 0 {
		return nil
	}
	// Make a defensive copy so callers can reuse the slice after return.
	ordered := make([]PatchEdit, 0, len(edits))
	for _, e := range edits {
		if len(e.Data) == 0 {
			continue
		}
		buf := make([]byte, len(e.Data))
		copy(buf, e.Data)
		ordered = append(ordered, PatchEdit{Offset: e.Offset, Data: buf})
	}
	if len(ordered) == 0 {
		return nil
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Offset < ordered[j].Offset
	})

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	for _, edit := range ordered {
		if edit.Offset < 0 {
			return fmt.Errorf("negative patch offset %d", edit.Offset)
		}
		end := edit.Offset + int64(len(edit.Data))
		if end > size {
			return fmt.Errorf("patch at %d with length %d exceeds file size %d", edit.Offset, len(edit.Data), size)
		}
		if _, err := f.Seek(edit.Offset, io.SeekStart); err != nil {
			return err
		}
		written := 0
		for written < len(edit.Data) {
			n, err := f.Write(edit.Data[written:])
			if err != nil {
				return err
			}
			written += n
		}
	}
	return f.Sync()
}
