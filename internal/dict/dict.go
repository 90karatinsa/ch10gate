package dict

import (
	"fmt"
	"strings"
)

type A429Entry struct {
	Label uint8
	SDI   uint8
	Name  string
}

type MIL1553Entry struct {
	RT        uint8
	SA        uint8
	Name      string
	WordCount *int
	ModeCode  *int
}

type Store struct {
	a429 map[a429Key]A429Entry
	mil  map[milKey]MIL1553Entry
}

type a429Key struct {
	label uint8
	sdi   uint8
}

type milKey struct {
	rt uint8
	sa uint8
}

type JSONFile struct {
	A429    []JSONA429Entry    `json:"a429"`
	MIL1553 []JSONMIL1553Entry `json:"mil1553"`
}

type JSONA429Entry struct {
	Label int    `json:"label"`
	SDI   int    `json:"sdi"`
	Name  string `json:"name"`
}

type JSONMIL1553Entry struct {
	RT        int    `json:"rt"`
	SA        int    `json:"sa"`
	WordCount *int   `json:"wc,omitempty"`
	ModeCode  *int   `json:"modeCode,omitempty"`
	Name      string `json:"name"`
}

func FromJSON(file JSONFile) (*Store, error) {
	store := &Store{
		a429: make(map[a429Key]A429Entry),
		mil:  make(map[milKey]MIL1553Entry),
	}
	for i, entry := range file.A429 {
		if entry.Label < 0 || entry.Label > 0xFF {
			return nil, fmt.Errorf("a429[%d]: label out of range", i)
		}
		if entry.SDI < 0 || entry.SDI > 0x3 {
			return nil, fmt.Errorf("a429[%d]: sdi out of range", i)
		}
		key := a429Key{label: uint8(entry.Label), sdi: uint8(entry.SDI)}
		if _, exists := store.a429[key]; exists {
			return nil, fmt.Errorf("a429[%d]: duplicate label/sdi", i)
		}
		store.a429[key] = A429Entry{
			Label: key.label,
			SDI:   key.sdi,
			Name:  strings.TrimSpace(entry.Name),
		}
	}
	for i, entry := range file.MIL1553 {
		if entry.RT < 0 || entry.RT > 0x1F {
			return nil, fmt.Errorf("mil1553[%d]: rt out of range", i)
		}
		if entry.SA < 0 || entry.SA > 0x1F {
			return nil, fmt.Errorf("mil1553[%d]: sa out of range", i)
		}
		if entry.WordCount != nil {
			if *entry.WordCount < 0 || *entry.WordCount > 32 {
				return nil, fmt.Errorf("mil1553[%d]: wc out of range", i)
			}
		}
		if entry.ModeCode != nil {
			if *entry.ModeCode < 0 || *entry.ModeCode > 0x1F {
				return nil, fmt.Errorf("mil1553[%d]: mode code out of range", i)
			}
		}
		key := milKey{rt: uint8(entry.RT), sa: uint8(entry.SA)}
		if _, exists := store.mil[key]; exists {
			return nil, fmt.Errorf("mil1553[%d]: duplicate rt/sa", i)
		}
		store.mil[key] = MIL1553Entry{
			RT:        key.rt,
			SA:        key.sa,
			Name:      strings.TrimSpace(entry.Name),
			WordCount: entry.WordCount,
			ModeCode:  entry.ModeCode,
		}
	}
	return store, nil
}

func (s *Store) LookupA429(label uint8, sdi uint8) (A429Entry, bool) {
	if s == nil {
		return A429Entry{}, false
	}
	entry, ok := s.a429[a429Key{label: label, sdi: sdi}]
	return entry, ok
}

func (s *Store) LookupMIL1553(rt uint8, sa uint8) (MIL1553Entry, bool) {
	if s == nil {
		return MIL1553Entry{}, false
	}
	entry, ok := s.mil[milKey{rt: rt, sa: sa}]
	return entry, ok
}

func (s *Store) IsEmpty() bool {
	if s == nil {
		return true
	}
	return len(s.a429) == 0 && len(s.mil) == 0
}

func (e MIL1553Entry) WordCountValue() (int, bool) {
	if e.WordCount == nil {
		return 0, false
	}
	return *e.WordCount, true
}

func (e MIL1553Entry) ModeCodeValue() (int, bool) {
	if e.ModeCode == nil {
		return 0, false
	}
	return *e.ModeCode, true
}
