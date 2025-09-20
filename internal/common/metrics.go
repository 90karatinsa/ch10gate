package common

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

type Metrics struct {
	mu         sync.Mutex
	start      time.Time
	end        time.Time
	bytes      int64
	totalBytes int64
	packets    int64
	resyncs    int64
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

func (m *Metrics) Start() {
	m.mu.Lock()
	if m.start.IsZero() {
		m.start = time.Now()
		m.end = time.Time{}
	}
	m.mu.Unlock()
}

func (m *Metrics) Stop() {
	m.mu.Lock()
	if !m.start.IsZero() && m.end.IsZero() {
		m.end = time.Now()
	}
	m.mu.Unlock()
}

func (m *Metrics) AddPacket(size int64) {
	if size <= 0 {
		return
	}
	m.mu.Lock()
	m.bytes += size
	m.packets++
	m.mu.Unlock()
}

func (m *Metrics) AddBytes(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.bytes += n
	m.mu.Unlock()
}

func (m *Metrics) IncResync() {
	m.mu.Lock()
	m.resyncs++
	m.mu.Unlock()
}

func (m *Metrics) SetTotalBytes(total int64) {
	if total < 0 {
		total = 0
	}
	m.mu.Lock()
	m.totalBytes = total
	m.mu.Unlock()
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MetricsSnapshot{
		Duration:   m.elapsedLocked(),
		Bytes:      m.bytes,
		TotalBytes: m.totalBytes,
		Packets:    m.packets,
		Resyncs:    m.resyncs,
	}
}

func (m *Metrics) elapsedLocked() time.Duration {
	if m.start.IsZero() {
		return 0
	}
	if !m.end.IsZero() {
		return m.end.Sub(m.start)
	}
	return time.Since(m.start)
}

type MetricsSnapshot struct {
	Duration   time.Duration
	Bytes      int64
	TotalBytes int64
	Packets    int64
	Resyncs    int64
}

func (s MetricsSnapshot) ThroughputBytesPerSecond() float64 {
	if s.Duration <= 0 {
		return 0
	}
	return float64(s.Bytes) / s.Duration.Seconds()
}

func (s MetricsSnapshot) Completion() float64 {
	if s.TotalBytes <= 0 {
		return 0
	}
	ratio := float64(s.Bytes) / float64(s.TotalBytes)
	if ratio < 0 {
		return 0
	}
	if ratio > 1 {
		return 1
	}
	return ratio
}

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div := float64(unit)
	exp := 0
	for n := float64(b) / div; n >= unit && exp < 6; n /= unit {
		div *= unit
		exp++
	}
	prefixes := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	return fmt.Sprintf("%.2f %s", float64(b)/div, prefixes[exp])
}

func formatProgressLine(s MetricsSnapshot) string {
	throughput := s.ThroughputBytesPerSecond() / (1024 * 1024)
	if s.TotalBytes > 0 {
		pct := s.Completion() * 100
		if math.IsNaN(pct) || math.IsInf(pct, 0) {
			pct = 0
		}
		return fmt.Sprintf("Progress: %6.2f%% (%s / %s) %.2f MiB/s", pct, FormatBytes(s.Bytes), FormatBytes(s.TotalBytes), throughput)
	}
	return fmt.Sprintf("Processed: %s %.2f MiB/s", FormatBytes(s.Bytes), throughput)
}

func StartProgressPrinter(w io.Writer, m *Metrics, interval time.Duration) func() {
	if m == nil || w == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = time.Second
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		lastLen := 0
		for {
			select {
			case <-ticker.C:
				line := formatProgressLine(m.Snapshot())
				pad := lastLen - len(line)
				if pad > 0 {
					line += strings.Repeat(" ", pad)
				}
				fmt.Fprintf(w, "\r%s", line)
				lastLen = len(line)
			case <-done:
				if lastLen > 0 {
					fmt.Fprintf(w, "\r%s\r\n", strings.Repeat(" ", lastLen))
				}
				return
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}
