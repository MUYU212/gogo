package core

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	progressTickInterval  = 250 * time.Millisecond
	progressLogInterval   = 5 * time.Second
	progressBarWidth      = 24
	progressTerminalWidth = 110
)

var progressSpinners = []string{"|", "/", "-", "\\"}

type ProgressSnapshot struct {
	Label string
	Total int64
	Done  int64
}

var activeProgressState struct {
	mu       sync.RWMutex
	progress *ProgressTracker
}

type ProgressTracker struct {
	label         string
	enabled       bool
	isTerminal    bool
	started       time.Time
	total         int64
	done          int64
	generatedDone uint32
	fixedTotal    uint32
	renderCount   uint64
	stopCh        chan struct{}
}

func NewProgressTracker(label string, enabled bool) *ProgressTracker {
	tracker := &ProgressTracker{
		label:   label,
		enabled: enabled,
		stopCh:  make(chan struct{}),
		started: time.Now(),
	}
	SetActiveProgress(tracker)

	if !enabled {
		return tracker
	}
	if stat, err := os.Stderr.Stat(); err == nil {
		tracker.isTerminal = stat.Mode()&os.ModeCharDevice != 0
	}
	go tracker.loop()
	return tracker
}

func (p *ProgressTracker) AddTotal(delta int64) {
	if p == nil || delta <= 0 {
		return
	}
	if atomic.LoadUint32(&p.fixedTotal) == 1 {
		return
	}
	atomic.AddInt64(&p.total, delta)
}

func (p *ProgressTracker) AddDone(delta int64) {
	if p == nil || delta <= 0 {
		return
	}
	atomic.AddInt64(&p.done, delta)
}

func (p *ProgressTracker) MarkGeneratedDone() {
	if p == nil {
		return
	}
	atomic.StoreUint32(&p.generatedDone, 1)
}

func (p *ProgressTracker) SetTotal(total int64) {
	if p == nil || total < 0 {
		return
	}
	atomic.StoreInt64(&p.total, total)
	atomic.StoreUint32(&p.fixedTotal, 1)
}

func (p *ProgressTracker) SetDone(done int64) {
	if p == nil || done < 0 {
		return
	}
	atomic.StoreInt64(&p.done, done)
}

func (p *ProgressTracker) Finish() {
	if p == nil {
		return
	}
	ClearActiveProgress(p)
	p.MarkGeneratedDone()
	if !p.enabled {
		return
	}
	close(p.stopCh)
}

func (p *ProgressTracker) Snapshot() ProgressSnapshot {
	if p == nil {
		return ProgressSnapshot{}
	}
	return ProgressSnapshot{
		Label: p.label,
		Total: atomic.LoadInt64(&p.total),
		Done:  atomic.LoadInt64(&p.done),
	}
}

func (p *ProgressTracker) loop() {
	interval := progressTickInterval
	if !p.isTerminal {
		interval = progressLogInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.render(false)
		case <-p.stopCh:
			p.render(true)
			return
		}
	}
}

func (p *ProgressTracker) render(final bool) {
	done := atomic.LoadInt64(&p.done)
	total := atomic.LoadInt64(&p.total)
	if total < done {
		total = done
	}

	elapsed := time.Since(p.started)
	renders := atomic.AddUint64(&p.renderCount, 1)
	spinner := progressSpinners[int(renders)%len(progressSpinners)]
	generatedDone := atomic.LoadUint32(&p.generatedDone) == 1
	fixedTotal := atomic.LoadUint32(&p.fixedTotal) == 1

	var percent float64
	if total > 0 {
		percent = float64(done) / float64(total)
		if percent > 1 {
			percent = 1
		}
	}

	bar := buildProgressBar(percent, generatedDone && total > 0)
	rate := float64(done) / maxFloat(elapsed.Seconds(), 1)
	eta := "--"
	if total > 0 && done > 0 && total >= done && (generatedDone || fixedTotal) {
		remaining := total - done
		if remaining == 0 {
			eta = "00:00"
		} else {
			eta = formatDuration(time.Duration(float64(remaining)/rate) * time.Second)
		}
	}

	state := "scanning"
	if !generatedDone && !fixedTotal {
		state = "discovering"
	} else if done >= total {
		state = "done"
	}

	line := fmt.Sprintf("%s %s %6.2f%% %d/%d elapsed %s eta %s rate %.1f/s %s",
		spinner,
		bar,
		percent*100,
		done,
		total,
		formatDuration(elapsed),
		eta,
		rate,
		p.label,
	)
	if !generatedDone && !fixedTotal && total == 0 {
		line = fmt.Sprintf("%s %s waiting for tasks elapsed %s %s", spinner, bar, formatDuration(elapsed), p.label)
	} else if !generatedDone && !fixedTotal {
		line = fmt.Sprintf("%s %s %6.2f%% %d/%d elapsed %s rate %.1f/s %s (%s)",
			spinner,
			bar,
			percent*100,
			done,
			total,
			formatDuration(elapsed),
			rate,
			p.label,
			state,
		)
	}
	line = trimProgressLine(line)

	if p.isTerminal {
		fmt.Fprintf(os.Stderr, "\r\033[K%s", line)
		if final {
			fmt.Fprint(os.Stderr, "\n")
		}
		return
	}

	if final {
		fmt.Fprintln(os.Stderr, line)
	}
}

func buildProgressBar(percent float64, freeze bool) string {
	filled := int(percent * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	if filled < 0 {
		filled = 0
	}
	if !freeze && filled == progressBarWidth && percent < 1 {
		filled = progressBarWidth - 1
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", progressBarWidth-filled) + "]"
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSeconds := int(d.Seconds())
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func trimProgressLine(line string) string {
	if len(line) <= progressTerminalWidth {
		return line
	}
	return line[:progressTerminalWidth-3] + "..."
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func SetActiveProgress(progress *ProgressTracker) {
	activeProgressState.mu.Lock()
	defer activeProgressState.mu.Unlock()
	activeProgressState.progress = progress
}

func GetActiveProgress() *ProgressTracker {
	activeProgressState.mu.RLock()
	defer activeProgressState.mu.RUnlock()
	return activeProgressState.progress
}

func ClearActiveProgress(progress *ProgressTracker) {
	activeProgressState.mu.Lock()
	defer activeProgressState.mu.Unlock()
	if activeProgressState.progress == progress {
		activeProgressState.progress = nil
	}
}
