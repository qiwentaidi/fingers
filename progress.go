package fingers

import (
	"sync"
	"time"

	"github.com/qiwentaidi/fingers/internal/logger"
)

const scanProgressInterval = 30 * time.Second

type scanProgressOutcome string

const (
	scanProgressOutcomeSkipped scanProgressOutcome = "skipped"
	scanProgressOutcomeFailed  scanProgressOutcome = "failed"
	scanProgressOutcomeMatched scanProgressOutcome = "matched"
)

type scanProgress struct {
	stage    string
	total    int
	enabled  bool
	interval time.Duration
	started  time.Time
	done     chan struct{}
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex

	processed int
	requested int
	failed    int
	matched   int
	skipped   int
}

func newScanProgress(stage string, total int, enabled bool) *scanProgress {
	p := &scanProgress{
		stage:    stage,
		total:    total,
		enabled:  enabled,
		interval: scanProgressInterval,
		started:  time.Now(),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
	}
	if enabled {
		go p.run()
	}
	return p
}

func (p *scanProgress) run() {
	ticker := time.NewTicker(p.interval)
	defer func() {
		ticker.Stop()
		close(p.closed)
	}()

	for {
		select {
		case <-ticker.C:
			p.print(false)
		case <-p.done:
			return
		}
	}
}

func (p *scanProgress) Requested() {
	p.add(func() { p.requested++ })
}

func (p *scanProgress) Failed() {
	p.add(func() { p.failed++ })
}

func (p *scanProgress) Matched() {
	p.add(func() { p.matched++ })
}

func (p *scanProgress) Skipped() {
	p.add(func() { p.skipped++ })
}

func (p *scanProgress) Processed() {
	p.add(func() { p.processed++ })
}

func (p *scanProgress) Finish() {
	if p == nil || !p.enabled {
		return
	}
	p.once.Do(func() {
		close(p.done)
		<-p.closed
		p.print(true)
	})
}

func (p *scanProgress) add(update func()) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	update()
	p.mu.Unlock()
}

func (p *scanProgress) print(final bool) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	processed := p.processed
	requested := p.requested
	failed := p.failed
	matched := p.matched
	skipped := p.skipped
	p.mu.Unlock()

	elapsed := time.Since(p.started).Round(time.Second)
	rate := 0.0
	if seconds := time.Since(p.started).Seconds(); seconds > 0 {
		rate = float64(processed) / seconds
	}
	status := "running"
	if final {
		status = "done"
	}
	logger.Default.Info("progress stage=%s status=%s processed=%d total=%d requested=%d failed=%d matched=%d skipped=%d elapsed=%s rate=%.1f/s",
		p.stage,
		status,
		processed,
		p.total,
		requested,
		failed,
		matched,
		skipped,
		elapsed,
		rate,
	)
}
