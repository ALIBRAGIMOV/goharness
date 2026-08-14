package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// paletteFor decides whether output may be colourised. Colour is a terminal
// affordance: a pipe, NO_COLOR, and --no-color all get plain text.
func paletteFor(w io.Writer, disabled bool) report.Palette {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return report.Palette{}
	}
	return report.Palette{Enabled: isTerminal(w)}
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// progressWidth caps a status line so it never wraps and leaves debris behind
// when it is erased.
const progressWidth = 160

// progress prints transient per-check status lines to a terminal and erases
// them before the report is written. It writes nothing when the destination is
// not a terminal, so piped output stays clean.
type progress struct {
	out     io.Writer
	enabled bool

	mu      sync.Mutex
	done    int
	total   int
	running map[string]time.Time
	painted bool
}

func newProgress(w io.Writer, enabled bool) *progress {
	return &progress{
		out:     w,
		enabled: enabled && isTerminal(w),
		running: map[string]time.Time{},
	}
}

// Handle receives scheduler events. It is safe for concurrent use because the
// scheduler calls it from every check goroutine.
func (p *progress) Handle(event verify.ProgressEvent) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if event.Total > p.total {
		p.total = event.Total
	}
	if event.Done {
		delete(p.running, event.Check)
		p.done++
	} else {
		p.running[event.Check] = time.Now()
	}
	p.paint()
}

func (p *progress) paint() {
	names := make([]string, 0, len(p.running))
	for name, started := range p.running {
		names = append(names, fmt.Sprintf("%s %.1fs", name, time.Since(started).Seconds()))
	}
	if len(names) == 0 {
		p.erase()
		return
	}
	line := fmt.Sprintf("\r\x1b[K[%d/%d] %s", p.done, p.total, strings.Join(names, ", "))
	if len(line) > progressWidth {
		line = line[:progressWidth]
	}
	p.write(line)
	p.painted = true
}

// write emits a progress fragment. A terminal that stops accepting writes is
// not a verification failure, so painting simply switches itself off.
func (p *progress) write(s string) {
	if _, err := io.WriteString(p.out, s); err != nil {
		p.enabled = false
	}
}

// Clear erases the transient line so the final report starts on a clean row.
func (p *progress) Clear() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.erase()
}

func (p *progress) erase() {
	if !p.painted {
		return
	}
	p.write("\r\x1b[K")
	p.painted = false
}
