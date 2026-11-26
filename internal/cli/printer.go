package cli

import (
	"fmt"
	"io"
)

// printer writes formatted output to a stream and remembers the first write
// error. A command emits many lines; checking once at the end is both honest
// about the failure and free of per-line error plumbing.
type printer struct {
	w   io.Writer
	err error
}

func newPrinter(w io.Writer) *printer {
	return &printer{w: w}
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	if _, err := fmt.Fprintf(p.w, format, args...); err != nil {
		p.err = fmt.Errorf("writing output: %w", err)
	}
}

func (p *printer) linef(format string, args ...any) {
	p.printf(format+"\n", args...)
}

// failure returns the first write failure, if any.
func (p *printer) failure() error {
	return p.err
}
