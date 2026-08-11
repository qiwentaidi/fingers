package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	bold   = "\033[1m"
)

type Logger struct {
	mu           sync.Mutex
	writer       io.Writer
	enableColor  bool
	enableOutput bool
}

var Default = &Logger{
	writer:       os.Stdout,
	enableColor:  true,
	enableOutput: true,
}

func (l *Logger) SetWriter(w io.Writer) {
	if w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

func (l *Logger) ConfigureWriter(w io.Writer) func() {
	if w == nil {
		return func() {}
	}

	l.mu.Lock()
	previous := l.writer
	previousColor := l.enableColor
	l.writer = w
	l.enableColor = false
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.writer = previous
			l.enableColor = previousColor
		})
	}
}

func (l *Logger) SetOutput(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enableOutput = enabled
}

func (l *Logger) SetColor(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enableColor = enabled
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.printf("INF", blue, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.printf("WRN", yellow, format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.printf("DBG", blue, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.printf("ERR", red, format, args...)
}

func (l *Logger) PrintRaw(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enableOutput {
		return
	}
	fmt.Fprintf(l.writer, format, args...)
}

func (l *Logger) printf(level string, levelColor string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enableOutput {
		return
	}
	label := level
	if l.enableColor {
		label = levelColor + level + reset
	}
	fmt.Fprintf(l.writer, "[%s] %s\n", label, fmt.Sprintf(format, args...))
}

func Title(text string) string {
	return Default.colorize(text, bold)
}

func Red(text string) string {
	return Default.colorize(text, red)
}

func Yellow(text string) string {
	return Default.colorize(text, yellow)
}

func Green(text string) string {
	return Default.colorize(text, green)
}

func ColorStatus(code int) string {
	text := fmt.Sprintf("%d", code)
	switch {
	case code >= 200 && code < 300:
		return Green(text)
	case code >= 300 && code < 400:
		return Yellow(text)
	case code >= 400:
		return Red(text)
	default:
		return text
	}
}

func WithDescription(name string, description string) string {
	if strings.TrimSpace(description) == "" {
		return name
	}
	return fmt.Sprintf("%s(%s)", name, description)
}

func (l *Logger) colorize(text string, color string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enableColor {
		return text
	}
	return color + text + reset
}
