package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
)

type Logger struct {
	VerboseLevel int
	NoColor      bool
}

func NewLogger(level int, noColor bool) *Logger {
	if noColor {
		color.NoColor = true
	}
	return &Logger{VerboseLevel: level, NoColor: noColor}
}

func (l *Logger) output(tag string, msg string, c *color.Color) {
	ts := time.Now().Format("15:04:05")
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, tag, msg)
	} else {
		tsStr := color.New(color.FgWhite).Sprintf("[%s]", ts)
		tagStr := c.Sprint(tag)
		fmt.Fprintf(os.Stderr, "%s %s %s\n", tsStr, tagStr, msg)
	}
}

func (l *Logger) Info(msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[INFO]", msg, color.New(color.FgGreen))
	}
}

func (l *Logger) Success(msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[SUCCESS]", msg, color.New(color.FgGreen, color.Bold))
	}
}

func (l *Logger) Warning(msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[WARNING]", msg, color.New(color.FgYellow))
	}
}

func (l *Logger) Error(msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[CRITICAL]", msg, color.New(color.FgRed, color.Bold))
	}
}

func (l *Logger) Critical(msg string) {
	if l.VerboseLevel >= 0 {
		l.output("[CRITICAL]", msg, color.New(color.FgRed, color.Bold))
	}
}

func (l *Logger) Payload(msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[PAYLOAD]", msg, color.New(color.FgCyan))
	}
}

func (l *Logger) Debug(msg string) {
	if l.VerboseLevel >= 2 {
		l.output("[DEBUG]", msg, color.New(color.FgMagenta))
	}
}

func (l *Logger) Raw(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

func (l *Logger) RawLog(data string) {
	f, _ := os.OpenFile("traffic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), data))
}

func (l *Logger) Banner(version string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "HACKIT SQLi Engine %s\n", version)
	} else {
		c := color.New(color.FgGreen, color.Bold)
		c.Fprintf(os.Stderr, "    ___   _  _   ___   ___\n")
		c.Fprintf(os.Stderr, "   / __| | || | |_ _| |_ _|\n")
		c.Fprintf(os.Stderr, "   \\__ \\ | __ |  | |   | |\n")
		c.Fprintf(os.Stderr, "   |___/ |_||_| |___| |___|\n")
		color.New(color.FgCyan).Fprintf(os.Stderr, "   HACKIT SQLi ENGINE v%s\n", version)
		color.New(color.FgYellow).Fprintf(os.Stderr, "   997 Payloads | 16 DBMS | 6-Stage Scan\n")
		fmt.Fprintln(os.Stderr)
	}
}
