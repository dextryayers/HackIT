package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
)

// Logger handles structured logging and output
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

func (l *Logger) format(level, prefix, msg string, c *color.Color) {
	timestamp := time.Now().Format("15:04:05")
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "[%s][%s] %s\n", timestamp, level, msg)
	} else {
		// Matching user requested format [WAKTU][LEVEL]
		timeStr := color.New(color.FgWhite).Sprint(timestamp)
		levelStr := c.Sprint(level)
		fmt.Fprintf(os.Stderr, "[%s][%s] %s\n", timeStr, levelStr, msg)
	}
}

func (l *Logger) Info(msg string) {
	l.format("INFO", "[*]", msg, color.New(color.FgCyan))
}

func (l *Logger) Success(msg string) {
	l.format("SUCCESS", "[+]", msg, color.New(color.FgGreen))
}

func (l *Logger) Warning(msg string) {
	l.format("WARNING", "[!]", msg, color.New(color.FgYellow))
}

func (l *Logger) Error(msg string) {
	l.format("CRITICAL", "[-]", msg, color.New(color.FgRed, color.Bold))
}

func (l *Logger) Critical(msg string) {
	l.format("CRITICAL", "[!!]", msg, color.New(color.FgRed, color.BgBlack, color.Bold))
}

func (l *Logger) Debug(msg string) {
	if l.VerboseLevel >= 2 {
		l.format("DEBUG", "[D]", msg, color.New(color.FgMagenta))
	}
}

func (l *Logger) Raw(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

func (l *Logger) RawLog(data string) {
	// Logic to save raw traffic log
	f, _ := os.OpenFile("traffic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), data))
}
