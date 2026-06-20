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

func (l *Logger) ts() string {
	return time.Now().Format("15:04:05")
}

func (l *Logger) output(symbol, tag, msg string, c *color.Color) {
	ts := l.ts()
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "%s [%s] [%s] %s\n", symbol, ts, tag, msg)
	} else {
		tsStr := color.New(color.FgWhite).Sprintf("[%s]", ts)
		tagStr := c.Sprintf("[%s]", tag)
		symStr := c.Sprintf("%s", symbol)
		fmt.Fprintf(os.Stderr, "%s %s %s %s\n", symStr, tsStr, tagStr, msg)
	}
}

func (l *Logger) Plus(tag, msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[+]", tag, msg, color.New(color.FgGreen))
	}
}

func (l *Logger) Minus(tag, msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[-]", tag, msg, color.New(color.FgYellow))
	}
}

func (l *Logger) Cross(tag, msg string) {
	if l.VerboseLevel >= 0 {
		l.output("[x]", tag, msg, color.New(color.FgRed))
	}
}

func (l *Logger) Arrow(tag, msg string) {
	if l.VerboseLevel >= 1 {
		l.output("[>]", tag, msg, color.New(color.FgGreen, color.Bold))
	}
}

func (l *Logger) Success(msg string) {
	l.Arrow("SUCCESS", msg)
}

func (l *Logger) Info(msg string) {
	l.Plus("INFO", msg)
}

func (l *Logger) Warning(msg string) {
	l.Minus("WARNING", msg)
}

func (l *Logger) Error(msg string) {
	l.Cross("ERROR", msg)
}

func (l *Logger) Critical(msg string) {
	l.Cross("WARNING", msg)
}

func (l *Logger) Payload(dbms, payload string) {
	if l.VerboseLevel >= 1 {
		ts := l.ts()
		tag := fmt.Sprintf("Testing [%s]", dbms)
		if l.NoColor {
			fmt.Fprintf(os.Stderr, "[+] [%s] [%s] %s\n", ts, tag, payload)
		} else {
			tsStr := color.New(color.FgWhite).Sprintf("[%s]", ts)
			tagStr := color.New(color.FgGreen).Sprintf("[%s]", tag)
			payStr := color.New(color.FgCyan).Sprintf("%s", payload)
			symStr := color.New(color.FgGreen).Sprintf("[+]")
			fmt.Fprintf(os.Stderr, "%s %s %s %s\n", symStr, tsStr, tagStr, payStr)
		}
	}
}

func (l *Logger) BackendStack(stack map[string]string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "[+] Back End Stack\n")
		for k, v := range stack {
			fmt.Fprintf(os.Stderr, "      [-] %s: %s\n", k, v)
		}
	} else {
		sym := color.New(color.FgGreen)
		sub := color.New(color.FgYellow)
		val := color.New(color.FgWhite)
		sym.Fprintf(os.Stderr, "[+] ")
		color.New(color.FgGreen, color.Bold).Fprintf(os.Stderr, "Back End Stack\n")
		for k, v := range stack {
			sub.Fprintf(os.Stderr, "      [-] %s: ", k)
			val.Fprintf(os.Stderr, "%s\n", v)
		}
	}
}

func (l *Logger) Failure(msg string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "[>] FAILED!! %s\n", msg)
	} else {
		color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "[>] FAILED!! %s\n", msg)
	}
}

func (l *Logger) SectionHeader(title string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "[>] %s\n", title)
	} else {
		color.New(color.FgGreen, color.Bold).Fprintf(os.Stderr, "[>] %s\n", title)
	}
}

func (l *Logger) SectionItem(name string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "\t[-] %s\n", name)
	} else {
		color.New(color.FgYellow).Fprintf(os.Stderr, "\t[-] ")
		fmt.Fprintf(os.Stderr, "%s\n", name)
	}
}

func (l *Logger) SectionData(name string) {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, "\t[+] %s\n", name)
	} else {
		color.New(color.FgGreen).Fprintf(os.Stderr, "\t[+] ")
		fmt.Fprintf(os.Stderr, "%s\n", name)
	}
}

func (l *Logger) ListDBHeader() {
	l.SectionHeader("AVAILABLE DATABASE")
}

func (l *Logger) ListDB(name string) {
	l.SectionItem(name)
}

func (l *Logger) ListItem(name string) {
	l.SectionItem(name)
}

func (l *Logger) Blank() {
	fmt.Fprintln(os.Stderr)
}

func (l *Logger) Raw(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

func (l *Logger) Debug(msg string) {
	if l.VerboseLevel >= 2 {
		l.Minus("DEBUG", msg)
	}
}

func (l *Logger) RawLog(data string) {
	f, _ := os.OpenFile("traffic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), data))
}

func (l *Logger) Banner() {
	if l.NoColor {
		fmt.Fprintf(os.Stderr, `  ▄████████  ▄█   ▄█          ▄████████ ████████▄
 ███    ███ ███  ███         ███    ███ ███   ▀███
 ███    █▀  ███▌ ███         ███    █▀  ███    ███
 ███        ███▌ ███        ▄███▄▄▄     ███    ███
▀███████████ ███▌ ███       ▀▀███▀▀▀     ███    ███
         ███ ███  ███         ███    █▀  ███   ▄███
   ▄█    ███ ███  ██▌    ▄   ███    ███ ████████▀
 ▄████████▀  █▀   ███▄▄██   ██████████
─────────────────────────────────────────────────
  SQLi Exploit Engine v2.1 (Blind/Time/Union)
  Developer  : AniipID
─────────────────────────────────────────────────
  WARNING : Use only on systems you own or
     have explicit written permission to test!
─────────────────────────────────────────────────
`)
	} else {
		c := color.New(color.FgGreen)
		c.Fprintf(os.Stderr, `  ▄████████  ▄█   ▄█          ▄████████ ████████▄
 ███    ███ ███  ███         ███    ███ ███   ▀███
 ███    █▀  ███▌ ███         ███    █▀  ███    ███
 ███        ███▌ ███        ▄███▄▄▄     ███    ███
▀███████████ ███▌ ███       ▀▀███▀▀▀     ███    ███
         ███ ███  ███         ███    █▀  ███   ▄███
   ▄█    ███ ███  ██▌    ▄   ███    ███ ████████▀
 ▄████████▀  █▀   ███▄▄██   ██████████
`)
		color.New(color.FgGreen).Fprintf(os.Stderr, "─────────────────────────────────────────────────\n")
		color.New(color.FgCyan).Fprintf(os.Stderr, "  SQLi Exploit Engine v3.0 (2270 Payloads / 20 Engines)\n")
		color.New(color.FgYellow).Fprintf(os.Stderr, "  Developer  : AniipID\n")
		color.New(color.FgGreen).Fprintf(os.Stderr, "─────────────────────────────────────────────────\n")
		color.New(color.FgYellow).Fprintf(os.Stderr, "  \u26a0\ufe0f  WARNING : Use only on systems you own or\n")
		color.New(color.FgYellow).Fprintf(os.Stderr, "     have explicit written permission to test!\n")
		color.New(color.FgGreen).Fprintf(os.Stderr, "─────────────────────────────────────────────────\n")
	}
}
