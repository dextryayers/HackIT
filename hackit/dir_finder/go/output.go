package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type LogLevel int

const (
	LogInfo LogLevel = iota
	LogWarn
	LogError
	LogOK
	LogDebug
)

type OutputEngine struct {
	mu           sync.Mutex
	lastWasProgress bool
	noColor      bool
}

var outputEngine = &OutputEngine{}

func (oe *OutputEngine) SetNoColor(nc bool) {
	oe.noColor = nc
}

func (oe *OutputEngine) log(level LogLevel, msg string, args ...interface{}) {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	oe.clearProgress()

	var tag, tagColor string
	switch level {
	case LogInfo:
		tag = "[*]"
		tagColor = ANSI_CYAN
	case LogWarn:
		tag = "[!]"
		tagColor = ANSI_YELLOW
	case LogError:
		tag = "[!]"
		tagColor = ANSI_RED
	case LogOK:
		tag = "[+]"
		tagColor = ANSI_GREEN
	case LogDebug:
		tag = "[D]"
		tagColor = ANSI_GRAY
	}

	text := fmt.Sprintf(msg, args...)
	if oe.noColor {
		fmt.Printf("%s %s\n", tag, text)
	} else {
		fmt.Printf("%s%s%s %s%s\n", tagColor, tag, ANSI_RESET, text, ANSI_RESET)
	}
}

func (oe *OutputEngine) Info(msg string, args ...interface{}) {
	oe.log(LogInfo, msg, args...)
}

func (oe *OutputEngine) Warn(msg string, args ...interface{}) {
	oe.log(LogWarn, msg, args...)
}

func (oe *OutputEngine) Error(msg string, args ...interface{}) {
	oe.log(LogError, msg, args...)
}

func (oe *OutputEngine) OK(msg string, args ...interface{}) {
	oe.log(LogOK, msg, args...)
}

func (oe *OutputEngine) clearProgress() {
	if oe.lastWasProgress {
		fmt.Print(ANSI_CLEAR_LINE)
		oe.lastWasProgress = false
	}
}

func (oe *OutputEngine) PrintResult(timeStr, mark, status, size, path, redirect, title string) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	oe.clearProgress()
	if oe.noColor {
		fmt.Printf("%s %s %s %s%s%s\n", timeStr, mark+status, size, path, redirect, title)
	} else {
		fmt.Printf("%s[%s] %s %7s %s%s%s\n",
			ANSI_CLEAR_LINE, timeStr, mark+status, size, path, redirect, title)
	}
}

func (oe *OutputEngine) PrintProgress(completed, total int, found, errors int, rate float64, etaM, etaS int, timedOut bool) {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	pct := int(float64(completed) / float64(total) * 100)
	var line string
	if timedOut {
		line = fmt.Sprintf("[*] [%d/%d] %d%% | TIMEOUT | Found: %d | Errors: %d",
			completed, total, pct, found, errors)
	} else {
		line = fmt.Sprintf("[*] [%d/%d] %d%% | Found: %d | Errors: %d | Rate: %.0f/s | ETA: %dm%ds",
			completed, total, pct, found, errors, rate, etaM, etaS)
	}

	if oe.noColor {
		fmt.Printf("\r%s   ", line)
	} else {
		fmt.Printf("\r%s%s%s   ", ANSI_CYAN, line, ANSI_RESET)
	}
	oe.lastWasProgress = true
}

func (oe *OutputEngine) PrintHeader(title string) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	if oe.noColor {
		fmt.Println(title)
	} else {
		fmt.Printf("%s%s%s\n", ANSI_MAGENTA, title, ANSI_RESET)
	}
}

func (oe *OutputEngine) PrintLine(line string) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	oe.clearProgress()
	fmt.Println(line)
}

func (oe *OutputEngine) FinalResults(results []DirResult, stats *ScanStats, elapsed string) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	oe.clearProgress()

	if oe.noColor {
		fmt.Printf("\n[+] Scan completed in %s\n", elapsed)
		if len(results) == 0 {
			fmt.Println("[!] No results found")
		} else {
			fmt.Printf("[+] Results (%d found):\n\n", len(results))
			for _, r := range results {
				sz := FormatSize(r.Size)
				rd := ""
				if r.Redirect != "" {
					rd = " -> " + r.Redirect
				}
				ti := ""
				if r.Title != "" {
					ti = " /* " + r.Title + " */"
				}
				fmt.Printf("  %d  %7s  /%s%s%s\n", r.Status, sz, strings.TrimPrefix(r.Path, "/"), rd, ti)
			}
		}
		fmt.Printf("\n[*] Requests: %d | Found: %d | Filtered: %d | Errors: %d\n",
			stats.TotalRequests, stats.Found, stats.Filtered, stats.Errors)
	} else {
		fmt.Printf("\n%s Scan completed in %s%s\n", ANSI_GREEN+"[+]"+ANSI_RESET, elapsed, ANSI_RESET)
		if len(results) == 0 {
			fmt.Printf("%s No results found%s\n", ANSI_YELLOW+"[!]"+ANSI_RESET, ANSI_RESET)
		} else {
			fmt.Printf("%s Results (%d found):%s\n\n", ANSI_GREEN+"[+]"+ANSI_RESET, len(results), ANSI_RESET)
			for _, r := range results {
				sz := FormatSize(r.Size)
				var sc string
				switch {
				case r.Status >= 200 && r.Status < 300:
					sc = ANSI_GREEN + fmt.Sprintf("%d", r.Status) + ANSI_RESET
				case r.Status >= 300 && r.Status < 400:
					sc = ANSI_YELLOW + fmt.Sprintf("%d", r.Status) + ANSI_RESET
				case r.Status >= 400 && r.Status < 500:
					sc = ANSI_ORANGE + fmt.Sprintf("%d", r.Status) + ANSI_RESET
				default:
					sc = ANSI_RED + fmt.Sprintf("%d", r.Status) + ANSI_RESET
				}
				rd := ""
				if r.Redirect != "" {
					rd = fmt.Sprintf(" %s-> %s%s", ANSI_GRAY, r.Redirect, ANSI_RESET)
				}
				ti := ""
				if r.Title != "" {
					ti = fmt.Sprintf(" %s/* %s */%s", ANSI_GRAY, r.Title, ANSI_RESET)
				}
				fmt.Printf("  %s  %7s  %s%s%s\n", sc, sz, strings.TrimPrefix(r.Path, "/"), rd, ti)
			}
		}
		fmt.Printf("\n%s[*]%s Requests: %d | Found: %d | Filtered: %d | Errors: %d\n",
			ANSI_CYAN, ANSI_RESET, stats.TotalRequests, stats.Found, stats.Filtered, stats.Errors)
	}
}

func (oe *OutputEngine) Printf(format string, args ...interface{}) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	oe.clearProgress()
	fmt.Fprintf(os.Stdout, format, args...)
}

func (oe *OutputEngine) Println(args ...interface{}) {
	oe.mu.Lock()
	defer oe.mu.Unlock()
	oe.clearProgress()
	fmt.Println(args...)
}
