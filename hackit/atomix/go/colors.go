package main

import (
	"fmt"
	"strings"
)

type Color string

const (
	ColorReset   Color = "\033[0m"
	ColorBold    Color = "\033[1m"
	ColorDim     Color = "\033[2m"
	ColorRed     Color = "\033[31m"
	ColorGreen   Color = "\033[32m"
	ColorYellow  Color = "\033[33m"
	ColorBlue    Color = "\033[34m"
	ColorMagenta Color = "\033[35m"
	ColorCyan    Color = "\033[36m"
	ColorWhite   Color = "\033[37m"
	ColorBRed    Color = "\033[1;31m"
	ColorBGreen  Color = "\033[1;32m"
	ColorBYellow Color = "\033[1;33m"
	ColorBBlue   Color = "\033[1;34m"
	ColorBMagenta Color = "\033[1;35m"
	ColorBCyan   Color = "\033[1;36m"
	ColorBWhite  Color = "\033[1;37m"
	ColorBgRed   Color = "\033[41m"
	ColorBgGreen Color = "\033[42m"
)

var noColor bool

func SetNoColor(v bool) { noColor = v }

func SColor(c Color, s string) string {
	if noColor {
		return s
	}
	return string(c) + s + string(ColorReset)
}

func SeverityColor(severity string) Color {
	switch strings.ToLower(severity) {
	case "critical":
		return ColorBRed
	case "high":
		return ColorRed
	case "medium":
		return ColorYellow
	case "low":
		return ColorBlue
	case "info":
		return ColorGreen
	default:
		return ColorWhite
	}
}

func SeverityBgColor(severity string) Color {
	switch strings.ToLower(severity) {
	case "critical":
		return ColorBgRed
	default:
		return ColorReset
	}
}

func SeverityTag(severity string) string {
	s := strings.ToUpper(severity)
	c := SeverityColor(severity)
	return SColor(c, fmt.Sprintf("[%s]", s))
}

func ColorStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return SColor(ColorGreen, fmt.Sprintf("%d", code))
	case code >= 300 && code < 400:
		return SColor(ColorBlue, fmt.Sprintf("%d", code))
	case code >= 400 && code < 500:
		return SColor(ColorYellow, fmt.Sprintf("%d", code))
	case code >= 500:
		return SColor(ColorRed, fmt.Sprintf("%d", code))
	default:
		return fmt.Sprintf("%d", code)
	}
}

func ColorMethod(method string) string {
	switch method {
	case "GET":
		return SColor(ColorGreen, method)
	case "POST":
		return SColor(ColorYellow, method)
	case "PUT":
		return SColor(ColorBlue, method)
	case "DELETE":
		return SColor(ColorRed, method)
	case "OPTIONS":
		return SColor(ColorMagenta, method)
	case "HEAD":
		return SColor(ColorCyan, method)
	case "PATCH":
		return SColor(ColorMagenta, method)
	default:
		return method
	}
}
