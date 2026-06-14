package main

import (
	"fmt"
	"os"
	"strings"
)

func SmartSelectTemplates(templates []*Template, target string) []*Template {
	parsed := ParseTarget(target)
	ext := getFileExtension(parsed.Path)

	var selected []*Template
	for _, t := range templates {
		tags := strings.Split(t.Info.Tags, ",")
		tagSet := make(map[string]bool)
		for _, tag := range tags {
			tagSet[strings.TrimSpace(strings.ToLower(tag))] = true
		}

		// Always include critical/high severity
		sev := strings.ToLower(t.Info.Severity)
		if sev == "critical" || sev == "high" {
			selected = append(selected, t)
			continue
		}

		// Match by extension
		if ext != "" {
			if tagSet["php"] && (ext == ".php" || ext == ".phtml") {
				selected = append(selected, t)
				continue
			}
			if tagSet["asp"] && (ext == ".asp" || ext == ".aspx") {
				selected = append(selected, t)
				continue
			}
			if tagSet["jsp"] && ext == ".jsp" {
				selected = append(selected, t)
				continue
			}
		}

		// Include tech detection and info templates always
		if tagSet["tech"] || tagSet["info"] {
			selected = append(selected, t)
			continue
		}

		// Include generic templates always
		if tagSet["generic"] || tagSet["basic"] {
			selected = append(selected, t)
			continue
		}

		// Include if medium severity and target is interesting
		if sev == "medium" && (strings.Contains(target, "api") || strings.Contains(target, "admin")) {
			selected = append(selected, t)
			continue
		}
	}

	if len(selected) == 0 {
		return templates
	}
	return selected
}

func getFileExtension(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 { return "" }
	ext := path[idx:]
	if strings.Contains(ext, "/") || strings.Contains(ext, "?") {
		return ""
	}
	return strings.ToLower(ext)
}

func PrintSmartInfo(total, selected int) {
	if noColor {
		fmt.Fprintf(os.Stderr, "[*] Smart scan: selected %d/%d templates\n", selected, total)
		return
	}
	fmt.Fprintf(os.Stderr, "  %s Smart scan: %s %d/%d templates\n",
		SColor(ColorCyan, "🧠"),
		SColor(ColorBWhite, "selected"),
		selected, total)
}
