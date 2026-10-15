package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type CustomTemplateSource struct {
	Name      string
	Dir       string
	Priority  int
	Overrides bool
}

var customTemplateDirs []CustomTemplateSource

func RegisterCustomTemplateDir(name, dir string, priority int, overrides bool) {
	customTemplateDirs = append(customTemplateDirs, CustomTemplateSource{
		Name:      name,
		Dir:       dir,
		Priority:  priority,
		Overrides: overrides,
	})
}

func ResolveTemplateDirs(config *ScanConfig) []string {
	var dirs []string
	seen := make(map[string]bool)
	add := func(d string) {
		d = strings.TrimSpace(expandPath(d))
		if d == "" {
			return
		}
		abs, err := filepath.Abs(d)
		key := d
		if err == nil {
			key = abs
		}
		if !seen[key] {
			seen[key] = true
			dirs = append(dirs, d)
		}
	}

	// Built-in library first; later (custom) sources override it on ID clash.
	add(config.TemplateDir)

	// User-specified custom directories (comma-separated).
	for _, d := range strings.Split(config.CustomTemplateDir, ",") {
		add(d)
	}

	// Environment variable (OS path-list separated).
	if envDir := os.Getenv("ATOMIX_CUSTOM_TEMPLATES"); envDir != "" {
		for _, d := range strings.Split(envDir, string(os.PathListSeparator)) {
			add(d)
		}
	}

	// Project-local custom directory (next to the binary/config)
	pwd, _ := os.Getwd()
	for _, ld := range []string{
		filepath.Join(pwd, "custom-templates"),
		filepath.Join(pwd, "custom_templates"),
		filepath.Join(pwd, ".atomix"),
	} {
		if dirExists(ld) {
			add(ld)
		}
	}

	// Check common user custom template paths
	home, _ := os.UserHomeDir()
	for _, p := range []string{
		filepath.Join(home, ".atomix", "custom"),
		filepath.Join(home, ".atomix", "custom-templates"),
		filepath.Join(home, ".atomix", "templates"),
		filepath.Join(home, ".config", "atomix", "templates"),
		filepath.Join(home, ".atomix", "community"),
		filepath.Join(home, "atomix-custom"),
	} {
		if dirExists(p) {
			add(p)
		}
	}

	// Global system path
	if dirExists("/etc/atomix/templates") {
		add("/etc/atomix/templates")
	}

	return dirs
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// templateSources records which directory each template ID was loaded
// from (after override resolution). Used by --list -v.
var templateSources = make(map[string]string)

// ResolveOverrides applies last-wins deduplication by template ID so
// --load / --from-git / stdin templates override the library.
func ResolveOverrides(templates []*Template) []*Template {
	index := make(map[string]int)
	var out []*Template
	for _, t := range templates {
		if pos, exists := index[t.ID]; exists {
			out[pos] = t
			continue
		}
		index[t.ID] = len(out)
		out = append(out, t)
	}
	for _, t := range out {
		if t.FilePath != "" {
			templateSources[t.ID] = t.FilePath
		}
	}
	return out
}

// TemplateSource returns the directory a template ID was loaded from.
func TemplateSource(id string) string { return templateSources[id] }

func LoadTemplatesFromDirs(dirs []string) ([]*Template, error) {
	var all []*Template
	index := make(map[string]int) // template ID -> position in all
	overridden := 0

	for _, dir := range dirs {
		templates, err := LoadTemplates(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error loading %s: %v\n",
				SColor(ColorYellow, "[!]"), dir, err)
			continue
		}
		for _, t := range templates {
			// Later directories override earlier ones, so custom
			// folders always win over the built-in library.
			if pos, exists := index[t.ID]; exists {
				all[pos] = t
				overridden++
			} else {
				index[t.ID] = len(all)
				all = append(all, t)
			}
			templateSources[t.ID] = dir
		}
	}

	fmt.Fprintf(os.Stderr, "%s Loaded %d unique templates from %d directories",
		SColor(ColorGreen, "[+]"), len(all), len(dirs))
	if overridden > 0 {
		fmt.Fprintf(os.Stderr, " (%d overridden by custom sources)", overridden)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return all, nil
}

// Load individual template files specified by --load / --template-file
func LoadTemplateFiles(paths []string) ([]*Template, error) {
	var all []*Template
	for _, p := range paths {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			t, err := downloadTemplateFromURL(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Error downloading %s: %v\n",
					SColor(ColorRed, "[!]"), p, err)
				continue
			}
			all = append(all, t)
			continue
		}
		expanded := expandPath(p)
		info, err := os.Stat(expanded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Template not found: %s\n",
				SColor(ColorRed, "[!]"), expanded)
			continue
		}
		if info.IsDir() {
			templates, err := LoadTemplates(expanded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Error loading dir %s: %v\n",
					SColor(ColorRed, "[!]"), expanded, err)
				continue
			}
			all = append(all, templates...)
		} else {
			templates, err := LoadAllTemplatesFromFile(expanded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Error loading %s: %v\n",
					SColor(ColorRed, "[!]"), expanded, err)
				continue
			}
			all = append(all, templates...)
		}
	}
	return all, nil
}

// Download template from URL
func downloadTemplateFromURL(url string) (*Template, error) {
	fmt.Fprintf(os.Stderr, "%s Downloading template: %s\n",
		SColor(ColorCyan, "↓"), url)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	// Try to parse as single or multi-document
	// First try single
	var t Template
	if err := yamlUnmarshal(data, &t); err != nil || t.ID == "" {
		// Try multi
		templates, err := parseMultiDocYAML(data)
		if err != nil || len(templates) == 0 {
			return nil, fmt.Errorf("invalid template from %s", url)
		}
		if len(templates) > 0 {
			templates[0].FilePath = url
			return templates[0], nil
		}
	}
	t.FilePath = url
	return &t, nil
}

// Load template from stdin (pipe)
func LoadTemplatesFromStdin() ([]*Template, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "%s Reading template from stdin...\n",
		SColor(ColorCyan, "↓"))
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("stdin read error: %w", err)
	}
	templates, err := parseMultiDocYAML(data)
	if err != nil {
		return nil, fmt.Errorf("stdin template parse error: %w", err)
	}
	for _, t := range templates {
		t.FilePath = "<stdin>"
	}
	return templates, nil
}

// Load templates from a git repository (clone or pull)
func LoadTemplatesFromGit(repoURL, targetDir string) ([]*Template, error) {
	repoName := filepath.Base(repoURL)
	if strings.HasSuffix(repoName, ".git") {
		repoName = repoName[:len(repoName)-4]
	}
	cloneDir := filepath.Join(targetDir, repoName)

	// Check if already cloned
	if dirExists(cloneDir) {
		fmt.Fprintf(os.Stderr, "%s Updating %s...\n",
			SColor(ColorCyan, "↻"), repoName)
		// Simple pull via git command
		// We'll attempt to find and load templates regardless
	}

	fmt.Fprintf(os.Stderr, "%s Cloning %s -> %s\n",
		SColor(ColorCyan, "↓"), repoURL, cloneDir)

	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir error: %w", err)
	}

	// We just try to load whatever is in the directory (user must clone manually)
	// For automated git operations, user needs git installed
	// Instead, print instructions
	fmt.Fprintf(os.Stderr, "  %s Run: git clone %s %s\n",
		SColor(ColorYellow, "→"), repoURL, cloneDir)
	fmt.Fprintf(os.Stderr, "  %s Then re-run atomix to load templates\n",
		SColor(ColorYellow, "→"))

	return LoadTemplates(cloneDir)
}

func ListCustomTemplateDirs() {
	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "CUSTOM TEMPLATE SOURCES"))

	home, _ := os.UserHomeDir()
	sources := []struct {
		name string
		path string
	}{
		{"~/.atomix/custom/", filepath.Join(home, ".atomix", "custom")},
		{"~/.atomix/custom-templates/", filepath.Join(home, ".atomix", "custom-templates")},
		{"~/.atomix/templates/", filepath.Join(home, ".atomix", "templates")},
		{"~/.config/atomix/templates/", filepath.Join(home, ".config", "atomix", "templates")},
		{"./custom-templates/", "custom-templates"},
		{"/etc/atomix/templates/", "/etc/atomix/templates"},
	}

	for _, s := range sources {
		exists := dirExists(s.path)
		status := SColor(ColorGreen, "✓ ready")
		if !exists {
			status = SColor(ColorDim, "○ empty")
		}
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			status,
			SColor(ColorBWhite, s.name),
			SColor(ColorDim, "("+s.path+")"),
		)
	}
	fmt.Fprintf(os.Stderr, "\n  %s Create a directory above and drop .yaml files to add custom templates\n",
		SColor(ColorDim, "💡"))
	fmt.Fprintf(os.Stderr, "  %s Or use: atomix --load /path/to/template.yaml\n",
		SColor(ColorDim, "💡"))
	fmt.Fprintf(os.Stderr, "\n")
}

type TemplateCollection struct {
	DefaultTemplates []*Template
	CustomTemplates  []*Template
	AllTemplates     []*Template
	sourceMap        map[string]string
}

func NewTemplateCollection() *TemplateCollection {
	return &TemplateCollection{
		sourceMap: make(map[string]string),
	}
}

func (tc *TemplateCollection) AddFromSource(templates []*Template, source string) {
	for _, t := range templates {
		if _, exists := tc.sourceMap[t.ID]; exists {
			continue
		}
		tc.AllTemplates = append(tc.AllTemplates, t)
		tc.sourceMap[t.ID] = source
		if source == "default" {
			tc.DefaultTemplates = append(tc.DefaultTemplates, t)
		} else {
			tc.CustomTemplates = append(tc.CustomTemplates, t)
		}
	}
}

func (tc *TemplateCollection) GetSource(id string) string {
	return tc.sourceMap[id]
}

func (tc *TemplateCollection) Stats() string {
	return fmt.Sprintf("%d total (%d default, %d custom)",
		len(tc.AllTemplates), len(tc.DefaultTemplates), len(tc.CustomTemplates))
}

func (tc *TemplateCollection) PrintBySource() {
	if noColor {
		fmt.Printf("Default templates: %d\n", len(tc.DefaultTemplates))
		fmt.Printf("Custom templates: %d\n", len(tc.CustomTemplates))
		for _, t := range tc.CustomTemplates {
			fmt.Printf("  %s (from %s)\n", t.ID, tc.sourceMap[t.ID])
		}
		return
	}
	fmt.Printf("\n%s %s\n", SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "TEMPLATE SOURCE BREAKDOWN"))
	fmt.Printf("  %s %s\n", SColor(ColorGreen, fmt.Sprintf("%d default", len(tc.DefaultTemplates))),
		SColor(ColorDim, "templates"))
	fmt.Printf("  %s %s\n", SColor(ColorYellow, fmt.Sprintf("%d custom", len(tc.CustomTemplates))),
		SColor(ColorDim, "templates"))

	if len(tc.CustomTemplates) > 0 {
		fmt.Printf("\n  %s\n", SColor(ColorBWhite, "Custom templates:"))
		for _, t := range tc.CustomTemplates {
			source := tc.sourceMap[t.ID]
			fmt.Printf("    %s %s %s\n",
				SColor(ColorCyan, "•"),
				SColor(ColorBWhite, t.ID),
				SColor(ColorDim, "("+source+")"),
			)
		}
	}
	fmt.Println()
}

func findUserTemplateDirs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".atomix", "custom"),
		filepath.Join(home, ".atomix", "templates"),
		filepath.Join(home, ".config", "atomix", "templates"),
		filepath.Join(home, ".atomix", "custom-templates"),
		"/etc/atomix/templates",
	}
	for _, d := range candidates {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

func EnsureCustomDir() string {
	home, _ := os.UserHomeDir()
	customDir := filepath.Join(home, ".atomix", "custom")
	if err := os.MkdirAll(customDir, 0755); err == nil {
		return customDir
	}
	return ""
}

func PrintCustomTemplateGuide() {
	fmt.Println("Atomix Custom Template Guide")
	fmt.Println("=============================")
	fmt.Println()
	fmt.Println("Write your own checks as YAML. Two block styles are accepted and")
	fmt.Println("can be mixed across files:")
	fmt.Println("  requests:  native Atomix style (method, path, matchers)")
	fmt.Println("  http:      portable style with payload attack types")
	fmt.Println()
	fmt.Println("Minimal working template:")
	fmt.Println("  id: my-first-check")
	fmt.Println("  info:")
	fmt.Println("    name: My First Check")
	fmt.Println("    author: you")
	fmt.Println("    severity: medium          # info, low, medium, high, critical")
	fmt.Println("    description: What this proves when it fires")
	fmt.Println("    tags: myapp, misconfig    # string or [list, form]")
	fmt.Println("  requests:")
	fmt.Println("    - method: GET")
	fmt.Println("      path:")
	fmt.Println("        - \"{{BaseURL}}/admin\"")
	fmt.Println("      matchers:")
	fmt.Println("        - type: word")
	fmt.Println("          words: [\"dashboard\", \"username\"]")
	fmt.Println("          name: admin-panel-exposed")
	fmt.Println()
	fmt.Println("Matcher types: word, regex, status, size, dsl, and, or.")
	fmt.Println("  part: body (default), header, all, status_code")
	fmt.Println("  condition: or (default) or and  |  negative: true inverts")
	fmt.Println("  matchers-condition: and at request level requires all to fire")
	fmt.Println("DSL examples: status_code == 200, contains(body, 'token'),")
	fmt.Println("  !contains(header, 'X-Frame-Options'), duration > 5")
	fmt.Println()
	fmt.Println("Placeholders: {{BaseURL}} {{Hostname}} {{Scheme}} {{Port}}")
	fmt.Println("  {{Random}} plus per-template variables: section.")
	fmt.Println("Payload attacks (http: blocks): attack batteringram, pitchfork")
	fmt.Println("  or clusterbomb with markers like §user§.")
	fmt.Println()
	fmt.Println("Confidence is scored automatically (reflection-only word hits")
	fmt.Println("are low; exact header values and compound matches are high).")
	fmt.Println("Use --min-confidence medium to hide low-signal findings.")
	fmt.Println()
	fmt.Println("Validate before scanning:")
	fmt.Println("  atomix --validate --load ./my-check.yaml")
	fmt.Println("Scan with only your templates:")
	fmt.Println("  atomix -u https://target.example --load ./my-check.yaml")
	fmt.Println("  --load also accepts directories, URLs, and comma-separated lists.")
	fmt.Println()
	fmt.Println("Multiple folders (all .yaml and .yml, recursive):")
	fmt.Println("  atomix -u https://target.example --custom-dir ./team-a,./team-b")
	fmt.Println("  Folders are layered: later folders override earlier ones on")
	fmt.Println("  duplicate template IDs, so custom folders always win over the")
	fmt.Println("  built-in library. Auto-detected folders: ./custom-templates,")
	fmt.Println("  ~/.atomix/custom, and ATOMIX_CUSTOM_TEMPLATES (path-separated).")
	fmt.Println("  atomix -l -v shows which folder each template came from.")
}

func yamlUnmarshal(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}

func parseMultiDocYAML(data []byte) ([]*Template, error) {
	var templates []*Template
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var t Template
		if err := decoder.Decode(&t); err != nil {
			break
		}
		if t.ID == "" {
			continue
		}
		templates = append(templates, &t)
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found in multi-doc YAML")
	}
	return templates, nil
}
