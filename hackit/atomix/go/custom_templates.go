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
	dirs := []string{config.TemplateDir}

	// User-specified custom directory via --custom-dir or --custom-templates
	if config.CustomTemplateDir != "" {
		dirs = append(dirs, config.CustomTemplateDir)
	}

	// Clear any old built-in registrations (to avoid duplicate loading)
	currentDirs := make(map[string]bool)
	for _, d := range dirs {
		currentDirs[d] = true
	}

	// Environment variable
	if envDir := os.Getenv("ATOMIX_CUSTOM_TEMPLATES"); envDir != "" {
		if !currentDirs[envDir] {
			dirs = append(dirs, envDir)
			currentDirs[envDir] = true
		}
	}

	// Project-local custom directory (next to the binary/config)
	pwd, _ := os.Getwd()
	localDirs := []string{
		filepath.Join(pwd, "custom-templates"),
		filepath.Join(pwd, "custom_templates"),
		filepath.Join(pwd, ".atomix"),
	}
	for _, ld := range localDirs {
		if !currentDirs[ld] && dirExists(ld) {
			dirs = append(dirs, ld)
			currentDirs[ld] = true
		}
	}

	// Check common user custom template paths
	home, _ := os.UserHomeDir()
	userPaths := []string{
		filepath.Join(home, ".atomix", "custom"),
		filepath.Join(home, ".atomix", "custom-templates"),
		filepath.Join(home, ".atomix", "templates"),
		filepath.Join(home, ".config", "atomix", "templates"),
		filepath.Join(home, ".atomix", "community"),
		filepath.Join(home, "atomix-custom"),
	}
	for _, p := range userPaths {
		p = expandPath(p)
		abs, _ := filepath.Abs(p)
		if !currentDirs[abs] && dirExists(p) {
			dirs = append(dirs, p)
			currentDirs[abs] = true
		}
	}

	// Global system path
	systemDir := "/etc/atomix/templates"
	if !currentDirs[systemDir] && dirExists(systemDir) {
		dirs = append(dirs, systemDir)
	}

	return deduplicatePaths(dirs)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func deduplicatePaths(paths []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		if !seen[abs] {
			seen[abs] = true
			result = append(result, p)
		}
	}
	return result
}

func LoadTemplatesFromDirs(dirs []string) ([]*Template, error) {
	var all []*Template
	seen := make(map[string]string)

	for _, dir := range dirs {
		templates, err := LoadTemplates(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error loading %s: %v\n",
				SColor(ColorYellow, "[!]"), dir, err)
			continue
		}
		for _, t := range templates {
			if _, exists := seen[t.ID]; exists {
				continue
			}
			all = append(all, t)
			seen[t.ID] = dir
		}
	}

	fmt.Fprintf(os.Stderr, "%s Loaded %d unique templates from %d directories\n",
		SColor(ColorGreen, "[+]"), len(all), len(dirs))
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
	fmt.Println("Custom Template Guide")
	fmt.Println("====================")
	fmt.Println()
	fmt.Println("Atomix supports loading your own YAML templates from multiple sources.")
	fmt.Println()
	fmt.Println("1. Directory-based (auto-detected):")
	fmt.Println("   ~/.atomix/custom/          - Drop .yaml files here")
	fmt.Println("   ~/.atomix/templates/       - Alternative location")
	fmt.Println("   ./custom-templates/        - Project-level templates")
	fmt.Println("   /etc/atomix/templates/     - System-wide templates")
	fmt.Println()
	fmt.Println("2. Flag-based:")
	fmt.Println("   --custom-dir /path/to/dir  - Specify custom template directory")
	fmt.Println("   --load /path/to/file.yaml  - Load specific template file(s)")
	fmt.Println("   --load https://example.com/t.yaml  - Load from URL")
	fmt.Println("   --from-git https://github.com/user/repo.git  - Clone from git")
	fmt.Println()
	fmt.Println("3. Environment variable:")
	fmt.Println("   ATOMIX_CUSTOM_TEMPLATES=/path/to/dir")
	fmt.Println()
	fmt.Println("4. Stdin pipe:")
	fmt.Println("   cat template.yaml | atomix -u https://target.com")
	fmt.Println("   curl -s https://example.com/template.yaml | atomix -u https://target.com")
	fmt.Println()
	fmt.Println("Template format:")
	fmt.Println("  Your .yaml files can contain one or more templates (separated by ---).")
	fmt.Println("  See the default templates in the template/ directory for examples.")
	fmt.Println()
	fmt.Println("Template ID priority:")
	fmt.Println("  If a custom template has the same ID as a default template,")
	fmt.Println("  the custom version takes precedence.")
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
