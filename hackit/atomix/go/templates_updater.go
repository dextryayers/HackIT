package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TemplateHubURL is optional: set ATOMIX_TEMPLATE_HUB to a .tar.gz URL with
// the same layout as the local template directory to enable remote refresh.
// When empty, --update performs a local library refresh (reload + validate).
var TemplateHubURL = os.Getenv("ATOMIX_TEMPLATE_HUB")

func UpdateTemplates(targetDir string, force bool) error {
	if strings.TrimSpace(TemplateHubURL) != "" {
		return updateFromHub(targetDir, TemplateHubURL, force)
	}
	return refreshLocalLibrary(targetDir)
}

// refreshLocalLibrary reloads every template and reports health.
// It is the default --update behavior and works fully offline.
func refreshLocalLibrary(targetDir string) error {
	fmt.Fprintf(os.Stderr, "%s Refreshing local template library in %s...\n",
		SColor(ColorBCyan, "►"), targetDir)
	templates, err := LoadTemplates(targetDir)
	if err != nil {
		return fmt.Errorf("load failed: %w", err)
	}
	valid, invalid := 0, 0
	for _, t := range templates {
		if len(ValidateTemplate(t)) == 0 {
			valid++
		} else {
			invalid++
		}
	}
	fmt.Fprintf(os.Stderr, "%s Library: %d templates (%d valid, %d need attention)\n",
		SColor(ColorGreen, "[+]"), len(templates), valid, invalid)
	return nil
}

func updateFromHub(targetDir, hubURL string, force bool) error {
	fmt.Fprintf(os.Stderr, "%s Downloading templates from configured hub...\n",
		SColor(ColorBCyan, "►"))

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(hubURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip error: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	count := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar error: %w", err)
		}

		if !strings.HasSuffix(header.Name, ".yaml") && !strings.HasSuffix(header.Name, ".yml") {
			continue
		}
		if strings.Contains(header.Name, "/.github/") {
			continue
		}
		if strings.Contains(header.Name, "/contrib/") {
			continue
		}

		// Strip top-level dir
		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		relPath := parts[1]

		targetPath := filepath.Join(targetDir, relPath)
		targetDirPath := filepath.Dir(targetPath)

		// Skip if exists and not forced
		if !force {
			if _, err := os.Stat(targetPath); err == nil {
				continue
			}
		}

		if err := os.MkdirAll(targetDirPath, 0755); err != nil {
			return fmt.Errorf("mkdir error: %w", err)
		}

		outFile, err := os.Create(targetPath)
		if err != nil {
			return fmt.Errorf("create error: %w", err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("write error: %w", err)
		}
		outFile.Close()
		count++
	}

	fmt.Fprintf(os.Stderr, "%s Updated %d templates in %s\n",
		SColor(ColorGreen, "[+]"), count, targetDir)
	return nil
}

func ListTemplateSources() []string {
	sources := []string{
		"atomix-library (built-in)",
		"custom (local)",
	}
	return sources
}

func ValidateTemplatePaths(paths []string) (valid, invalid int) {
	for _, p := range paths {
		t, err := LoadTemplate(p)
		if err != nil || t == nil {
			invalid++
			continue
		}
		valid++
	}
	return
}
