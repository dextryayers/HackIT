package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type BackupExtension struct {
	Ext      string
	Category string
}

var backupPatterns = []BackupExtension{
	{".bak", "backup"}, {".old", "backup"}, {".tmp", "temp"},
	{".zip", "archive"}, {".tar.gz", "archive"}, {".tar", "archive"},
	{".sql", "database"}, {".dump", "database"},
	{".conf", "config"}, {".config", "config"}, {".cfg", "config"},
	{".save", "save"}, {".backup", "backup"}, {".swp", "vim"},
	{".swo", "vim"}, {".~", "temp"},
	{".orig", "original"}, {".copy", "copy"},
	{".php~", "editor"}, {".php.old", "editor"},
}

func GenerateBackupPaths(paths []string) []string {
	var backupPaths []string
	seen := make(map[string]bool)

	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			continue
		}
		// Skip paths that already look like backups
		isBackup := false
		for _, bp := range backupPatterns {
			if strings.HasSuffix(p, bp.Ext) {
				isBackup = true
				break
			}
		}
		if isBackup {
			continue
		}

		for _, bp := range backupPatterns {
			backupPath := p + bp.Ext
			if !seen[backupPath] {
				seen[backupPath] = true
				backupPaths = append(backupPaths, backupPath)
			}
		}
	}

	return backupPaths
}

func PrintBackupInfo(count int) {
	if count > 0 {
		fmt.Fprintf(color.Output, "%s Added %d backup patterns\n", color.GreenString("[+]"), count)
	}
}
