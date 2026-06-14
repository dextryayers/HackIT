package main

import (
	"fmt"
	"os"
)

func PrintBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "   ▒▓█ PERMISSION OR PRISON. CHOOSE WISELY. █▓▒"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "   █████╗ ████████╗ ██████╗ ███╗   ███╗██╗██╗  ██╗"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║╚██╗██╔╝"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ███████║   ██║   ██║   ██║██╔████╔██║██║ ╚███╔╝ "))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║ ██╔██╗ "))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║██╔╝ ██╗"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  ┌─────────────────────────────────────────────────┐"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  │ HackIT V2.1 - By: AniipID                       │"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  │ Vulnerability Toolkit – Nailed It               │"))
	fmt.Fprintf(os.Stderr, "  %s\n", SColor(ColorBCyan, "  └─────────────────────────────────────────────────┘"))
	fmt.Fprintf(os.Stderr, "\n")
}
