package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

var (
	stdout   = bufio.NewWriter(os.Stdout)
	outputMu sync.Mutex
)

func writeOutput(format string, args ...interface{}) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintf(stdout, format, args...)
	stdout.Flush()
}
