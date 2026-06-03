package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	path := flag.String("path", ".", "Directory to scan")
	output := flag.String("output", "", "Output JSON file path (default: stdout only)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "Error: -path required")
		flag.Usage()
		os.Exit(1)
	}

	RunAPIFinder(*path, *output, *verbose)
}
