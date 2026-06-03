package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	path := flag.String("path", ".", "Directory to scan")
	output := flag.String("output", "", "Output JSON file path (default: stdout only)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("code2api %s (built %s)\n", version, buildDate)
		os.Exit(0)
	}

	if *path == "" {
		fmt.Fprintln(os.Stderr, "Error: -path required")
		flag.Usage()
		os.Exit(1)
	}

	RunAPIFinder(*path, *output, *verbose)
}
