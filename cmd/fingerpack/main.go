package main

import (
	"flag"
	"fmt"
	"os"

	fingerprintsdk "github.com/qiwentaidi/fingers/lib"
)

func main() {
	input := flag.String("input", "", "path to finger yaml")
	output := flag.String("output", "", "path to output bundle")
	password := flag.String("password", "", "optional bundle password")
	flag.Parse()

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: fingerpack -input finger.yaml -output finger.fpb [-password secret]")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input failed: %v\n", err)
		os.Exit(1)
	}

	bundle, err := fingerprintsdk.PackFingerprintYAML(raw, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack bundle failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, bundle, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output failed: %v\n", err)
		os.Exit(1)
	}
}
