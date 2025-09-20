package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"example.com/ch10gate/examples/internal/samples"
)

func main() {
	outDir := flag.String("out", ".", "output directory for generated sample files")
	flag.Parse()

	if err := samples.WriteFiles(*outDir); err != nil {
		log.Fatalf("generate samples: %v", err)
	}

	fmt.Printf("wrote %s and %s\n",
		filepath.Join(*outDir, samples.Chapter10FileName),
		filepath.Join(*outDir, samples.TMATSFileName))
}
