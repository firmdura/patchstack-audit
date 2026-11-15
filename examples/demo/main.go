// Command demo generates inputs for the original two-patch example.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/firmdura/patchstack-audit/examples/demo/fixtures"
)

func main() {
	output := flag.String("output", "", "new directory for the example inputs; its parent must already exist")
	flag.Parse()
	if flag.NArg() != 0 || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./examples/demo --output /tmp/demo-inputs")
		os.Exit(2)
	}
	if err := fixtures.Generate(*output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(*output)
}
