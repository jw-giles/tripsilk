//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Tripsilk self-test checks Windows features. Run it on Windows.")
	os.Exit(2)
}
