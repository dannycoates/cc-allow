package main

import (
	"os"

	"mvdan.cc/sh/v3/syntax"
)

func main() {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(os.Stdin, "")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	syntax.DebugPrint(os.Stdout, f)
}
