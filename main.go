package main

import (
	"fmt"
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func main() {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(os.Stdin, "")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}

	fmt.Println("\n--- Commands ---")
	syntax.Walk(f, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			if len(call.Args) > 0 {
				cmd := wordToString(call.Args[0])
				fmt.Println(cmd)
			}
		}
		return true
	})
}

func wordToString(word *syntax.Word) string {
	var parts []string
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			parts = append(parts, p.Value)
		case *syntax.SglQuoted:
			parts = append(parts, p.Value)
		case *syntax.DblQuoted:
			parts = append(parts, wordPartsToString(p.Parts))
		case *syntax.ParamExp:
			if p.Param != nil {
				parts = append(parts, "$"+p.Param.Value)
			}
		default:
			parts = append(parts, fmt.Sprintf("<%T>", p))
		}
	}
	return strings.Join(parts, "")
}

func wordPartsToString(wps []syntax.WordPart) string {
	var parts []string
	for _, part := range wps {
		switch p := part.(type) {
		case *syntax.Lit:
			parts = append(parts, p.Value)
		case *syntax.ParamExp:
			if p.Param != nil {
				parts = append(parts, "$"+p.Param.Value)
			}
		default:
			parts = append(parts, fmt.Sprintf("<%T>", p))
		}
	}
	return strings.Join(parts, "")
}
