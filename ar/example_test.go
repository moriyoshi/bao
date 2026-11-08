package ar_test

import (
	"fmt"
	"log"

	"github.com/moriyoshi/bao/ar"
)

func ExampleParse() {
	// In an application, data can come from os.ReadFile or another byte source.
	data := []byte(fmt.Sprintf("!<arch>\n%-16s%-12d%-6d%-6d%-8s%-10d`\nhello\n",
		"hello.txt/", 0, 0, 0, "100644", 5))
	members, err := ar.Parse(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range members {
		if m.Kind == ar.Regular {
			fmt.Printf("%s: %s\n", m.Name, m.Data)
		}
	}
	// Output: hello.txt: hello
}
