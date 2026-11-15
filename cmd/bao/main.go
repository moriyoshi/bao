// bao translates native objects into packages for Go's internal linker.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/moriyoshi/bao/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bao:", err)
		os.Exit(cli.ExitCode(err))
	}
}
