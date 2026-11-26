// Command moley is the Moley daemon, CLI and browser native host in one
// binary. See `moley help`.
package main

import (
	"os"

	"moley/internal/cli"
)

func main() {
	args := os.Args[1:]
	if cli.IsNativeHostLaunch(args) {
		os.Exit(cli.NativeHost(args[0], os.Stdin, os.Stdout))
	}
	os.Exit(cli.Run(args, &cli.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}))
}
