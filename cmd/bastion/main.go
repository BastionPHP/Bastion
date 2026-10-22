// Command bastion is a local, read-only PHP security tool.
package main

import (
	"os"

	"github.com/BastionPHP/Bastion/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
