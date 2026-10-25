// Command netreach answers "which instance ports are reachable from where?"
// for AWS-style VPC snapshots, with hop-by-hop explanations.
package main

import (
	"os"

	"github.com/SlateGitOrg/netreach/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
