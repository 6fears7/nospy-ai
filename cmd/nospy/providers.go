package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"nospyai/internal/proxy"
)

// runProviders lists the built-in provider table.
func runProviders(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if args[0] == "-h" || args[0] == "--help" {
			commands["providers"].printHelp(stdout)
			return 0
		}
		return usageError("providers", stderr, "unexpected argument %q", args[0])
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tAPI\tUPSTREAM"); err != nil {
		return exitFail
	}
	for _, p := range proxy.Providers {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Name, p.API, p.Upstream); err != nil {
			return exitFail
		}
	}
	if err := tw.Flush(); err != nil {
		return exitFail
	}
	return 0
}
