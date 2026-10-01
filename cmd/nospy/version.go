package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// versionString is e.g. "nospy 1.2.3 (a1b2c3d-dirty, go1.27.1, darwin/arm64)". The commit
// comes from the build's VCS stamp, which is absent for `go run` and some test builds.
func versionString() string {
	bi, _ := debug.ReadBuildInfo()
	return formatVersion(version, bi)
}

func formatVersion(ver string, bi *debug.BuildInfo) string {
	commit := "unknown"
	if bi != nil {
		rev, dirty := "", false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if rev != "" {
			commit = rev[:min(len(rev), 7)]
			if dirty {
				commit += "-dirty"
			}
		}
	}
	return fmt.Sprintf("nospy %s (%s, %s, %s/%s)", ver, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
