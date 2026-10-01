package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// agentConfig says how to hand base URLs to an agent that doesn't honor env vars alone (its own
// settings can override the environment). Add an entry only once it is verified against the real agent.
type agentConfig struct {
	flag    string // inserted right after the command, followed by the settings file path
	jsonKey string // the file is {"<jsonKey>": {ENV_VAR: url, ...}}
}

// agentConfigs is keyed by the command's basename. The wrapper can't see inside `sh -c`, so a
// command run that way isn't matched; the no-traffic warning covers that case.
var agentConfigs = map[string]agentConfig{
	"claude": {flag: "--settings", jsonKey: "env"},
}

// injectAgentConfig returns cmdArgs with the agent's settings flag added when the command is a
// known agent, plus a cleanup that removes the settings file's directory (call it on every exit
// path). The file holds the base URLs, which include the session token, so it is 0600 in a
// 0700 directory and its path, never the URL, goes on the command line. Commands that aren't in
// the table, --no-agent-config, and a user-supplied flag of the same name all leave cmdArgs as is.
func injectAgentConfig(cmdArgs []string, env map[string]string, disabled bool, stderr io.Writer) ([]string, func(), error) {
	noop := func() {}
	tc, ok := agentConfigs[filepath.Base(cmdArgs[0])]
	if disabled || !ok {
		return cmdArgs, noop, nil
	}
	for _, a := range cmdArgs[1:] {
		if a == tc.flag || strings.HasPrefix(a, tc.flag+"=") {
			_, _ = fmt.Fprintf(stderr, "nospy: notice: %s already given; not adding nospy's base URL settings. If those settings choose their own base URL, traffic will bypass nospy.\n", tc.flag)
			return cmdArgs, noop, nil
		}
	}
	data, err := json.Marshal(map[string]map[string]string{tc.jsonKey: env})
	if err != nil {
		return nil, noop, err
	}
	dir, err := os.MkdirTemp("", "nospy-") // mode 0700
	if err != nil {
		return nil, noop, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return nil, noop, err
	}
	out := append([]string{cmdArgs[0], tc.flag, path}, cmdArgs[1:]...)
	return out, cleanup, nil
}
