//go:build race

package redact

// raceEnabled is true under -race, which makes regex scanning ~15x slower.
const raceEnabled = true
