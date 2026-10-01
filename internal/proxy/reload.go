package proxy

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// reloadable caches a value built from files and rebuilds it when any file's mtime or size
// changes (Secret rotation, cert-manager renewal). A rebuild that fails keeps the previous
// value and reports the error once per change.
type reloadable[T any] struct {
	paths []string
	load  func() (T, error)
	onErr func(error)

	mu  sync.Mutex
	sig string
	val T
}

// newReloadable builds the first value and fails if it can't.
func newReloadable[T any](paths []string, load func() (T, error), onErr func(error)) (*reloadable[T], error) {
	sig := fileSig(paths)
	v, err := load()
	if err != nil {
		return nil, err
	}
	return &reloadable[T]{paths: paths, load: load, onErr: onErr, sig: sig, val: v}, nil
}

func (r *reloadable[T]) get() T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sig := fileSig(r.paths); sig != r.sig {
		r.sig = sig
		if v, err := r.load(); err == nil {
			r.val = v
		} else if r.onErr != nil {
			r.onErr(err)
		}
	}
	return r.val
}

// fileSig identifies the current state of the files by mtime and size. os.Stat follows
// symlinks, so the atomic symlink swap of a mounted Secret changes it.
func fileSig(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%d:%d;", fi.ModTime().UnixNano(), fi.Size())
		} else {
			b.WriteString("missing;")
		}
	}
	return b.String()
}
