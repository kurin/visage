// Package visage allows programs to expose files publicly with access control.
package visage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var (
	ErrNoAccess = errors.New("access denied")
)

type Share struct {
	fs     map[string]FileSystem
	grants map[string][]Grant
	mux    sync.Mutex
}

type View struct {
	s *Share
}

// FileSystem specifies the abstraction that backends must satisfy.
type FileSystem interface {
	// String is a unique, descriptive identifier for this file system.
	String() string

	Open(path string) (io.ReadCloser, error)
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.FileInfo, error)
}

type Grant interface {
	Valid() bool
	Verify(string, Token) bool
	Grants(string) bool
	Cancel()
}

type Token interface {
	Data() []byte
}

func (s *Share) FileSystems() []string {
	s.mux.Lock()
	defer s.mux.Unlock()

	var rtn []string
	for name := range s.fs {
		rtn = append(rtn, name)
	}
	sort.Strings(rtn)
	return rtn
}

func (s *Share) FileSystem(fs string) FileSystem {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.fs[fs]
}

func (s *Share) AddGrant(fs string, g Grant) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if _, ok := s.fs[fs]; !ok {
		return fmt.Errorf("visage: %s: no such file system", fs)
	}
	s.grants[fs] = append(s.grants[fs], g)
	return nil
}

func (v View) access(fs, path string, t Token) bool {
	v.s.mux.Lock()
	defer v.s.mux.Unlock()

	grants, ok := v.s.grants[fs]
	if !ok {
		return false
	}
	for _, g := range grants {
		if g.Valid() && g.Verify(path, t) {
			return true
		}
	}
	return false
}

func (v View) Open(fs, path string, t Token) (io.ReadCloser, error) {
	if !v.access(fs, path, t) {
		return nil, ErrNoAccess
	}

	v.s.mux.Lock()
	defer v.s.mux.Unlock()

	fsys := v.s.fs[fs]
	return fsys.Open(path)
}

// Directory exposes a local directory as a FileSystem.
type Directory string

func (d Directory) String() string { return string(d) }

func (d Directory) absPath(path string) string {
	dir := string(d)
	p := filepath.Join(dir, filepath.Clean(path))
	if !strings.HasPrefix(p, dir) {
		p = filepath.Join(dir, p)
	}
	return p
}

func (d Directory) Open(path string) (io.ReadCloser, error) {
	return os.Open(d.absPath(path))
}

func (d Directory) Stat(path string) (os.FileInfo, error) {
	return os.Stat(d.absPath(path))
}

func (d Directory) ReadDir(path string) ([]os.FileInfo, error) {
	f, err := os.Open(d.absPath(path))
	defer f.Close()
	if err != nil {
		return nil, err
	}
	return f.Readdir(0)
}
