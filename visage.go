// Package visage allows programs to expose files publicly with access control.
package visage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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
