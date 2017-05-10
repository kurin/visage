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
	s  *Share
	fs FileSystem
}

// FileSystem specifies the abstraction that backends must satisfy.
type FileSystem interface {
	// String is a unique, descriptive identifier for this file system.
	String() string

	Open(path string) (io.ReadCloser, error)
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.FileInfo, error)
}

// A Grant is used to gate access to resources in a FileSystem.  Methods in
// this interface must be safe to call from multiple goroutines simultaneously.
type Grant interface {
	// Valid reports whether this grant can be used to gate access.
	Valid() bool

	// Verify reports whether the given access token is good.
	Verify(Token) bool

	// Allows reports whether this grant gates access to the given path.
	Allows(string) bool
}

// A Token is an identifier that is used by a Grant to verify a request.
type Token interface {

	// Contents should return a bite slice necessary to verify the token.  It
	// must be callable from multiple goroutines simultaneously.
	Contents() []byte
}

type StaticToken string

func (s StaticToken) Contents() []byte { return []byte(s) }

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

func (v *View) access(t Token, path string) bool {
	v.s.mux.Lock()
	defer v.s.mux.Unlock()

	grants, ok := v.s.grants[v.fs.String()]
	if !ok {
		return false
	}
	for _, g := range grants {
		if g.Valid() && g.Verify(t) && g.Allows(path) {
			return true
		}
	}
	return false
}

func (v View) Open(t Token, path string) (io.ReadCloser, error) {
	if !v.access(t, path) {
		return nil, ErrNoAccess
	}
	return v.fs.Open(path)
}

func (v View) ReadDir(t Token, path string) ([]os.FileInfo, error) {
	if !v.access(t, path) {
		return nil, ErrNoAccess
	}
	return v.fs.ReadDir(path)
}
