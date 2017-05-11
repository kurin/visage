// Package visage allows programs to expose files publicly with access control.
package visage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func New() *Share {
	return &Share{
		fs:     make(map[string]FileSystem),
		grants: make(map[string][]Grant),
	}
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
	// Valid reports whether this grant can be used to gate access.  Grants should
	// never become valid after having been invalid for any period of time.
	Valid() bool

	// Verify reports whether the given access token is good.
	Verify(context.Context) bool

	// Allows reports whether this grant gates access to the given path.
	Allows(string) bool
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

func (s *Share) AddFileSystem(fs FileSystem) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if _, ok := s.fs[fs.String()]; ok {
		return fmt.Errorf("visage: %s: file system already registered", fs.String())
	}
	s.fs[fs.String()] = fs
	return nil
}

func (s *Share) FileSystem(fs string) (FileSystem, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	f, ok := s.fs[fs]
	if !ok {
		return nil, fmt.Errorf("visage: %s: file system not registered")
	}
	return f, nil
}

func (s *Share) View(fs string) (*View, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	f, ok := s.fs[fs]
	if !ok {
		return nil, fmt.Errorf("visage: %s: file system not registered")
	}

	return &View{
		s:  s,
		fs: f,
	}, nil
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

func (v *View) grants() []Grant {
	var grants []Grant
	v.s.mux.Lock()
	for _, g := range v.s.grants[v.fs.String()] {
		grants = append(grants, g)
	}
	v.s.mux.Unlock()
	return grants
}

func (v *View) access(ctx context.Context, path string) bool {
	for _, g := range v.grants() {
		if g.Valid() && g.Verify(ctx) && g.Allows(path) {
			return true
		}
	}
	return false
}

func (v View) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	if !v.access(ctx, path) {
		return nil, ErrNoAccess
	}
	return v.fs.Open(path)
}

func (v View) ReadDir(ctx context.Context, path string) ([]os.FileInfo, error) {
	if !v.access(ctx, path) {
		return nil, ErrNoAccess
	}
	return v.fs.ReadDir(path)
}

func (v View) List(ctx context.Context) ([]string, error) {
	grants := v.grants()

	var files []string
	if err := Walk(v.fs, "", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return err
		}

		if fi.IsDir() {
			return nil
		}

		for _, g := range grants {
			if g.Valid() && g.Verify(ctx) && g.Allows(path) {
				files = append(files, path)
				return nil
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}
