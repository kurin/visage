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
	"time"

	uuid "github.com/satori/go.uuid"
)

type Server struct {
	grants map[string]*Grant
	gmux   sync.RWMutex
	done   chan struct{}
}

func New() *Server {
	s := &Server{
		grants: make(map[string]*Grant),
		done:   make(chan struct{}),
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				var rem []string
				s.gmux.RLock()
				for key, val := range s.grants {
					if !val.Valid() {
						rem = append(rem, key)
					}
				}
				s.gmux.RUnlock()
				if len(rem) == 0 {
					continue
				}
				s.gmux.Lock()
				for _, key := range rem {
					delete(s.grants, key)
				}
				s.gmux.Unlock()
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *Server) Shutdown() {
	close(s.done)
	return
}

// FileSystem specifies the abstraction that backends must satisfy.
type FileSystem interface {
	// String should return a description of the backend provided by this
	// interface.
	String() string

	Open(path string) (io.ReadCloser, error)
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.FileInfo, error)
}

// NewGrant creates a grant to the names files from the given FileSystem.  Each
// file argument passed must be a valid argument to FileSystem.Open().  A zero time
// argument means the grant expires until it is revoked.
//
// NewGrant returns an access token which can be used to retrieve this grant.
func (s *Server) NewGrant(fs FileSystem, files []string, expires time.Time) string {
	g := &Grant{
		fs:    fs,
		exp:   expires,
		now:   time.Now,
		files: make(map[string]bool),
	}
	for _, f := range files {
		g.files[f] = true
	}
	auth := uuid.NewV4().String()
	s.gmux.Lock()
	s.grants[auth] = g
	s.gmux.Unlock()
	return auth
}

// Lookup returns the grant corresponding to the given auth token.
func (s *Server) Lookup(auth string) *Grant {
	s.gmux.RLock()
	defer s.gmux.RUnlock()
	return s.grants[auth]
}

// Grant represents an access grant.
type Grant struct {
	fs      FileSystem
	exp     time.Time
	now     func() time.Time
	revoked bool
	files   map[string]bool
	fmux    sync.Mutex
}

// Valid reports whether the given grant is valid.
func (g *Grant) Valid() bool {
	return g != nil && !g.exp.IsZero() && g.exp.After(g.now()) && !g.revoked
}

// Open returns an io.ReadCloser for the given file if it is in the grant.
func (g *Grant) Open(path string) (io.ReadCloser, error) {
	g.fmux.Lock()
	defer g.fmux.Unlock()
	if !g.files[path] {
		return nil, fmt.Errorf("%s: access grant not valid", path)
	}
	rc, err := g.fs.Open(path)
	if err != nil {
		return nil, err
	}
	return &wrappedReader{
		r: rc,
		g: g,
	}, nil
}

// List enumerates all the files in the grant.
func (g *Grant) List() []string {
	var rtn []string
	g.fmux.Lock()
	defer g.fmux.Unlock()
	for key := range g.files {
		rtn = append(rtn, key)
	}
	sort.Strings(rtn)
	return rtn
}

// Stat returns info for a given file.
func (g *Grant) Stat(path string) (os.FileInfo, error) {
	g.fmux.Lock()
	defer g.fmux.Unlock()

	if !g.files[path] {
		return nil, fmt.Errorf("%s: access grant not valid", path)
	}

	return g.Stat(path)
}

type wrappedReader struct {
	r io.ReadCloser
	g *Grant
}

func (wr *wrappedReader) Read(p []byte) (int, error) {
	if !wr.g.Valid() {
		return 0, errors.New("access grant expired")
	}
	return wr.r.Read(p)
}

func (wr *wrappedReader) Close() error {
	return wr.r.Close()
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
