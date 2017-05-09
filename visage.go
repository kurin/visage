// Package visage allows programs to expose files publicly with access control.
package visage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
)

var (
	grants = map[string]*Grant{}
	gmux   = &sync.RWMutex{}
)

func init() {
	go func() {
		for range time.Tick(time.Minute) {
			var rem []string
			gmux.RLock()
			for key, val := range grants {
				if !val.Valid() {
					rem = append(rem, key)
				}
			}
			gmux.RUnlock()
			if len(rem) == 0 {
				continue
			}
			gmux.Lock()
			for _, key := range rem {
				delete(grants, key)
			}
			gmux.Unlock()
		}
	}()
}

// FileSystem specifies the abstraction that backends must satisfy.
type FileSystem interface {
	// String should return a description of the backend provided by this
	// interface.
	String() string

	Open(name string) (io.ReadCloser, error)
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.FileInfo, error)
}

// NewGrant creates a grant to the names files from the given FileSystem.  Each
// file argument passed must be a valid argument to FileSystem.Open().  A zero time
// argument means the grant expires until it is revoked.
//
// NewGrant returns an access token which can be used to retrieve this grant.
func NewGrant(fs FileSystem, files []string, expires time.Time) string {
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
	gmux.Lock()
	grants[auth] = g
	gmux.Unlock()
	return auth
}

// Lookup returns the grant corresponding to the given auth token.
func Lookup(auth string) *Grant {
	gmux.RLock()
	defer gmux.RUnlock()
	return grants[auth]
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
