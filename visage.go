//   Copyright 2017 Google
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

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

	"github.com/google/okay"
)

var (
	ErrNoAccess = errors.New("access denied")
)

type Share struct {
	fs  map[string]FileSystem
	oks map[string][]okay.OK
	mux sync.Mutex
}

func New() *Share {
	return &Share{
		fs:  make(map[string]FileSystem),
		oks: make(map[string][]okay.OK),
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

	// Open the named file for reading.
	Open(path string) (io.ReadCloser, error)

	// Create should return a writer for the given path.  It is left to specific
	// implementations whether they want to allow users to overwrite existing files,
	// or to return an error, or to implement something more sophisticated such as
	// versioning.
	Create(path string) (io.WriteCloser, error)

	// Stat should behave as os.Stat.  If the underlying file system implements
	// symlinks, Stat should follow them and treat them as directories.
	Stat(path string) (os.FileInfo, error)

	// ReadDir should return all the entries in a given directory.
	ReadDir(path string) ([]os.FileInfo, error)
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
		return nil, fmt.Errorf("visage: %s: file system not registered", fs)
	}
	return f, nil
}

func (s *Share) View(fs string) (*View, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	f, ok := s.fs[fs]
	if !ok {
		return nil, fmt.Errorf("visage: %s: file system not registered", fs)
	}

	return &View{
		s:  s,
		fs: f,
	}, nil
}

func (s *Share) AddOK(fs string, ok okay.OK) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if _, ok := s.fs[fs]; !ok {
		return fmt.Errorf("visage: %s: no such file system", fs)
	}
	s.oks[fs] = append(s.oks[fs], ok)
	return nil
}

func (v *View) oks() []okay.OK {
	var oks []okay.OK
	v.s.mux.Lock()
	for _, ok := range v.s.oks[v.fs.String()] {
		oks = append(oks, ok)
	}
	v.s.mux.Unlock()
	return oks
}

func (v *View) access(ctx context.Context, path string) bool {
	ok, _ := okay.Check(ctx, path, v.oks()...)
	return ok
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
	oks := v.oks()

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

		if ok, _ := okay.Check(ctx, path, oks...); ok {
			files = append(files, path)
			return nil
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}
