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

package visage

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

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

func (d Directory) Create(path string) (io.WriteCloser, error) {
	return os.Create(d.absPath(path))
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
