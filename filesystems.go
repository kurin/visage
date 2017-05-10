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
