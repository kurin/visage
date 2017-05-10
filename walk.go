package visage

import (
	"os"
	"path/filepath"
)

func walk(fs FileSystem, path string, fi os.FileInfo, fn filepath.WalkFunc) error {
	err := fn(path, fi, nil)
	if err != nil {
		if fi.IsDir() && err == filepath.SkipDir {
			return nil
		}
		return err
	}
	if !fi.IsDir() {
		return nil
	}
	fis, err := fs.ReadDir(path)
	if err != nil {
		return fn(path, fi, err)
	}
	for _, fi := range fis {
		err := walk(fs, filepath.Join(path, fi.Name()), fi, fn)
		if err != nil {
			if err != filepath.SkipDir || !fi.IsDir() {
				return err
			}
		}
	}
	return nil
}

// Walk implements filepath.Walk for the given directory in the given
// file system, except that it does not know about symlinks because
// FileSystem does not implement Lstat.
func Walk(fs FileSystem, root string, fn filepath.WalkFunc) error {
	fi, err := fs.Stat(root)
	var fnErr error
	if err != nil {
		fnErr = fn(root, nil, err)
	} else {
		fnErr = walk(fs, root, fi, fn)
	}
	if fnErr == filepath.SkipDir {
		return nil
	}
	return fnErr
}
