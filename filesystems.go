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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

// NewDirectory creates a FileSystem that serves files with the given path at
// the root.
func NewDirectory(path string) FileSystem { return directory(path) }

// Directory exposes a local directory as a FileSystem.
type directory string

func (d directory) String() string { return string(d) }

func (d directory) Open(path string) (io.ReadCloser, error) {
	return os.Open(absPath(string(d), path))
}

func (d directory) Create(path string) (io.WriteCloser, error) {
	return os.Create(absPath(string(d), path))
}

func (d directory) Stat(path string) (os.FileInfo, error) {
	return os.Stat(absPath(string(d), path))
}

func (d directory) ReadDir(path string) ([]os.FileInfo, error) {
	f, err := os.Open(absPath(string(d), path))
	defer f.Close()
	if err != nil {
		return nil, err
	}
	return f.Readdir(0)
}

// NewEncryptedDirectory returns a FileSystem that serves files from the given
// root.  Files are encrypted on disk, and optionally signed.  Files are
// automatically decrypted when read.
func NewEncryptedDirectory(path string, recipients []*openpgp.Entity, signer *openpgp.Entity) FileSystem {
	return &encryptedDir{
		root:       path,
		recipients: recipients,
		signer:     signer,
	}
}

type encryptedDir struct {
	root       string
	recipients []*openpgp.Entity
	signer     *openpgp.Entity
}

func (e *encryptedDir) String() string {
	return fmt.Sprintf("%s - encrypted", e.root)
}

func (e *encryptedDir) Create(path string) (io.WriteCloser, error) {
	f, err := os.Create(absPath(e.root, path))
	if err != nil {
		return nil, err
	}
	return openpgp.Encrypt(f, e.recipients, e.signer, &openpgp.FileHints{IsBinary: true}, nil)
}

type encryptedReader struct {
	c   io.Closer
	md  *openpgp.MessageDetails
	err error
}

func (er *encryptedReader) Read(p []byte) (int, error) {
	if er.err != nil {
		return 0, er.err
	}
	i, err := er.md.UnverifiedBody.Read(p)
	if err == io.EOF && er.md.SignatureError != nil {
		er.err = er.md.SignatureError
		return i, er.err
	}
	er.err = err
	return i, err
}

func (er *encryptedReader) Close() error {
	return er.c.Close()
}

func (e *encryptedDir) Open(path string) (io.ReadCloser, error) {
	f, err := os.Open(absPath(e.root, path))
	if err != nil {
		return nil, err
	}
	var kr openpgp.EntityList
	for _, r := range e.recipients {
		kr = append(kr, r)
	}
	kr = append(kr, e.signer)
	md, err := openpgp.ReadMessage(f, kr, func([]openpgp.Key, bool) ([]byte, error) { return nil, errors.New("not implemented") }, nil)
	if err != nil {
		return nil, err
	}
	return &encryptedReader{
		c:  f,
		md: md,
	}, nil
}

func (e *encryptedDir) Stat(path string) (os.FileInfo, error) {
	return os.Stat(absPath(e.root, path))
}

func (e *encryptedDir) ReadDir(path string) ([]os.FileInfo, error) {
	f, err := os.Open(absPath(e.root, path))
	defer f.Close()
	if err != nil {
		return nil, err
	}
	return f.Readdir(0)
}

// absPath returns a path that is guaranteed to be under root.
func absPath(root, path string) string {
	path = filepath.Join("/", path)
	return filepath.Join(root, path)
}
