package visage

import "time"

type staticFileList struct {
	token   string
	files   map[string]bool
	expires time.Time
	now     func() time.Time
}

// StaticFileList returns a Grant that will allow access to the given files if
// the token matches.  It will expire after the given time, or never if expires is
// the zero time.
func StaticFileList(token string, files []string, expires time.Time) Grant {
	s := &staticFileList{
		token:   token,
		files:   make(map[string]bool),
		expires: expires,
		now:     time.Now,
	}
	for _, f := range files {
		s.files[f] = true
	}
	return s
}

func (s *staticFileList) Valid() bool {
	return s.expires.IsZero() || s.now().After(s.expires)
}

func (s *staticFileList) Verify(t Token) bool {
	return string(t.Contents()) == s.token
}

func (s *staticFileList) Allows(path string) bool {
	return s.files[path]
}
