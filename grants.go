package visage

import (
	"strings"
	"sync/atomic"
	"time"
)

type nullGrant struct{}

func (n nullGrant) Valid() bool        { return true }
func (n nullGrant) Verify(Token) bool  { return false }
func (n nullGrant) Allows(string) bool { return false }

// NewGrant returns a new grant.  The returned grant is always valid, but
// verifies no tokens and allows no paths.
func NewGrant() Grant {
	return nullGrant{}
}

type staticGrant struct {
	Grant
	token string
}

func (s staticGrant) Verify(t Token) bool {
	return string(t.Contents()) == s.token || s.Grant.Verify(t)
}

// WithStaticToken wraps the parent grant, returning a new grant that verifies
// token.  It does not overwrite other methods of access;
// WithStaticToken(WithStaticToken(g, "a"), "b") would accept both "a" and "b".
func WithStaticToken(g Grant, token string) Grant {
	return staticGrant{
		Grant: g,
		token: token,
	}
}

type fileListGrant struct {
	Grant
	files map[string]bool
}

func (f *fileListGrant) Allows(p string) bool {
	return f.files[p] || f.Grant.Allows(p)
}

// WithAllowFileList wraps the parent grant, returning a new grant that allows
// any of the given paths.  It does so in addition to any paths already allowed
// by g.
func WithAllowFileList(g Grant, paths []string) Grant {
	f := &fileListGrant{
		Grant: g,
		files: make(map[string]bool),
	}
	for _, p := range paths {
		f.files[p] = true
	}
	return f
}

type prefixGrant struct {
	Grant
	pfx string
}

func (p prefixGrant) Allows(path string) bool {
	return strings.HasPrefix(path, p.pfx) || p.Grant.Allows(path)
}

// WithAllowPrefix wraps the parent grant, returning a new grant that allows
// any paths with the given prefix.  It does so in addition to any paths already
// allowed by g.
func WithAllowPrefix(g Grant, prefix string) Grant {
	return prefixGrant{
		Grant: g,
		pfx:   prefix,
	}
}

type cancelGrant struct {
	Grant
	c int32
}

func (cg *cancelGrant) Valid() bool {
	i := atomic.LoadInt32(&cg.c)
	return i == 0 && cg.Grant.Valid()
}

// CancelFunc immediately marks the associated grant invalid.  Calls after the
// first have no effect.
type CancelFunc func()

// WithCancel returns a grant that will expire when CancelFunc is called.
func WithCancel(g Grant) (Grant, CancelFunc) {
	cg := &cancelGrant{
		Grant: g,
	}
	return cg, func() { atomic.StoreInt32(&cg.c, 1) }
}

type expiresGrant struct {
	Grant
	exp time.Time
	now func() time.Time
}

func (e *expiresGrant) Valid() bool {
	return e.now().Before(e.exp) && e.Grant.Valid()
}

// WithDeadline returns a grant that will expire once the deadline has passed.
func WithDeadline(g Grant, deadline time.Time) Grant {
	return &expiresGrant{
		Grant: g,
		exp:   deadline,
		now:   time.Now,
	}
}

// WithTimeout returns a grant that will time out after the given duration.
func WithTimeout(g Grant, timeout time.Duration) Grant {
	return &expiresGrant{
		Grant: g,
		exp:   time.Now().Add(timeout),
		now:   time.Now,
	}
}