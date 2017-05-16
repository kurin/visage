// Package onetime provides a grant type that can be used exactly once.
package onetime

import (
	"context"
	"sync"

	"github.com/kurin/visage"
)

type grant struct {
	visage.Grant
	c visage.CancelFunc
	sync.Mutex
}

func (g *grant) Verify(ctx context.Context) bool {
	g.Lock()
	defer g.Unlock()

	t := g.Grant.Verify(ctx)
	if t {
		g.c()
	}
	return t
}

// Grant wraps the given grant and returns a new grant that is invalidated as
// soon as Verify is called.
func Grant(g visage.Grant) visage.Grant {
	g, c := visage.WithCancel(g)
	return &grant{
		Grant: g,
		c:     c,
	}
}
