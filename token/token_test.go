package token

import (
	"context"
	"testing"

	"github.com/kurin/visage"
)

func TestToken(t *testing.T) {
	table := []struct {
		desc     string
		grant    visage.Grant
		ctx      context.Context
		verifies bool
	}{
		{
			desc:  "empty context, empty grant",
			grant: visage.NewGrant(),
			ctx:   context.Background(),
		},
		{
			desc:  "empty context, token",
			grant: visage.NewGrant(),
			ctx:   Context(context.Background(), "foo"),
		},
		{
			desc:  "wrong token",
			grant: Verifies(visage.NewGrant(), "a"),
			ctx:   Context(context.Background(), "b"),
		},
		{
			desc:     "right token",
			grant:    Verifies(visage.NewGrant(), "a"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (ctx), correct first",
			grant:    Verifies(visage.NewGrant(), "a"),
			ctx:      Context(Context(context.Background(), "b"), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (ctx), correct second",
			grant:    Verifies(visage.NewGrant(), "a"),
			ctx:      Context(Context(context.Background(), "a"), "b"),
			verifies: true,
		},
		{
			desc:     "two tokens (grant), correct first",
			grant:    Verifies(Verifies(visage.NewGrant(), "a"), "b"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (grant), correct second",
			grant:    Verifies(Verifies(visage.NewGrant(), "b"), "a"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
	}

	for _, ent := range table {
		if ent.grant.Verify(ent.ctx) != ent.verifies {
			t.Errorf("%s: got %v, want %v", ent.desc, ent.grant.Verify(ent.ctx), ent.verifies)
		}
	}
}
