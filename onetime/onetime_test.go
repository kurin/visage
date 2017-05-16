package onetime

import (
	"context"
	"testing"

	"github.com/kurin/visage"
	"github.com/kurin/visage/token"
)

func TestGrant(t *testing.T) {
	ctx := token.Context(context.Background(), "abcd")
	g := Grant(token.Verifies(visage.NewGrant(), "abcd"))

	if !g.Valid() {
		t.Errorf("Valid(): got false, want true")
	}

	if g.Verify(context.Background()) {
		t.Errorf("Verify(context.Background()): got true, want false")
	}

	if !g.Valid() {
		t.Errorf("Valid(): got false, want true")
	}

	if !g.Verify(ctx) {
		t.Errorf("Verify(): got false, want true")
	}

	if g.Valid() {
		t.Errorf("Verify(): got true, want false")
	}
}
