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
