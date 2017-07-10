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

	"github.com/google/okay"
)

func TestToken(t *testing.T) {
	table := []struct {
		desc     string
		ok       okay.OK
		ctx      context.Context
		verifies bool
	}{
		{
			desc: "empty context, empty ok",
			ok:   okay.New(),
			ctx:  context.Background(),
		},
		{
			desc: "empty context, token",
			ok:   okay.New(),
			ctx:  Context(context.Background(), "foo"),
		},
		{
			desc: "wrong token",
			ok:   Verifies(okay.New(), "a"),
			ctx:  Context(context.Background(), "b"),
		},
		{
			desc:     "right token",
			ok:       Verifies(okay.New(), "a"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (ctx), correct first",
			ok:       Verifies(okay.New(), "a"),
			ctx:      Context(Context(context.Background(), "b"), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (ctx), correct second",
			ok:       Verifies(okay.New(), "a"),
			ctx:      Context(Context(context.Background(), "a"), "b"),
			verifies: true,
		},
		{
			desc:     "two tokens (ok), correct first",
			ok:       Verifies(Verifies(okay.New(), "a"), "b"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
		{
			desc:     "two tokens (ok), correct second",
			ok:       Verifies(Verifies(okay.New(), "b"), "a"),
			ctx:      Context(context.Background(), "a"),
			verifies: true,
		},
	}

	for _, ent := range table {
		if v, _ := ent.ok.Verify(ent.ctx); v != ent.verifies {
			t.Errorf("%s: got %v, want %v", ent.desc, v, ent.verifies)
		}
	}
}
