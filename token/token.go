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

// Package token implements a token-based grant.
package token

import (
	"context"

	"github.com/kurin/visage"
)

type grant struct {
	visage.Grant
	t string
}

type ctxKey string

func (g *grant) Valid() bool        { return true }
func (g *grant) Allows(string) bool { return false }

func (g *grant) Verify(ctx context.Context) bool {
	val, ok := ctx.Value(ctxKey(g.t)).(string)
	if !ok {
		return g.Grant.Verify(ctx)
	}
	return val == g.t || g.Grant.Verify(ctx)
}

// Verifies returns a new grant that verifies access based
// on a static token.
func Verifies(g visage.Grant, token string) visage.Grant {
	return &grant{
		Grant: g,
		t:     token,
	}
}

// Context returns a new context that contains the given access token.
func Context(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKey(token), token)
}
