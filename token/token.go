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

// Package token implements a token-based OK.
package token

import (
	"context"

	"github.com/google/okay"
)

type ctxKey string

// Verifies returns a new OK that verifies access based on a static token.
func Verifies(ok okay.OK, token string) okay.OK {
	return okay.Verify(ok, func(ctx context.Context) (bool, error) {
		val, ok := ctx.Value(ctxKey(token)).(string)
		if !ok {
			return false, nil
		}
		return val == token, nil
	})
}

// Context returns a new context that contains the given access token.
func Context(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKey(token), token)
}
