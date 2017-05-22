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

import "testing"

func TestAbsPath(t *testing.T) {
	table := []struct {
		root string
		path string
		want string
	}{
		{
			root: "/",
			path: "thing",
			want: "/thing",
		},
		{
			root: "/a/tmp/dir",
			path: "../../../root/secret",
			want: "/a/tmp/dir/root/secret",
		},
		{
			root: "/a/tmp/dir",
			path: "/../../../root/secret",
			want: "/a/tmp/dir/root/secret",
		},
		{
			root: "",
			path: "../../a/test",
			want: "/a/test",
		},
	}
	for _, ent := range table {
		got := absPath(ent.root, ent.path)
		if got != ent.want {
			t.Errorf("absPath(%q, %q): got %q, want %q", ent.root, ent.path, got, ent.want)
		}
	}
}
