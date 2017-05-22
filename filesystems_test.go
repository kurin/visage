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
