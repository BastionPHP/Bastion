package version

import "testing"

func TestParsePHP(t *testing.T) {
	cases := []struct {
		in, upstream, branch, extra string
	}{
		{"8.3.6", "8.3.6", "8.3", ""},
		{"8.6.0RC4", "8.6.0RC4", "8.6", ""},
		{"8.1.2-1ubuntu2.28", "8.1.2", "8.1", "-1ubuntu2.28"},
		{"7.4.31-dev", "7.4.31dev", "7.4", ""},
		{"5.5.9-1ubuntu4.29", "5.5.9", "5.5", "-1ubuntu4.29"},
		{"8.2.7-1+0~20230609.24+debian11~1.gbp7b3dbd", "8.2.7", "8.2", "-1+0~20230609.24+debian11~1.gbp7b3dbd"},
	}
	for _, c := range cases {
		v, err := ParsePHP(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if v.Upstream() != c.upstream || v.Branch() != c.branch || v.Extra != c.extra {
			t.Errorf("%s: got upstream=%s branch=%s extra=%q", c.in, v.Upstream(), v.Branch(), v.Extra)
		}
	}
	if _, err := ParsePHP("banana"); err == nil {
		t.Error("expected error")
	}
}

func TestComparePHP(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.3.36", "8.3.36", 0},
		{"8.3.35", "8.3.36", -1},
		{"8.3.100", "8.3.36", 1},
		{"8.6.0RC3", "8.6.0RC4", -1},
		{"8.6.0", "8.6.0RC4", 1},
		{"8.6.0beta3", "8.6.0RC1", -1},
		{"8.1.31-dev", "8.1.31", -1},
		{"8.1.2-1ubuntu2.28", "8.1.2", 0},
	}
	for _, c := range cases {
		if got := MustPHP(c.a).Compare(MustPHP(c.b)); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareDpkg(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1},
		{"8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0},
		{"8.2.35-1~deb12u1", "8.2.32-1~deb12u1", 1},
		{"8.2.35-1~deb12u1", "8.2.35-1", -1},
		{"1:1.0", "2.0", 1},
		{"7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29", 1},
		{"1.0~rc1", "1.0", -1},
		{"5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29+esm17", 1},
		{"8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.9", 1},
	}
	for _, c := range cases {
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.2.35-1.el9", "8.2.34-1.el9", 1},
		{"8.0.30-1.el9_2", "8.0.30-1.el9_2.1", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1:7.4.33-1", "8.0.0-1", 1},
		{"1.0a-1", "1.0-1", 1},
		{"1.0^1-1", "1.0-1", 1},
		{"1.010-1", "1.10-1", 0},
	}
	for _, c := range cases {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
