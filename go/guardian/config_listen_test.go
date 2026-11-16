package main

import "testing"

func TestCheckListenSecurity(t *testing.T) {
	cases := []struct {
		listen  string
		auth    bool
		wantErr bool
	}{
		{"127.0.0.1:18080", false, false},
		{"localhost:18080", false, false},
		{"[::1]:18080", false, false},
		{"0.0.0.0:18080", false, true},
		{":18080", false, true},
		{"192.0.2.1:18080", false, true},
		{"0.0.0.0:18080", true, false},
	}
	for _, c := range cases {
		cfg := &GuardianConfig{Listen: c.listen, Auth: AuthConfig{Enabled: c.auth}}
		if err := checkListenSecurity(cfg); (err != nil) != c.wantErr {
			t.Errorf("listen=%q auth=%v err=%v wantErr=%v", c.listen, c.auth, err, c.wantErr)
		}
	}
}
