package main

import "testing"

func TestParseRole(t *testing.T) {
	tests := []struct {
		args    []string
		want    role
		wantErr bool
	}{
		{nil, roleGUI, false},
		{[]string{}, roleGUI, false},
		{[]string{"gui"}, roleGUI, false},
		{[]string{"service"}, roleService, false},
		{[]string{"worker"}, roleWorker, false},
		{[]string{"tunnel"}, roleTunnel, false},
		{[]string{"setup", "install"}, roleSetup, false},
		{[]string{"Service"}, "", true},
		{[]string{"--service"}, "", true},
		{[]string{""}, "", true},
		{[]string{"cmd.exe"}, "", true},
	}
	for _, tt := range tests {
		got, err := parseRole(tt.args)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseRole(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("parseRole(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestRunRejectsUnknownAndUnbuiltRoles(t *testing.T) {
	for _, args := range [][]string{{"nope"}, {"service"}, {"worker"}, {"tunnel"}, {"setup"}} {
		if code := run(args); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
