package main

import (
	"os"
	"testing"
)

func TestResolveEditor(t *testing.T) {
	tests := []struct {
		name       string
		envEditor  string
		flagEditor string
		want       string
	}{
		{
			name:       "env var takes precedence",
			envEditor:  "nano",
			flagEditor: "vim",
			want:       "nano",
		},
		{
			name:       "flag used when no env var",
			envEditor:  "",
			flagEditor: "vim",
			want:       "vim",
		},
		{
			name:       "fallback to vi",
			envEditor:  "",
			flagEditor: "",
			want:       "vi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("EDITOR")
			if tt.envEditor != "" {
				t.Setenv("EDITOR", tt.envEditor)
			}
			got := resolveEditor(tt.flagEditor)
			if got != tt.want {
				t.Errorf("resolveEditor(%q) = %q, want %q", tt.flagEditor, got, tt.want)
			}
		})
	}
}

func TestRunEditMissingVault(t *testing.T) {
	err := runEdit("/nonexistent/path/.env.age", "cat")
	if err == nil {
		t.Error("expected error for missing vault, got nil")
	}
}
