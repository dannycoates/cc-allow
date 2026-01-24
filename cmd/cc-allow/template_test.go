package main

import "testing"

func TestTemplateMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		ctx  TemplateContext
		want string
	}{
		{
			name: "no template",
			msg:  "simple message",
			ctx:  TemplateContext{},
			want: "simple message",
		},
		{
			name: "empty message",
			msg:  "",
			ctx:  TemplateContext{Command: "rm"},
			want: "",
		},
		{
			name: "command substitution",
			msg:  "{{.Command}} is not allowed",
			ctx:  TemplateContext{Command: "rm"},
			want: "rm is not allowed",
		},
		{
			name: "file path substitution",
			msg:  "Cannot write to {{.FilePath}}",
			ctx:  TemplateContext{FilePath: "/etc/passwd"},
			want: "Cannot write to /etc/passwd",
		},
		{
			name: "file name helper",
			msg:  "Cannot access {{.FileName}}",
			ctx:  TemplateContext{FilePath: "/etc/passwd"},
			want: "Cannot access passwd",
		},
		{
			name: "file dir helper",
			msg:  "Cannot access files in {{.FileDir}}",
			ctx:  TemplateContext{FilePath: "/etc/passwd"},
			want: "Cannot access files in /etc",
		},
		{
			name: "target file name helper",
			msg:  "Cannot redirect to {{.TargetFileName}}",
			ctx:  TemplateContext{Target: "/var/log/app.log"},
			want: "Cannot redirect to app.log",
		},
		{
			name: "target dir helper",
			msg:  "Cannot redirect to {{.TargetDir}}",
			ctx:  TemplateContext{Target: "/var/log/app.log"},
			want: "Cannot redirect to /var/log",
		},
		{
			name: "invalid template returns raw",
			msg:  "{{.Invalid syntax",
			ctx:  TemplateContext{},
			want: "{{.Invalid syntax",
		},
		{
			name: "missing field returns empty",
			msg:  "Command: {{.Command}}",
			ctx:  TemplateContext{},
			want: "Command: ",
		},
		{
			name: "args helper",
			msg:  "Full command: {{.ArgsStr}}",
			ctx:  TemplateContext{Args: []string{"rm", "-rf", "/tmp/foo"}},
			want: "Full command: rm -rf /tmp/foo",
		},
		{
			name: "arg helper first arg",
			msg:  "First arg: {{.Arg 0}}",
			ctx:  TemplateContext{Args: []string{"rm", "-rf", "/tmp/foo"}},
			want: "First arg: -rf",
		},
		{
			name: "arg helper second arg",
			msg:  "Second arg: {{.Arg 1}}",
			ctx:  TemplateContext{Args: []string{"rm", "-rf", "/tmp/foo"}},
			want: "Second arg: /tmp/foo",
		},
		{
			name: "arg helper out of bounds",
			msg:  "Third arg: {{.Arg 2}}",
			ctx:  TemplateContext{Args: []string{"rm", "-rf", "/tmp/foo"}},
			want: "Third arg: ",
		},
		{
			name: "multiple substitutions",
			msg:  "{{.Command}} cannot access {{.FilePath}}",
			ctx:  TemplateContext{Command: "cat", FilePath: "/etc/shadow"},
			want: "cat cannot access /etc/shadow",
		},
		{
			name: "redirect context",
			msg:  "Cannot redirect to {{.Target}} (append={{.Append}})",
			ctx:  TemplateContext{Target: "/var/log/app.log", Append: true},
			want: "Cannot redirect to /var/log/app.log (append=true)",
		},
		{
			name: "heredoc context",
			msg:  "Heredoc with delimiter {{.Delimiter}} not allowed",
			ctx:  TemplateContext{Delimiter: "EOF"},
			want: "Heredoc with delimiter EOF not allowed",
		},
		{
			name: "tool context",
			msg:  "{{.Tool}} access to {{.FileName}} denied",
			ctx:  TemplateContext{Tool: "Write", FilePath: "/etc/passwd"},
			want: "Write access to passwd denied",
		},
		{
			name: "environment context",
			msg:  "Cannot access files outside {{.ProjectRoot}}",
			ctx:  TemplateContext{ProjectRoot: "/home/user/project"},
			want: "Cannot access files outside /home/user/project",
		},
		{
			name: "pipes from context",
			msg:  "{{.Command}} receiving from pipe not allowed",
			ctx:  TemplateContext{Command: "bash", PipesFrom: []string{"curl"}},
			want: "bash receiving from pipe not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := templateMessage(tt.msg, tt.ctx)
			if got != tt.want {
				t.Errorf("templateMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTemplateContextHelpers(t *testing.T) {
	t.Run("ArgsStr with empty args", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.ArgsStr(); got != "" {
			t.Errorf("ArgsStr() = %q, want empty", got)
		}
	})

	t.Run("Arg with nil args", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.Arg(0); got != "" {
			t.Errorf("Arg(0) = %q, want empty", got)
		}
	})

	t.Run("FileName with empty path", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.FileName(); got != "" {
			t.Errorf("FileName() = %q, want empty", got)
		}
	})

	t.Run("FileDir with empty path", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.FileDir(); got != "" {
			t.Errorf("FileDir() = %q, want empty", got)
		}
	})

	t.Run("TargetFileName with empty target", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.TargetFileName(); got != "" {
			t.Errorf("TargetFileName() = %q, want empty", got)
		}
	})

	t.Run("TargetDir with empty target", func(t *testing.T) {
		ctx := TemplateContext{}
		if got := ctx.TargetDir(); got != "" {
			t.Errorf("TargetDir() = %q, want empty", got)
		}
	})
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{
			name:   "short string",
			s:      "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "exact length",
			s:      "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "truncated",
			s:      "hello world",
			maxLen: 5,
			want:   "hello...",
		},
		{
			name:   "empty string",
			s:      "",
			maxLen: 10,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString() = %q, want %q", got, tt.want)
			}
		})
	}
}
