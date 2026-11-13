package config

import "testing"

// DR-2 (docs/reviews/2026-11-12-skills-review.md): Caddy expands
// {placeholders} in response-header values, so {file.*} or {env.*} would
// publish files and environment variables to every visitor. Validation must
// refuse braces in a header value.
func TestHeaderValueRefusesPlaceholders(t *testing.T) {
	for _, v := range []string{`{file.C:/ProgramData/SoireeHost/logs/web/access.log}`, `{env.USERNAME}`, `a{b`, `a}b`} {
		c := Default()
		c.Sites = []Site{{
			ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"},
			Type: TypeStatic, Static: &Static{Root: `C:\Sites\blog`},
			ResponseHeaders: map[string]string{"Permissions-Policy": v},
		}}
		c.Normalize()
		if err := c.Validate(); err == nil {
			t.Errorf("header value %q passed validation", v)
		}
	}
}
