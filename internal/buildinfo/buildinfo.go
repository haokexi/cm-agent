package buildinfo

import "strings"

var (
	// Set by -ldflags at build time.
	Version = "dev"
	Commit  = "unknown"
	// BuildTime should be RFC3339.
	BuildTime = ""
)

func VersionString() string {
	v := strings.TrimSpace(Version)
	if v == "" {
		return "dev"
	}
	return v
}

func CommitString() string {
	c := strings.TrimSpace(Commit)
	if c == "" {
		return "unknown"
	}
	return c
}

func BuildTimeString() string {
	return strings.TrimSpace(BuildTime)
}

func UserAgent() string {
	return "cm-agent/" + sanitizeToken(VersionString())
}

func sanitizeToken(in string) string {
	if in == "" {
		return "dev"
	}
	out := make([]rune, 0, len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		case r == '.', r == '-', r == '_', r == '+':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "dev"
	}
	return string(out)
}
