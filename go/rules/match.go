package rules

// The matching of the node-agent's profile helpers, ported from the node-agent
// (pkg/rulemanager/cel/libraries/containerprofile: path_match.go, exec.go) and from the
// storage it uses (pkg/registry/file/dynamicpathdetector: CompareDynamic, CompareExecArgs;
// pkg/registry/file/networkmatch: MatchIP, MatchDNS), as the playground cannot import them.

import (
	"net"
	"path"
	"slices"
	"strings"
)

const (
	// dynamicIdentifier matches exactly one path segment, exec argument or DNS label
	dynamicIdentifier = "⋯"
	// wildcardIdentifier matches zero or more path segments in the middle of a path and one or
	// more at its end; in exec arguments it is a literal character
	wildcardIdentifier = "*"
	// execArgsWildcard matches zero or more whole exec arguments
	execArgsWildcard = "⋯⋯"
)

// isPattern tells whether a profile path is matched as a pattern rather than literally, as
// the projection of the node-agent sorts the entries of the paths it matches
func isPattern(entry string) bool {
	return strings.Contains(entry, dynamicIdentifier) || strings.Contains(entry, wildcardIdentifier)
}

// matchProfilePath matches a path against the literal and pattern entries of a profile, as
// the node-agent matches execs, opens and HTTP endpoints
func matchProfilePath(entries []string, query string) bool {
	if query == "" {
		return false
	}
	literals := map[string]struct{}{}
	for _, entry := range entries {
		if !isPattern(entry) {
			literals[entry] = struct{}{}
		}
	}
	if matchLiteralPath(literals, query) {
		return true
	}
	for _, entry := range entries {
		if isPattern(entry) && compareDynamic(entry, query) {
			return true
		}
	}
	return false
}

// matchLiteralPath is a lookup in literal paths that treats a single trailing slash as equal:
// "/etc/passwd/" matches "/etc/passwd" and the other way round, but "/" and paths ending in
// "//" are only matched exactly
func matchLiteralPath(values map[string]struct{}, query string) bool {
	if query == "" || len(values) == 0 {
		return false
	}
	if _, ok := values[query]; ok {
		return true
	}
	if query != "/" && !strings.HasSuffix(query, "//") {
		if trimmed, ok := strings.CutSuffix(query, "/"); ok {
			if trimmed != "" && !strings.HasSuffix(trimmed, "/") {
				if _, ok := values[trimmed]; ok {
					return true
				}
			}
		} else if _, ok := values[query+"/"]; ok {
			return true
		}
	}
	return false
}

// compareDynamic tells whether a path is matched by a profile path with "⋯" (one segment) and
// "*" (zero or more segments in the middle, one or more at the end) segments. An anchored
// pattern ("/etc/*") does not match the directory itself ("/etc"), and a trailing slash of the
// path is ignored.
func compareDynamic(dynamicPath, regularPath string) bool {
	if dynamicPath == "" || regularPath == "" {
		return false
	}
	dynamic := splitPath(collapseConsecutiveStars(dynamicPath))
	regular := splitPath(regularPath)
	memo := map[[2]int]bool{}
	return compareSegments(dynamic, regular, 0, 0, memo)
}

func compareSegments(dynamic, regular []string, di, ri int, memo map[[2]int]bool) bool {
	if di == len(dynamic) {
		return ri == len(regular)
	}
	key := [2]int{di, ri}
	if result, ok := memo[key]; ok {
		return result
	}
	result := false
	switch {
	case dynamic[di] == wildcardIdentifier:
		if di == len(dynamic)-1 {
			// a trailing "*" matches one or more segments
			result = ri < len(regular)
		} else {
			for i := ri; i <= len(regular); i++ {
				if compareSegments(dynamic, regular, di+1, i, memo) {
					result = true
					break
				}
			}
		}
	case ri == len(regular):
		result = false
	case dynamic[di] == dynamicIdentifier || dynamic[di] == regular[ri]:
		result = compareSegments(dynamic, regular, di+1, ri+1, memo)
	}
	memo[key] = result
	return result
}

// collapseConsecutiveStars replaces runs of "*" segments by one, which matches the same
func collapseConsecutiveStars(p string) string {
	segments := strings.Split(p, "/")
	collapsed := make([]string, 0, len(segments))
	for i, segment := range segments {
		if segment == wildcardIdentifier && i > 0 && segments[i-1] == wildcardIdentifier {
			continue
		}
		collapsed = append(collapsed, segment)
	}
	return strings.Join(collapsed, "/")
}

// splitPath splits a path in its segments without the empty ones of trailing slashes; the
// empty segment of a leading slash anchors the path
func splitPath(p string) []string {
	segments := strings.Split(p, "/")
	for len(segments) > 1 && segments[len(segments)-1] == "" {
		segments = segments[:len(segments)-1]
	}
	return segments
}

// matchExecArgv tells whether the arguments of an exec (argv[0] included) match those the
// profile recorded for the path. An empty vector on either side matches: the profile then
// does not constrain the arguments, or the tracer did not capture them. argv[0] is compared
// by its base name without a leading "-" (login shells), unless the profile has a pattern
// there.
func matchExecArgv(profileArgs, runtimeArgs []string) bool {
	if len(profileArgs) == 0 || len(runtimeArgs) == 0 {
		return true
	}
	if strings.Contains(profileArgs[0], dynamicIdentifier) {
		return compareExecArgs(profileArgs, runtimeArgs)
	}
	if argv0Name(profileArgs[0]) != argv0Name(runtimeArgs[0]) {
		return false
	}
	if len(profileArgs) == 1 {
		return len(runtimeArgs) == 1
	}
	return compareExecArgs(profileArgs[1:], runtimeArgs[1:])
}

func argv0Name(arg0 string) string {
	return path.Base(strings.TrimPrefix(arg0, "-"))
}

// compareExecArgs matches arguments position by position, anchored at both ends: "⋯" is any
// one argument (or one path segment inside an argument), "⋯⋯" zero or more arguments, and every
// other character, "*" included, is literal. An empty profile vector matches anything.
func compareExecArgs(profileArgs, runtimeArgs []string) bool {
	if len(profileArgs) == 0 {
		return true
	}
	type state struct{ pi, ri int }
	memo := map[state]bool{}
	var match func(pi, ri int) bool
	match = func(pi, ri int) bool {
		s := state{pi, ri}
		if result, ok := memo[s]; ok {
			return result
		}
		result := false
		switch {
		case pi == len(profileArgs):
			result = ri == len(runtimeArgs)
		case profileArgs[pi] == execArgsWildcard:
			for k := ri; k <= len(runtimeArgs) && !result; k++ {
				result = match(pi+1, k)
			}
		case ri == len(runtimeArgs):
			result = false
		case argMatches(profileArgs[pi], runtimeArgs[ri]):
			result = match(pi+1, ri+1)
		}
		memo[s] = result
		return result
	}
	return match(0, 0)
}

func argMatches(profileArg, runtimeArg string) bool {
	if profileArg == dynamicIdentifier {
		return true
	}
	if !strings.Contains(profileArg, dynamicIdentifier) {
		return profileArg == runtimeArg
	}
	p := strings.Split(profileArg, "/")
	r := strings.Split(runtimeArg, "/")
	if len(p) != len(r) {
		return false
	}
	for i := range p {
		if p[i] != dynamicIdentifier && p[i] != r[i] {
			return false
		}
	}
	return true
}

// matchIPField tells whether an address is in the addresses of a profile: as it was written,
// in its canonical form ("::ffff:10.0.0.1" is "10.0.0.1"), in a CIDR, or by a "*" entry, which
// matches every valid address
func matchIPField(entries []string, observed string) bool {
	if observed == "" {
		return false
	}
	if slices.Contains(entries, observed) {
		return true
	}
	parsed := net.ParseIP(observed)
	if parsed == nil {
		return false
	}
	canonical := parsed.String()
	for _, entry := range entries {
		switch {
		case entry == "":
		case entry == canonical, entry == wildcardIdentifier:
			return true
		case strings.Contains(entry, "/"):
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(parsed) {
				return true
			}
		default:
			if ip := net.ParseIP(entry); ip != nil && ip.Equal(parsed) {
				return true
			}
		}
	}
	return false
}

// matchDNSField tells whether a domain is in the domains of a profile, with or without the
// trailing dot and regardless of case, or matched by a pattern: a leading "*" is one label, a
// trailing "*" one or more, and "⋯" one label anywhere
func matchDNSField(entries []string, observed string) bool {
	if observed == "" {
		return false
	}
	canonical := strings.TrimSuffix(observed, ".")
	for _, entry := range entries {
		if entry == canonical || entry == canonical+"." {
			return true
		}
	}
	labels, ok := splitDNS(observed)
	if !ok {
		return false
	}
	for _, entry := range entries {
		if pattern, ok := dnsPattern(entry); ok && matchDNSPattern(pattern, labels) {
			return true
		}
	}
	return false
}

// splitDNS lowercases a name and splits it in its labels, without the trailing dot; a name
// with an empty label is not valid
func splitDNS(name string) ([]string, bool) {
	canonical := strings.ToLower(strings.TrimSuffix(name, "."))
	if canonical == "" {
		return nil, false
	}
	labels := strings.Split(canonical, ".")
	if slices.Contains(labels, "") {
		return nil, false
	}
	return labels, true
}

func dnsPattern(entry string) ([]string, bool) {
	labels, ok := splitDNS(entry)
	if !ok {
		return nil, false
	}
	if slices.Contains(labels, "**") {
		return nil, false
	}
	// "*" alone is not a valid pattern
	if len(labels) == 1 && labels[0] == wildcardIdentifier {
		return nil, false
	}
	return labels, true
}

func matchDNSPattern(pattern, observed []string) bool {
	oi := 0
	for pi, token := range pattern {
		if token == wildcardIdentifier && pi == len(pattern)-1 && pi != 0 {
			return len(observed)-oi >= 1
		}
		if oi >= len(observed) {
			return false
		}
		// a leading "*", "⋯", and a "*" elsewhere, which may not be declared there, are one
		// label; other labels are literal
		if token != wildcardIdentifier && token != dynamicIdentifier && observed[oi] != token {
			return false
		}
		oi++
	}
	return oi == len(observed)
}
