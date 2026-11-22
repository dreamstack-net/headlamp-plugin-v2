package rules

// The node-agent's prefilter (pkg/rulemanager/prefilter/prefilter.go: ParseWithDefaults and
// ShouldSkip, with the fields that extractEventFields of pkg/rulemanager/rule_manager.go reads):
// the parameters in the state of a rule skip an event before the expressions are evaluated. The
// playground has no rule bindings, whose parameters override the state.

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
)

type direction string

const (
	dirNone     direction = ""
	dirInbound  direction = "inbound"
	dirOutbound direction = "outbound"
)

func parseDirection(s string) direction {
	switch direction(s) {
	case dirInbound, dirOutbound:
		return direction(s)
	}
	return dirNone
}

// httpMethods are the methods the prefilter knows; others are not filtered
var httpMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}

// processKey is a process name, as the kernel truncates it, with the full path of its executable
type processKey struct {
	name, path string
}

type prefilterParams struct {
	ignorePrefixes         []string
	includePrefixes        []string
	excludeProcesses       map[processKey]bool
	excludeParentProcesses map[processKey]bool
	ports                  []uint16
	dir                    direction
	methods                []string
}

type rawProcessEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type rawPrefilterParams struct {
	IgnorePrefixes         []string          `json:"ignorePrefixes"`
	IncludePrefixes        []string          `json:"includePrefixes"`
	Ports                  []uint16          `json:"ports"`
	Direction              string            `json:"direction"`
	Methods                []string          `json:"methods"`
	ExcludeProcesses       []rawProcessEntry `json:"excludeProcesses"`
	ExcludeParentProcesses []rawProcessEntry `json:"excludeParentProcesses"`
}

// parsePrefilter reads the prefilter parameters of a rule's state, nil when it has none. Like
// the node-agent, it reads the keys without case, and a state that does not decode, such as a
// port above 65535, filters nothing (the node-agent only logs a warning).
func parsePrefilter(state map[string]any) *prefilterParams {
	if len(state) == 0 {
		return nil
	}
	buf, err := json.Marshal(state)
	if err != nil {
		return nil
	}
	var raw rawPrefilterParams
	if err := json.Unmarshal(buf, &raw); err != nil {
		return nil
	}
	p := &prefilterParams{
		ignorePrefixes:         trimTrailingSlash(raw.IgnorePrefixes),
		includePrefixes:        trimTrailingSlash(raw.IncludePrefixes),
		ports:                  raw.Ports,
		dir:                    parseDirection(strings.ToLower(raw.Direction)),
		excludeProcesses:       processMap(raw.ExcludeProcesses),
		excludeParentProcesses: processMap(raw.ExcludeParentProcesses),
	}
	for _, method := range raw.Methods {
		if upper := strings.ToUpper(method); slices.Contains(httpMethods, upper) {
			p.methods = append(p.methods, upper)
		}
	}
	if len(p.ignorePrefixes) == 0 && len(p.includePrefixes) == 0 && len(p.ports) == 0 && p.dir == dirNone &&
		len(p.methods) == 0 && p.excludeProcesses == nil && p.excludeParentProcesses == nil {
		return nil
	}
	return p
}

func trimTrailingSlash(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}
	result := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		result[i] = strings.TrimRight(prefix, "/")
	}
	return result
}

// processMap leaves out entries without a name or with a path that normalizes to "" or "/"
func processMap(entries []rawProcessEntry) map[processKey]bool {
	m := map[processKey]bool{}
	for _, entry := range entries {
		normalized := normalizePath(entry.Path)
		if entry.Name != "" && normalized != "" && normalized != "/" {
			m[processKey{name: entry.Name, path: normalized}] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// normalizePath is the node-agent's NormalizePath (pkg/utils/path.go), with which it reads the
// paths of events
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// prefilterEvent holds the fields of an event that the prefilter reads
type prefilterEvent struct {
	path, parentExePath, comm, pcomm string
	dstPort                          int64
	// the ports only filter network and SSH events
	portEligible bool
	dir          direction
	method       string
}

// prefilterFields reads the fields of the event that the node-agent's prefilter reads. The
// node-agent also reads the path of the parent's executable, which its rules cannot read, so
// the mock event has none and excludeParentProcesses never skips it.
func prefilterFields(eventType string, event map[string]any) prefilterEvent {
	text := func(fields map[string]any, key string) string {
		s, _ := fields[key].(string)
		return s
	}
	var f prefilterEvent
	switch eventType {
	case "open":
		f.path = normalizePath(text(event, "path"))
	case "exec":
		f.path = normalizePath(text(event, "exepath"))
		f.comm = text(event, "comm")
		f.pcomm = text(event, "pcomm")
	case httpEventType:
		f.dir = parseDirection(text(event, "direction"))
		if request, ok := event["request"].(map[string]any); ok && slices.Contains(httpMethods, text(request, "method")) {
			f.method = text(request, "method")
		}
	case "network", "ssh":
		// a missing port is the zero of the node-agent's event
		f.dstPort, _ = event["dstPort"].(int64)
		f.portEligible = true
	}
	return f
}

// skipReason is the reason why the node-agent skips the event for the rule before it evaluates
// its expressions, "" when it does not (ShouldSkip). A field of the event that is not known
// filters nothing.
func (p *prefilterParams) skipReason(e prefilterEvent) string {
	if p == nil {
		return ""
	}
	if p.dir != dirNone && e.dir != dirNone && e.dir != p.dir {
		return fmt.Sprintf("its direction %s is not the direction %s of the rule's state", e.dir, p.dir)
	}
	if len(p.methods) > 0 && e.method != "" && !slices.Contains(p.methods, e.method) {
		return fmt.Sprintf("its method %s is not one of the methods of the rule's state (%s)", e.method, strings.Join(p.methods, ", "))
	}
	if e.path != "" {
		if len(p.includePrefixes) > 0 && !hasAnyPrefix(e.path, p.includePrefixes) {
			return fmt.Sprintf("its path %s is under none of the includePrefixes of the rule's state (%s)", e.path, strings.Join(p.includePrefixes, ", "))
		}
		if len(p.ignorePrefixes) > 0 && hasAnyPrefix(e.path, p.ignorePrefixes) {
			return fmt.Sprintf("its path %s is under the ignorePrefixes of the rule's state (%s)", e.path, strings.Join(p.ignorePrefixes, ", "))
		}
	}
	if e.portEligible && len(p.ports) > 0 && !slices.ContainsFunc(p.ports, func(port uint16) bool { return int64(port) == e.dstPort }) {
		ports := make([]string, len(p.ports))
		for i, port := range p.ports {
			ports[i] = fmt.Sprint(port)
		}
		return fmt.Sprintf("its destination port %d is not one of the ports of the rule's state (%s)", e.dstPort, strings.Join(ports, ", "))
	}
	if e.comm != "" && e.path != "" && p.excludeProcesses[processKey{name: e.comm, path: e.path}] {
		return fmt.Sprintf("its process %s (%s) is in the excludeProcesses of the rule's state", e.comm, e.path)
	}
	if e.pcomm != "" && e.parentExePath != "" && p.excludeParentProcesses[processKey{name: e.pcomm, path: e.parentExePath}] {
		return fmt.Sprintf("its parent process %s (%s) is in the excludeParentProcesses of the rule's state", e.pcomm, e.parentExePath)
	}
	return ""
}

// hasAnyPrefix tells whether a path is one of the prefixes or under one, by whole segments
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if s == p || (len(s) > len(p) && s[len(p)] == '/' && s[:len(p)] == p) {
			return true
		}
	}
	return false
}
