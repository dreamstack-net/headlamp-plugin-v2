package rules

import (
	"strings"
	"testing"
)

// The prefilter parameters of a rule's state skip an event before the node-agent evaluates the
// expressions (node-agent pkg/rulemanager/prefilter); the playground still answers them.
func TestAppliesThePrefilterOfTheRulesState(t *testing.T) {
	rule := func(eventType, expression, state string) string {
		return `
spec:
  rules:
  - id: T1
    expressions:
      message: "'fired'"
      uniqueId: "'id'"
      ruleExpression:
      - eventType: ` + eventType + `
        expression: "` + expression + `"
    state: ` + state
	}
	for _, c := range []struct {
		name, eventType, state, event string
		skipped                       string
	}{
		{"a path under an included prefix", "open", "{includePrefixes: [/run/secrets/]}", `{"path": "/run/secrets/token"}`, ""},
		{"the included prefix itself", "open", "{includePrefixes: [/proc]}", `{"path": "/proc"}`, ""},
		{"a path under no included prefix", "open", "{includePrefixes: [/run/secrets, /var/run/secrets]}", `{"path": "/etc/shadow"}`,
			"its path /etc/shadow is under none of the includePrefixes of the rule's state (/run/secrets, /var/run/secrets)"},
		{"prefixes by whole segments", "open", "{includePrefixes: [/proc]}", `{"path": "/process/x"}`, "its path /process/x"},
		{"the path as the node-agent normalizes it", "open", "{includePrefixes: [/proc]}", `{"path": "proc//1/environ"}`, ""},
		{"an ignored prefix", "exec", "{ignorePrefixes: [/usr/bin]}", `{"exepath": "/usr/bin/id", "comm": "id"}`,
			"its path /usr/bin/id is under the ignorePrefixes of the rule's state (/usr/bin)"},
		{"no path to filter", "open", "{includePrefixes: [/proc]}", `{}`, ""},
		{"an excluded process", "exec", "{excludeProcesses: [{name: sh, path: /bin/sh}]}", `{"exepath": "/bin/sh", "comm": "sh"}`,
			"its process sh (/bin/sh) is in the excludeProcesses"},
		{"a process of another name", "exec", "{excludeProcesses: [{name: bash, path: /bin/sh}]}", `{"exepath": "/bin/sh", "comm": "sh"}`, ""},
		{"a port of the state", "network", "{ports: [3333, 45700]}", `{"dstPort": 45700}`, ""},
		{"another port", "network", "{ports: [3333, 45700]}", `{"dstPort": 443}`,
			"its destination port 443 is not one of the ports of the rule's state (3333, 45700)"},
		{"the ports of an SSH event", "ssh", "{ports: [22]}", `{"dstPort": 2222}`, "its destination port 2222"},
		{"no ports for HTTP", "http", "{ports: [22]}", `{"dstPort": 8080}`, ""},
		{"a port the node-agent cannot read", "network", "{ports: [70000]}", `{"dstPort": 443}`, ""},
		{"the direction", "http", "{direction: Inbound}", `{"direction": "outbound"}`,
			"its direction outbound is not the direction inbound of the rule's state"},
		{"an unknown direction", "http", "{direction: inbound}", `{"direction": ""}`, ""},
		{"the methods", "http", "{methods: [get, post]}", `{"request": {"method": "DELETE"}}`,
			"its method DELETE is not one of the methods of the rule's state (GET, POST)"},
		{"a method of the state", "http", "{methods: [get, post]}", `{"request": {"method": "POST"}}`, ""},
		{"keys without case", "open", "{IncludePrefixes: [/proc]}", `{"path": "/etc/shadow"}`, "its path /etc/shadow"},
		{"other keys of the state", "open", "{threshold: 3}", `{"path": "/etc/shadow"}`, ""},
	} {
		evaluator, err := NewRuleEvaluator([]byte(rule(c.eventType, "true", c.state)), c.eventType, []byte(c.event), nil, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		results := evaluator.Evaluate()
		if c.skipped == "" {
			if results.Prefiltered != "" || !results.Fired {
				t.Errorf("%s: expected the rule to fire, got %+v", c.name, results)
			}
			continue
		}
		if !strings.Contains(results.Prefiltered, c.skipped) || results.Fired {
			t.Errorf("%s: expected the event to be skipped because %q, got %+v", c.name, c.skipped, results)
		}
		// the expressions are still answered, but the message is not evaluated
		if len(results.RuleExpression) != 1 || results.RuleExpression[0].Result == nil || results.Message.Result != "" {
			t.Errorf("%s: unexpected results %+v", c.name, results)
		}
	}
}
