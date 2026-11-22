package rules

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// events of each type with the fields the default rules read
var sampleEvents = map[string]map[string]any{
	"exec": {
		"comm": "sh", "pid": 1234, "exepath": "/bin/sh", "cwd": "/", "args": []any{"/bin/sh", "-c", "id"},
		"upperlayer": true, "pupperlayer": false, "pcomm": "bash",
		"containerId": "c1", "containerName": "web", "namespace": "shop", "podName": "web-1",
	},
	"open": {
		"comm": "cat", "pid": 1234, "path": "/etc/shadow", "flags": []any{"O_RDONLY"}, "flagsRaw": 1,
		"containerId": "c1", "containerName": "web",
	},
	"syscall":      {"comm": "app", "pid": 1234, "syscallName": "ptrace", "containerId": "c1", "containerName": "web"},
	"capabilities": {"comm": "app", "pid": 1234, "capName": "CAP_SYS_ADMIN", "syscallName": "mount", "containerId": "c1", "containerName": "web"},
	"dns":          {"comm": "curl", "name": "pool.supportxmr.com.", "containerId": "c1", "containerName": "web"},
	"network": {
		"comm": "curl", "pktType": "OUTGOING", "dstAddr": "10.96.0.1", "dstPort": 3333, "proto": "TCP",
		"containerId": "c1", "containerName": "web",
	},
	"bpf":      {"comm": "bpftool", "cmd": 5, "containerId": "c1", "containerName": "web"},
	"kmod":     {"comm": "insmod", "module": "evil", "syscallName": "init_module", "containerId": "c1", "containerName": "web"},
	"ssh":      {"comm": "ssh", "srcPort": 40000, "dstPort": 2222, "dstIp": "203.0.113.7", "containerId": "c1", "containerName": "web"},
	"symlink":  {"comm": "ln", "oldPath": "/etc/shadow", "newPath": "/tmp/s", "containerId": "c1", "containerName": "web"},
	"hardlink": {"comm": "ln", "oldPath": "/etc/sudoers", "newPath": "/tmp/s", "containerId": "c1", "containerName": "web"},
	"ptrace":   {"comm": "strace", "exepath": "/usr/bin/strace", "containerId": "c1", "containerName": "web"},
	"randomx":  {"comm": "xmrig", "exepath": "/tmp/xmrig", "containerId": "c1", "containerName": "web"},
	"unshare":  {"comm": "unshare", "pcomm": "bash", "containerId": "c1", "containerName": "web"},
	"iouring":  {"comm": "app", "opcode": 1, "flagsRaw": 0, "containerId": "c1", "containerName": "web"},
	"k8s-admission": {
		"Kind": "Pod", "Name": "web-1", "Namespace": "shop", "Operation": "CREATE",
		"UserInfo": map[string]any{"Username": "jane", "Groups": []any{"system:authenticated"}},
		"Object": map[string]any{
			"metadata": map[string]any{"name": "web-1", "namespace": "shop"},
			"spec": map[string]any{
				"hostNetwork": true,
				"containers": []any{map[string]any{
					"name": "web", "securityContext": map[string]any{"privileged": true},
				}},
				"volumes": []any{map[string]any{"name": "host", "hostPath": map[string]any{"path": "/etc"}}},
			},
		},
	},
}

const sampleK8s = `
apiServerAddress: 10.96.0.1
pods:
- metadata: {namespace: shop, name: web-1}
  spec:
    containers:
    - name: web
      volumeMounts:
      - mountPath: /bin
`

// The default rules of the chart compile and evaluate in the playground: the functions and
// overloads they use exist, and the events of their types have the fields they read.
func TestEvaluatesTheDefaultRulesOfTheChart(t *testing.T) {
	data, err := os.ReadFile("testdata/default-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rulesDoc Rules
	if err := yaml.Unmarshal(data, &rulesDoc); err != nil {
		t.Fatal(err)
	}
	if len(rulesDoc.Spec.Rules) < 20 {
		t.Fatalf("expected the default rules, got %d", len(rulesDoc.Spec.Rules))
	}

	fired := 0
	for _, rule := range rulesDoc.Spec.Rules {
		single, _ := yaml.Marshal(Rules{Spec: RulesSpec{Rules: []Rule{rule}}})
		seen := map[string]bool{}
		for _, expression := range rule.Expressions.RuleExpression {
			eventType := expression.EventType
			if seen[eventType] {
				continue
			}
			seen[eventType] = true
			event, ok := sampleEvents[eventType]
			if !ok {
				t.Errorf("%s: no sample event of type %q", rule.ID, eventType)
				continue
			}
			eventJSON, _ := json.Marshal(event)
			// an empty profile, so that the anomaly rules fire and their messages are evaluated
			evaluator, err := NewRuleEvaluator(single, eventType, eventJSON, nil, nil, []byte(sampleK8s))
			if err != nil {
				t.Fatalf("%s: %v", rule.ID, err)
			}
			results := evaluator.Evaluate()
			if results.Error != "" || results.EventTypeMismatch != "" {
				t.Errorf("%s (%s): %+v", rule.ID, eventType, results)
			}
			for _, r := range results.RuleExpression {
				if r.Error != "" {
					t.Errorf("%s (%s): expression %q: %s", rule.ID, eventType, r.Expression, r.Error)
				}
			}
			if results.Message.Error != "" || results.UniqueID.Error != "" {
				t.Errorf("%s (%s): message %+v, uniqueId %+v", rule.ID, eventType, results.Message, results.UniqueID)
			}
			if results.Fired {
				fired++
				if rule.Expressions.Message != "" && results.Message.Result == "" {
					t.Errorf("%s (%s): no message although the rule fired", rule.ID, eventType)
				}
			}
		}
	}
	t.Logf("%d of %d rules fired", fired, len(rulesDoc.Spec.Rules))
	// the samples make most rules fire, so that their messages are evaluated too
	if fired < len(rulesDoc.Spec.Rules)*2/3 {
		t.Errorf("only %d of %d rules fired on the samples", fired, len(rulesDoc.Spec.Rules))
	}
}

// Functions and overloads that do not exist are reported, even where the expression would not
// call them for the event, as the node-agent does not load such a rule.
func TestReportsFunctionsThatDoNotExist(t *testing.T) {
	for _, expression := range []string{
		"false && ap.was_spawned(event.containerId, event.comm)",
		"false && parse.get_exec_path(event.args, event.comm, event.exepath, event.cwd) == ''",
		"false && object.spec.hostPID",
	} {
		rule := strings.Replace(execRule, "event.path.startsWith('/etc/')", expression, 1)
		results := evaluate(t, rule, "open", `{"path": "/etc/passwd", "containerId": "c1"}`, "")
		if len(results.RuleExpression) != 1 || results.RuleExpression[0].Error == "" || results.Fired {
			t.Errorf("%s: expected an error, got %+v", expression, results.RuleExpression)
		}
	}
}
