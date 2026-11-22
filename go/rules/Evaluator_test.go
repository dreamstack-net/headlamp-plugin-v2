package rules

import (
	"strings"
	"testing"
)

const execRule = `
apiVersion: kubescape.io/v1
kind: Rules
spec:
  rules:
  - name: Unexpected process launched
    id: R0001
    expressions:
      message: "'Unexpected process: ' + parse.get_exec_path(event.args, event.comm)"
      uniqueId: "event.comm + '_' + event.exepath"
      ruleExpression:
      - eventType: exec
        expression: "!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm))"
      - eventType: open
        expression: "event.path.startsWith('/etc/')"
`

const execEvent = `{"containerId": "c1", "comm": "sh", "exepath": "/bin/sh", "args": ["/bin/sh", "-c", "id"]}`

func evaluate(t *testing.T, rule, eventType, event, profile string) RuleEvalResults {
	t.Helper()
	evaluator, err := NewRuleEvaluator([]byte(rule), eventType, []byte(event), []byte(profile), nil, nil)
	if err != nil {
		t.Fatalf("NewRuleEvaluator: %v", err)
	}
	return evaluator.Evaluate()
}

func TestEvaluatesTheExpressionsOfTheEventType(t *testing.T) {
	results := evaluate(t, execRule, "exec", execEvent, "")

	if len(results.RuleExpression) != 1 || results.RuleExpression[0].EventType != "exec" {
		t.Fatalf("expected only the exec expression, got %+v", results.RuleExpression)
	}
	// the dotted names of the library functions resolve
	exec := results.RuleExpression[0]
	if exec.Error != "" || exec.Result == nil || !*exec.Result {
		t.Errorf("a process the profile does not have should match, got %+v", exec)
	}
	if results.Message.Result != "Unexpected process: /bin/sh" || results.Message.Error != "" {
		t.Errorf("unexpected message %+v", results.Message)
	}
	if results.UniqueID.Result != "sh_/bin/sh" {
		t.Errorf("unexpected uniqueId %+v", results.UniqueID)
	}
}

func TestUsesTheProfile(t *testing.T) {
	profile := `
containers:
  c1:
    execs:
    - path: /bin/sh
`
	results := evaluate(t, execRule, "exec", execEvent, profile)
	exec := results.RuleExpression[0]
	if exec.Result == nil || *exec.Result {
		t.Errorf("a process the profile has should not match, got %+v", exec)
	}
}

func TestReportsAnEventTypeTheRuleDoesNotHandle(t *testing.T) {
	results := evaluate(t, execRule, "dns", `{}`, "")
	if !strings.Contains(results.EventTypeMismatch, `"dns"`) || len(results.RuleExpression) != 0 {
		t.Errorf("expected a mismatch, got %+v", results)
	}
	if results.Message.Result != "" || results.Message.Error != "" {
		t.Errorf("the message should not be evaluated for another event type, got %+v", results.Message)
	}
}

func TestReportsErrorsPerExpression(t *testing.T) {
	rule := strings.Replace(execRule, "event.path.startsWith('/etc/')", "event.path.size()", 1)
	results := evaluate(t, rule, "open", `{"path": "/etc/passwd"}`, "")
	if len(results.RuleExpression) != 1 || !strings.Contains(results.RuleExpression[0].Error, "must return bool") {
		t.Errorf("expected an error for a non-boolean expression, got %+v", results.RuleExpression)
	}

	broken := strings.Replace(execRule, "event.path.startsWith('/etc/')", "event.path ==", 1)
	results = evaluate(t, broken, "open", `{"path": "/etc/passwd"}`, "")
	if results.RuleExpression[0].Error == "" {
		t.Errorf("expected a syntax error, got %+v", results.RuleExpression[0])
	}
}

// An expression that does not compile fails for every event, and is told apart from one that
// fails for this event, such as an index the arguments of the event do not have.
func TestTellsCompileErrorsFromEvaluationErrors(t *testing.T) {
	for expression, wantCompileError := range map[string]bool{
		"event.path ==":                  true,
		"cp.was_spawned(event.path)":     true,
		"event.args[1] == '-c'":          false,
		"event.path.size()":              false,
		"event.path.startsWith('/etc/')": false,
	} {
		rule := strings.Replace(execRule, "event.path.startsWith('/etc/')", expression, 1)
		results := evaluate(t, rule, "open", `{"path": "/etc/passwd", "args": ["cat"]}`, "")
		if got := results.RuleExpression[0]; got.CompileError != wantCompileError || (wantCompileError && got.Error == "") {
			t.Errorf("%s: expected compileError %v, got %+v", expression, wantCompileError, got)
		}
	}

	// the message and the unique id are compiled also when the rule does not fire
	rule := strings.Replace(execRule, `"event.comm + '_' + event.exepath"`, `"event.comm +"`, 1)
	results := evaluate(t, rule, "open", `{"path": "/tmp/x"}`, "")
	if !results.UniqueID.CompileError || results.UniqueID.Error == "" || results.Message.CompileError {
		t.Errorf("expected a compile error of the unique id only, got %+v, %+v", results.UniqueID, results.Message)
	}
}

const stringsRule = `
spec:
  rules:
  - id: T1
    expressions:
      message: MESSAGE
      uniqueId: UNIQUEID
      ruleExpression:
      - eventType: EVENTTYPE
        expression: "true"
`

// The node-agent and the operator only take a string for the message and the unique id. The
// node-agent sends no alert for an event whose unique id fails; the operator alerts without it.
func TestMessageAndUniqueIdAreStrings(t *testing.T) {
	for _, tc := range []struct {
		name, eventType, message, uniqueID string
		wantFired                          bool
		wantMessage, wantUniqueID          string
		wantMessageError, wantUniqueIDErr  string
	}{
		{"strings", "exec", "event.comm", "event.comm", true, "sh", "sh", "", ""},
		{"message that is no string", "exec", "event.dstPort", "event.comm", true, "", "sh", "expression returned int64, expected string", ""},
		{"unique id that is no string", "exec", "event.comm", "event.dstPort", false, "sh", "", "", "expression returned int64, expected string"},
		{"unique id that fails", "exec", "event.comm", "event.args[0]", false, "sh", "", "", "index out of bounds"},
		// a unique id that does not compile is an empty one for the node-agent
		{"unique id that does not compile", "exec", "event.comm", "event.comm +", true, "sh", "", "", "Syntax error"},
		{"unique id of an admission rule that fails", "k8s-admission", "event.comm", "event.args[0]", true, "sh", "", "", "index out of bounds"},
	} {
		rule := strings.NewReplacer("MESSAGE", tc.message, "UNIQUEID", tc.uniqueID, "EVENTTYPE", tc.eventType).Replace(stringsRule)
		results := evaluate(t, rule, tc.eventType, `{"comm": "sh", "dstPort": 443, "args": []}`, "")
		if results.Fired != tc.wantFired {
			t.Errorf("%s: expected fired %v, got %+v", tc.name, tc.wantFired, results)
		}
		if results.Message.Result != tc.wantMessage || !strings.Contains(results.Message.Error, tc.wantMessageError) || (tc.wantMessageError == "") != (results.Message.Error == "") {
			t.Errorf("%s: unexpected message %+v", tc.name, results.Message)
		}
		if results.UniqueID.Result != tc.wantUniqueID || !strings.Contains(results.UniqueID.Error, tc.wantUniqueIDErr) || (tc.wantUniqueIDErr == "") != (results.UniqueID.Error == "") {
			t.Errorf("%s: unexpected unique id %+v", tc.name, results.UniqueID)
		}
	}
}

func TestGetExecPathFallsBackToTheCommand(t *testing.T) {
	results := evaluate(t, execRule, "exec", `{"containerId": "c1", "comm": "sh", "args": []}`, "")
	if results.Message.Result != "Unexpected process: sh" {
		t.Errorf("expected the command, got %+v", results.Message)
	}
}

func TestRejectsRulesWithoutRules(t *testing.T) {
	if _, err := NewRuleEvaluator([]byte("spec: {rules: []}"), "exec", nil, nil, nil, nil); err == nil {
		t.Error("expected an error for a Rules object without rules")
	}
}

func TestIsPrivateIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.1.2.3":    true,
		"192.168.1.1": true,
		"172.16.0.1":  true,
		"127.0.0.1":   true,
		"8.8.8.8":     false,
		"fd00::1":     true,
		"2001:db8::1": false,
		"not-an-ip":   false,
		// as the node-agent counts them
		"169.254.1.1":     true,
		"fe80::1":         true,
		"::1":             true,
		"100.64.0.1":      true,
		"100.127.255.255": true,
		"100.128.0.1":     false,
		"224.0.0.251":     true,
		"255.255.255.255": true,
		"0.0.0.0":         false,
		"ff02::1":         false,
	} {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", ip, got, want)
		}
	}
}
