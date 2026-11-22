package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type mocks struct {
	profile, network, k8s string
}

// evalExpr evaluates one expression of an event type and returns its result or its error
func evalExpr(t *testing.T, eventType, expression, event string, m mocks) (bool, string) {
	t.Helper()
	rule, _ := yaml.Marshal(Rules{Spec: RulesSpec{Rules: []Rule{{
		ID: "T1",
		Expressions: RuleExpressions{
			RuleExpression: []RuleExpression{{EventType: eventType, Expression: expression}},
		},
	}}}})
	evaluator, err := NewRuleEvaluator(rule, eventType, []byte(event), []byte(m.profile), []byte(m.network), []byte(m.k8s))
	if err != nil {
		t.Fatalf("NewRuleEvaluator: %v", err)
	}
	results := evaluator.Evaluate()
	if len(results.RuleExpression) != 1 {
		t.Fatalf("%s: unexpected results %+v", expression, results)
	}
	r := results.RuleExpression[0]
	return r.Result != nil && *r.Result, r.Error
}

func expectAll(t *testing.T, eventType, event string, m mocks, cases map[string]bool) {
	t.Helper()
	for expression, want := range cases {
		got, err := evalExpr(t, eventType, expression, event, m)
		if err != "" {
			t.Errorf("%s: %s", expression, err)
		} else if got != want {
			t.Errorf("%s = %v, want %v", expression, got, want)
		}
	}
}

func TestCompareDynamic(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{"/etc/⋯", "/etc/passwd", true},
		{"/etc/⋯", "/etc/ssl/certs", false},
		{"/etc/⋯/certs", "/etc/ssl/certs", true},
		// a trailing * is one or more segments, so not the directory itself
		{"/etc/*", "/etc/ssl/certs/ca.pem", true},
		{"/etc/*", "/etc", false},
		{"/etc/*", "/etc/", false},
		// a * in the middle is zero or more
		{"/a/*/b", "/a/b", true},
		{"/a/*/b", "/a/x/y/b", true},
		{"/a/*/*/b", "/a/x/b", true},
		{"/a/*/b/*/c", "/a/1/2/b/3/c", true},
		{"/a/*/b/*/c", "/a/1/b/c/d", false},
		// a trailing slash of the path is ignored
		{"/etc/⋯", "/etc/passwd/", true},
		// an unanchored * matches the root too
		{"*", "/", true},
		{"/etc/⋯", "", false},
	} {
		if got := compareDynamic(c.pattern, c.path); got != c.want {
			t.Errorf("compareDynamic(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatchProfilePath(t *testing.T) {
	entries := []string{"/etc/passwd", "/var/log/", "/usr/lib/⋯/libc.so", "/opt/app/*"}
	for path, want := range map[string]bool{
		"/etc/passwd":                   true,
		"/etc/passwd/":                  true,
		"/var/log":                      true,
		"/etc/passwd//":                 false,
		"/etc/shadow":                   false,
		"/usr/lib/x86_64-linux/libc.so": true,
		"/usr/lib/a/b/libc.so":          false,
		"/opt/app/bin/run":              true,
		"/opt/app":                      false,
		"":                              false,
	} {
		if got := matchProfilePath(entries, path); got != want {
			t.Errorf("matchProfilePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchExecArgv(t *testing.T) {
	for _, c := range []struct {
		profile, runtime []string
		want             bool
	}{
		// argv[0] by its base name, without the - of a login shell
		{[]string{"/bin/sh", "-c", "id"}, []string{"sh", "-c", "id"}, true},
		{[]string{"/bin/sh", "-c", "id"}, []string{"-sh", "-c", "id"}, true},
		{[]string{"/bin/sh", "-c", "id"}, []string{"sh", "-c", "whoami"}, false},
		{[]string{"/bin/sh", "-c", "⋯"}, []string{"sh", "-c", "whoami"}, true},
		{[]string{"/bin/sh", "-c", "⋯"}, []string{"sh", "-c"}, false},
		{[]string{"/bin/sh", "⋯⋯"}, []string{"sh"}, true},
		{[]string{"/bin/sh", "⋯⋯"}, []string{"sh", "-c", "id"}, true},
		{[]string{"/bin/sh"}, []string{"sh", "-c", "id"}, false},
		// no constraint, or arguments that were not captured
		{nil, []string{"sh", "-c", "id"}, true},
		{[]string{"/bin/sh", "-c", "id"}, nil, true},
		// * is literal, and ⋯ inside an argument is one path segment
		{[]string{"cat", "/plugins/*"}, []string{"cat", "/plugins/evil.so"}, false},
		{[]string{"cat", "/plugins/⋯"}, []string{"cat", "/plugins/evil.so"}, true},
		{[]string{"cat", "/plugins/⋯"}, []string{"cat", "/plugins/a/evil.so"}, false},
	} {
		if got := matchExecArgv(c.profile, c.runtime); got != c.want {
			t.Errorf("matchExecArgv(%q, %q) = %v, want %v", c.profile, c.runtime, got, c.want)
		}
	}
}

func TestMatchIPField(t *testing.T) {
	entries := []string{"10.0.0.1", "192.168.0.0/16", "2001:db8::1"}
	for address, want := range map[string]bool{
		"10.0.0.1":                 true,
		"::ffff:10.0.0.1":          true,
		"192.168.10.20":            true,
		"2001:0db8:0000::0001":     true,
		"10.0.0.2":                 false,
		"not-an-address":           false,
		"":                         false,
		"::ffff:192.168.1.1":       true,
		"2001:db8:0:0:0:0:0:2":     false,
		"192.169.0.1":              false,
		"10.0.0.1/32":              false,
		"0000:0000::ffff:10.0.0.1": true,
	} {
		if got := matchIPField(entries, address); got != want {
			t.Errorf("matchIPField(%q) = %v, want %v", address, got, want)
		}
	}
	// * is every valid address
	if !matchIPField([]string{"*"}, "8.8.8.8") || matchIPField([]string{"*"}, "garbage") {
		t.Error("* should match every valid address and nothing else")
	}
}

func TestMatchDNSField(t *testing.T) {
	entries := []string{"api.example.com.", "registry.example.org", "*.cdn.example.net", "storage.*", "pod.⋯.svc.cluster.local"}
	for name, want := range map[string]bool{
		"api.example.com.":             true,
		"api.example.com":              true,
		"API.Example.com.":             true,
		"registry.example.org.":        true,
		"example.com.":                 false,
		"img.cdn.example.net.":         true,
		"a.img.cdn.example.net.":       false,
		"cdn.example.net.":             false,
		"storage.googleapis.com.":      true,
		"storage.":                     false,
		"pod.shop.svc.cluster.local.":  true,
		"pod.a.b.svc.cluster.local.":   false,
		"":                             false,
		"foo..example.com":             false,
		"proxy.golang.org.":            false,
		"registry.example.org.evil.io": false,
	} {
		if got := matchDNSField(entries, name); got != want {
			t.Errorf("matchDNSField(%q) = %v, want %v", name, got, want)
		}
	}
}

const libraryProfile = `
containers:
  c1:
    execs:
    - path: /bin/sh
      args: [/bin/sh, -c, ⋯]
    - path: /usr/bin/python3
    - path: /opt/tools/⋯
      args: [⋯, --version]
    opens:
    - path: /etc/passwd
      flags: [O_RDONLY]
    - path: /var/run/secrets/kubernetes.io/serviceaccount/⋯/token
    syscalls: [read, openat]
    capabilities: [CAP_NET_BIND_SERVICE]
    endpoints:
    - endpoint: ":8080/api/⋯/orders"
      methods: [GET]
    - endpoint: "http://payments.internal:9000/charge"
`

const libraryNetwork = `
containers:
  c1:
    egress:
    # the form of the mock: dns as a list
    - ipAddress: 10.0.0.1
      dns: [api.example.com.]
    # the form of a profile's neighbor
    - ipAddresses: [192.168.0.0/16]
      dns: registry.example.org.
      dnsNames: [mirror.example.org.]
    ingress:
    - ipAddress: 10.1.0.5
      dns: [client.example.com.]
`

func TestProfileFunctions(t *testing.T) {
	m := mocks{profile: libraryProfile}
	expectAll(t, "exec", `{"containerId": "c1", "comm": "sh", "args": ["sh", "-c", "id"]}`, m, map[string]bool{
		"ap.was_executed(event.containerId, '/bin/sh')":            true,
		"cp.was_executed(event.containerId, '/bin/sh/')":           true,
		"cp.was_executed(event.containerId, '/bin/bash')":          false,
		"cp.was_executed(event.containerId, '/opt/tools/kubectl')": true,
		"cp.was_executed(event.containerId, '')":                   false,
		"cp.was_executed('other', '/bin/sh')":                      false,
		// the arguments of a path that matches
		"ap.was_executed_with_args(event.containerId, '/bin/sh', event.args)":                          true,
		"cp.was_executed_with_args(event.containerId, '/bin/sh', ['sh', '-x'])":                        false,
		"cp.was_executed_with_args(event.containerId, '/usr/bin/python3', ['python3', 'evil.py'])":     true,
		"cp.was_executed_with_args(event.containerId, '/opt/tools/kubectl', ['kubectl', '--version'])": true,
		"cp.was_executed_with_args(event.containerId, '/opt/tools/kubectl', ['kubectl', 'get'])":       false,
		"cp.was_executed_with_args(event.containerId, '/bin/bash', ['bash'])":                          false,
	})
	expectAll(t, "open", `{"containerId": "c1", "path": "/etc/passwd"}`, m, map[string]bool{
		"ap.was_path_opened(event.containerId, event.path)":                                                                                        true,
		"cp.was_path_opened(event.containerId, '/etc/shadow')":                                                                                     false,
		"cp.was_path_opened(event.containerId, '/var/run/secrets/kubernetes.io/serviceaccount/..2024/token')":                                      true,
		"cp.was_path_opened_with_flags(event.containerId, event.path, ['O_RDWR'])":                                                                 true,
		"ap.was_path_opened_with_suffix(event.containerId, '/token')":                                                                              true,
		"cp.was_path_opened_with_prefix(event.containerId, '/var/run/secrets')":                                                                    true,
		"cp.was_path_opened_with_prefix(event.containerId, '/proc')":                                                                               false,
		"ap.was_syscall_used(event.containerId, 'openat')":                                                                                         true,
		"cp.was_syscall_used(event.containerId, 'ptrace')":                                                                                         false,
		"cp.was_capability_used(event.containerId, 'CAP_NET_BIND_SERVICE')":                                                                        true,
		"cp.was_capability_used(event.containerId, 'CAP_SYS_ADMIN')":                                                                               false,
		"cp.was_endpoint_accessed(event.containerId, ':8080/api/v1/orders')":                                                                       true,
		"cp.was_endpoint_accessed(event.containerId, ':8080/api/v1/users')":                                                                        false,
		"cp.was_endpoint_accessed_with_method(event.containerId, ':8080/api/v2/orders', 'POST')":                                                   true,
		"cp.was_endpoint_accessed_with_methods(event.containerId, ':8080/api/v2/orders', ['GET', 'POST'])":                                         true,
		"cp.was_endpoint_accessed_with_prefix(event.containerId, ':8080/api/')":                                                                    true,
		"cp.was_endpoint_accessed_with_suffix(event.containerId, '/charge')":                                                                       true,
		"cp.was_host_accessed(event.containerId, 'payments.internal')":                                                                             true,
		"cp.was_host_accessed(event.containerId, 'payments.internal:9000')":                                                                        true,
		"cp.was_host_accessed(event.containerId, 'api')":                                                                                           false,
		"ap.was_host_accessed(event.containerId, 'orders.internal')":                                                                               false,
		"ap.was_endpoint_accessed(event.containerId, ':8080/api/v1/orders') == cp.was_endpoint_accessed(event.containerId, ':8080/api/v1/orders')": true,
	})

	// a list argument must be a list of strings
	if _, err := evalExpr(t, "exec", "cp.was_executed_with_args(event.containerId, '/bin/sh', [1])", `{"containerId": "c1"}`, m); err == "" {
		t.Error("expected an error for a list that is not of strings")
	}
}

func TestNetworkFunctions(t *testing.T) {
	m := mocks{network: libraryNetwork}
	expectAll(t, "network", `{"containerId": "c1", "dstAddr": "::ffff:10.0.0.1", "dstPort": 443, "proto": "TCP"}`, m, map[string]bool{
		"nn.was_address_in_egress(event.containerId, event.dstAddr)":                                           true,
		"cp.was_address_in_egress(event.containerId, '192.168.3.4')":                                           true,
		"cp.was_address_in_egress(event.containerId, '8.8.8.8')":                                               false,
		"cp.was_address_in_egress(event.containerId, '10.1.0.5')":                                              false,
		"nn.was_address_in_ingress(event.containerId, '10.1.0.5')":                                             true,
		"cp.is_domain_in_egress(event.containerId, 'api.example.com')":                                         true,
		"nn.is_domain_in_egress(event.containerId, 'registry.example.org.')":                                   true,
		"cp.is_domain_in_egress(event.containerId, 'mirror.example.org')":                                      true,
		"cp.is_domain_in_egress(event.containerId, 'client.example.com.')":                                     false,
		"nn.is_domain_in_ingress(event.containerId, 'client.example.com')":                                     true,
		"nn.was_address_port_protocol_in_egress(event.containerId, event.dstAddr, event.dstPort, event.proto)": true,
		"cp.was_address_port_protocol_in_egress(event.containerId, '8.8.8.8', 443, 'TCP')":                     false,
		"cp.was_address_port_protocol_in_egress(event.containerId, '10.0.0.1', 70000, 'TCP')":                  false,
		"cp.was_address_port_protocol_in_ingress(event.containerId, '10.1.0.5', 53, 'UDP')":                    true,
	})
	if _, err := evalExpr(t, "network", "cp.was_address_port_protocol_in_egress(event.containerId, '10.0.0.1', '443', 'TCP')", `{"containerId": "c1"}`, m); err == "" {
		t.Error("expected an error for a port that is not a number")
	}
}

func TestK8sFunctions(t *testing.T) {
	m := mocks{k8s: sampleK8s}
	event := `{"namespace": "shop", "podName": "web-1", "containerName": "web", "dstAddr": "10.96.0.1"}`
	expectAll(t, "network", event, m, map[string]bool{
		"k8s.is_api_server_address(event.dstAddr)":                                                       true,
		"k8s.is_api_server_address('10.96.0.2')":                                                         false,
		"k8s.get_container_mount_paths(event.namespace, event.podName, event.containerName) == ['/bin']": true,
		"k8s.get_container_mount_paths(event.namespace, 'other', event.containerName).size() == 0":       true,
		"k8s.get_container_by_name(event.namespace, event.podName, event.containerName)":                 true,
		"k8s.get_container_by_name(event.namespace, event.podName, 'sidecar')":                           false,
	})
	// without a mock nothing is known
	expectAll(t, "network", event, mocks{}, map[string]bool{
		"k8s.is_api_server_address(event.dstAddr)": false,
	})
}

func TestParseAndProcessFunctions(t *testing.T) {
	expectAll(t, "exec", `{"comm": "sleep", "pid": 42, "exepath": "/usr/bin/sleep", "args": ["/bin/sh"]}`, mocks{}, map[string]bool{
		// argv[0] may lie; the kernel's exepath does not
		"parse.get_exec_path(event.args, event.comm, event.exepath) == '/usr/bin/sleep'": true,
		"parse.get_exec_path(event.args, event.comm, '') == '/bin/sh'":                   true,
		"parse.get_exec_path([], event.comm, '') == 'sleep'":                             true,
		"parse.get_exec_path(event.args, event.comm) == '/bin/sh'":                       true,
		// the pid of the environment is an integer, that of the hook unsigned as event.pid is
		"process.get_process_env(int(event.pid)).size() == 0": true,
		"process.get_ld_hook_var(event.pid) == ''":            true,
	})
}

func TestFiresWhenEveryExpressionOfTheEventTypeIsTrue(t *testing.T) {
	rule := func(expressions ...string) string {
		r := Rule{ID: "T1", Expressions: RuleExpressions{Message: "'fired: ' + event.comm", UniqueID: "event.comm"}}
		for _, expression := range expressions {
			r.Expressions.RuleExpression = append(r.Expressions.RuleExpression, RuleExpression{EventType: "exec", Expression: expression})
		}
		// an expression of another event type does not count
		r.Expressions.RuleExpression = append(r.Expressions.RuleExpression, RuleExpression{EventType: "open", Expression: "false"})
		data, _ := yaml.Marshal(Rules{Spec: RulesSpec{Rules: []Rule{r}}})
		return string(data)
	}
	const event = `{"comm": "sh"}`

	results := evaluate(t, rule("event.comm == 'sh'", "true"), "exec", event, "")
	if !results.Fired || results.Message.Result != "fired: sh" || results.UniqueID.Result != "sh" {
		t.Errorf("expected the rule to fire with its message, got %+v", results)
	}

	// one expression that is true is not enough
	results = evaluate(t, rule("event.comm == 'sh'", "false"), "exec", event, "")
	if results.Fired || len(results.RuleExpression) != 2 || !*results.RuleExpression[0].Result {
		t.Errorf("expected the rule not to fire, got %+v", results)
	}
	// and the message is only evaluated when the rule fires, but it is compiled
	if results.Message.Result != "" || results.Message.Error != "" {
		t.Errorf("the message should not be evaluated, got %+v", results.Message)
	}
	broken := evaluate(t, rule("false"), "exec", event, "")
	if broken.Fired {
		t.Errorf("expected the rule not to fire, got %+v", broken)
	}

	// an expression that fails does not fire
	results = evaluate(t, rule("true", "event.missing == 'x'"), "exec", event, "")
	if results.Fired || results.RuleExpression[1].Error == "" {
		t.Errorf("expected an error and no alert, got %+v", results)
	}
}

func TestCompilesTheMessageOfARuleThatDoesNotFire(t *testing.T) {
	rule, _ := yaml.Marshal(Rules{Spec: RulesSpec{Rules: []Rule{{
		ID: "T1",
		Expressions: RuleExpressions{
			Message:        "'x' + nn.unknown(event.comm)",
			RuleExpression: []RuleExpression{{EventType: "exec", Expression: "false"}},
		},
	}}}})
	evaluator, err := NewRuleEvaluator(rule, "exec", []byte(`{"comm": "sh"}`), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if results := evaluator.Evaluate(); results.Message.Error == "" {
		t.Errorf("expected an error for an unknown function, got %+v", results.Message)
	}
}

func TestEventTypes(t *testing.T) {
	// a DNS query is evaluated with the event type of the tracer
	expectAll(t, "dnsQuery", `{"name": "x.example.com.", "qr": "Q", "qtype": "TXT", "numAnswers": 0}`, mocks{}, map[string]bool{
		"eventType == 'dns' && event.qr == 'Q' && event.numAnswers == 0": true,
		"has(event.rcode)": false,
	})
	// an HTTP event is also the variable http
	expectAll(t, "http", `{"request": {"method": "POST"}}`, mocks{}, map[string]bool{
		"http.request.method == 'POST' && event.request.method == 'POST'": true,
	})

	admission := map[string]any{
		"Kind": "RoleBinding", "Name": "admins", "Namespace": "shop", "Operation": "UPDATE",
		"UserInfo":  map[string]any{"Username": "jane"},
		"Object":    map[string]any{"roleRef": map[string]any{"name": "cluster-admin"}, "subjects": []any{"a", "b"}},
		"OldObject": map[string]any{"roleRef": map[string]any{"name": "cluster-admin"}, "subjects": []any{"a"}},
	}
	event, _ := json.Marshal(admission)
	expectAll(t, "k8s-admission", string(event), mocks{}, map[string]bool{
		"eventType == 'k8s-admission' && event.UserInfo.Username == 'jane'":               true,
		"object.roleRef.name == 'cluster-admin' && object.subjects != oldObject.subjects": true,
		"options.size() == 0 && params.size() == 0":                                       true,
		// the extensions the operator enables
		"sets.contains(object.subjects, ['a'])":             true,
		"object.subjects.sortBy(s, -size(s)) == ['a', 'b']": true,
	})
	// the node-agent's functions are not those of the operator
	if _, err := evalExpr(t, "k8s-admission", "ap.was_executed('c1', '/bin/sh')", string(event), mocks{}); err == "" {
		t.Error("expected the node-agent's functions to be unknown in admission rules")
	}
	// nor is object known to the node-agent
	if _, err := evalExpr(t, "exec", "has(object.spec)", `{}`, mocks{}); err == "" {
		t.Error("expected object to be unknown in runtime rules")
	}
}

// The numbers of the event have the types of their fields, and those of an admission request
// are integers when they are whole, rather than the doubles of JSON.
func TestReadsNumbersWithTheTypesOfTheirFields(t *testing.T) {
	expectAll(t, "bpf", `{"cmd": 5, "pid": 42, "dstPort": 443}`, mocks{}, map[string]bool{
		"event.cmd == uint(5) && type(event.cmd) == uint && string(event.cmd) == '5'": true,
		"event.pid == 42u && event.dstPort == 443 && type(event.dstPort) == int":      true,
	})
	expectAll(t, "k8s-admission", `{"Object": {"spec": {"replicas": 3, "ratio": 0.5}}}`, mocks{}, map[string]bool{
		"type(object.spec.replicas) == int && object.spec.replicas % 2 == 1": true,
		"type(object.spec.ratio) == double":                                  true,
	})
}

// The node-agent declares the fields of the event with their types and does not load a rule
// that does not compile with them, so such an expression is an error here too, also where the
// same expression would be true for the numbers of the mock.
func TestChecksTheExpressionsAgainstTheTypesOfTheEvent(t *testing.T) {
	const event = `{"pid": 1, "uid": 0, "comm": "sh", "dstPort": 443}`
	for _, expression := range []string{
		"event.pid == 1",
		"event.uid == 0",
		"event.pid > 0",
		"event.comm + event.pid == 'sh1'",
		"event.dstPort == 443u",
		"event.nosuchfield == ''",
		"!has(event.nosuchfield)",
		"event.request.verb == 'GET'",
		"process.get_process_env(event.pid).size() == 0",
		"process.get_ld_hook_var(1) == ''",
		"net.is_private_ip(event.dstPort)",
		"cp.was_executed(event.containerId, event.args)",
		"cp.was_address_port_protocol_in_egress(event.containerId, event.dstAddr, event.pid, event.proto)",
		"k8s.is_api_server_address(event.dstPort)",
	} {
		rule, _ := yaml.Marshal(Rules{Spec: RulesSpec{Rules: []Rule{{
			ID:          "T1",
			Expressions: RuleExpressions{RuleExpression: []RuleExpression{{EventType: "exec", Expression: expression}}},
		}}}})
		results := evaluate(t, string(rule), "exec", event, "")
		if got := results.RuleExpression[0]; !got.CompileError || got.Error == "" || results.Fired {
			t.Errorf("%s: expected a compile error, got %+v", expression, got)
		}
	}

	// as the node-agent takes them
	expectAll(t, "exec", event, mocks{}, map[string]bool{
		"event.pid == 1u && event.uid == uint(0) && event.pid > 0u": true,
		"event.comm + string(event.pid) == 'sh1'":                   true,
		"dyn(event.dstPort) >= 443 && event.dstPort in [80, 443]":   true,
	})
}

// The node-agent has a value for every field of every event, so a field the mock leaves out is
// empty rather than an error; has() is only false for the fields it does not always set.
func TestFieldsTheMockEventLeavesOut(t *testing.T) {
	expectAll(t, "exec", `{"comm": "sh"}`, mocks{}, map[string]bool{
		"event.cwd == '' && event.pid == 0u && event.dstPort == 0 && !event.upperlayer": true,
		"event.args.size() == 0 && event.dstPodLabels.size() == 0":                      true,
		"has(event.cwd) && has(event.pid) && has(event.args)":                           true,
		"has(event.rcode) || has(event.file) || has(event.hasTty) || has(event.tty)":    false,
		"event.request.method == '' && event.request.headers.size() == 0":               true,
		"has(event.request.method) || has(event.request.url)":                           false,
	})
	expectAll(t, "http", `{"hasTty": true, "request": {"method": "GET", "headers": {"Host": ["shop"]}}}`, mocks{}, map[string]bool{
		"has(event.hasTty) && event.hasTty":                       true,
		"has(http.request.method) && !has(http.request.url)":      true,
		"http.request.headers['Host'][0] == 'shop'":               true,
		"http.request.url == '' && event.request == http.request": true,
	})

	// a value of the mock that is not of the type of its field is said, not converted
	for event, want := range map[string]string{
		`{"pid": "abc"}`: "pid of the mock event must be an unsigned integer",
		`{"pid": -1}`:    "pid of the mock event must be an unsigned integer",
		`{"pid": 1.5}`:   "pid of the mock event must be an unsigned integer",
	} {
		if _, err := evalExpr(t, "exec", "event.pid == 1u", event, mocks{}); !strings.Contains(err, want) {
			t.Errorf("%s: expected %q, got %q", event, want, err)
		}
	}
}

// Like the node-agent's isExecInPodSpec, a path of the container's command or of an exec hook
// of its lifecycle counts as executed, once the container has a profile; the pod of a container
// is known for the container of the event.
func TestCountsTheExecsOfThePodSpec(t *testing.T) {
	k8s := `
pods:
- metadata: {namespace: shop, name: web-1}
  spec:
    containers:
    - name: web
      command: [/usr/local/bin/entrypoint, --serve]
      lifecycle:
        preStop: {exec: {command: [/bin/drain, now]}}
        postStart: {exec: {command: [/bin/warm]}}
    - name: sidecar
      command: [/bin/envoy]
    initContainers:
    - name: init
      command: [/bin/migrate]
`
	profile := "containers: {c1: {execs: [{path: /bin/sh}]}, c2: {}}"
	event := `{"containerId": "c1", "namespace": "shop", "podName": "web-1", "containerName": "web", "args": ["x"]}`
	m := mocks{profile: profile, k8s: k8s}
	expectAll(t, "exec", event, m, map[string]bool{
		"cp.was_executed(event.containerId, '/usr/local/bin/entrypoint')": true,
		// every element of the command, as the node-agent compares them
		"cp.was_executed(event.containerId, '--serve')":                       true,
		"cp.was_executed(event.containerId, '/bin/drain')":                    true,
		"ap.was_executed(event.containerId, '/bin/warm')":                     true,
		"cp.was_executed(event.containerId, '/bin/envoy')":                    false,
		"cp.was_executed(event.containerId, '/bin/migrate')":                  false,
		"cp.was_executed(event.containerId, '/bin/sh')":                       true,
		"cp.was_executed(event.containerId, '')":                              false,
		"cp.was_executed_with_args(event.containerId, '/bin/warm', ['a'])":    true,
		"cp.was_executed_with_args(event.containerId, '/bin/envoy', ['a'])":   false,
		"cp.was_executed_with_args(event.containerId, '/bin/sh', event.args)": true,
		// only the pod of the event's container is known
		"cp.was_executed('c2', '/usr/local/bin/entrypoint')": false,
	})
	// an init container by its name
	expectAll(t, "exec", strings.Replace(event, `"web"`, `"init"`, 1), m, map[string]bool{
		"cp.was_executed(event.containerId, '/bin/migrate')":              true,
		"cp.was_executed(event.containerId, '/usr/local/bin/entrypoint')": false,
	})
	// a container without a profile has executed nothing, as the node-agent has no answer then
	expectAll(t, "exec", strings.Replace(event, `"c1"`, `"c3"`, 1), m, map[string]bool{
		"cp.was_executed(event.containerId, '/usr/local/bin/entrypoint')": false,
	})
	// nor is the pod known without the mock, or for another pod
	expectAll(t, "exec", event, mocks{profile: profile}, map[string]bool{
		"cp.was_executed(event.containerId, '/usr/local/bin/entrypoint')": false,
	})
	expectAll(t, "exec", strings.Replace(event, "web-1", "web-2", 1), m, map[string]bool{
		"cp.was_executed(event.containerId, '/usr/local/bin/entrypoint')": false,
	})
}
