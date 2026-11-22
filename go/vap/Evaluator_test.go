package vap

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

const deployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  replicas: 5
`

func policyWith(spec string) string {
	return `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["deployments"]
` + spec
}

func evaluate(t *testing.T, policy, object, oldObject, request string) EvaluationResults {
	t.Helper()
	evaluator, err := NewAdmissionPolicyEvaluator([]byte(policy), []byte(object), []byte(oldObject), []byte(request), nil, nil)
	if err != nil {
		t.Fatalf("NewAdmissionPolicyEvaluator: %v", err)
	}
	evaluator.CheckMatchConstraints()
	if !evaluator.Results.MatchConstraints {
		t.Fatal("policy does not match the object")
	}
	evaluator.Evaluate()
	return evaluator.Results
}

func validation(t *testing.T, results EvaluationResults, index int) *EvalResult {
	t.Helper()
	if len(results.Validations) <= index {
		t.Fatalf("expected at least %d validations, got %+v", index+1, results)
	}
	return results.Validations[index]
}

// expectBool fails unless the expression evaluated without error to the given boolean
func expectBool(t *testing.T, name string, result *EvalResult, expected bool) {
	t.Helper()
	value, ok := result.Result.(*structpb.Value)
	if ok {
		_, ok = value.GetKind().(*structpb.Value_BoolValue)
	}
	if result.Error != "" || !ok || value.GetBoolValue() != expected {
		t.Errorf("%s: expected %v, got result %v, error %q", name, expected, result.Result, result.Error)
	}
}

func TestDefaultRequestIsCreateWithoutOldObject(t *testing.T) {
	policy := policyWith(`
  validations:
  - expression: "request.operation == 'CREATE' && oldObject == null"
  - expression: "request.kind.kind == 'Deployment' && request.resource.resource == 'deployments'"
  - expression: "request.name == 'web' && request.namespace == 'shop'"
`)
	results := evaluate(t, policy, deployment, "", "")

	for i, v := range results.Validations {
		expectBool(t, v.Expression, validation(t, results, i), true)
	}
}

func TestDefaultRequestIsUpdateWithOldObject(t *testing.T) {
	policy := policyWith(`
  validations:
  - expression: "request.operation == 'UPDATE'"
  - expression: "object.spec.replicas > oldObject.spec.replicas"
`)
	oldDeployment := strings.Replace(deployment, "replicas: 5", "replicas: 2", 1)
	results := evaluate(t, policy, deployment, oldDeployment, "")

	for i, v := range results.Validations {
		expectBool(t, v.Expression, validation(t, results, i), true)
	}
}

func TestExplicitRequest(t *testing.T) {
	policy := policyWith(`
  validations:
  - expression: "request.userInfo.username == 'alice'"
`)
	results := evaluate(t, policy, deployment, "", "userInfo:\n  username: alice\noperation: CREATE\n")

	expectBool(t, "username", validation(t, results, 0), true)
}

func TestVariablesReferToEarlierVariables(t *testing.T) {
	policy := policyWith(`
  variables:
  - name: replicas
    expression: "object.spec.replicas"
  - name: tooMany
    expression: "variables.replicas > 3"
  validations:
  - expression: "!variables.tooMany"
`)
	results := evaluate(t, policy, deployment, "", "")

	expectBool(t, "validation", validation(t, results, 0), false)
}

func TestMatchConditions(t *testing.T) {
	for _, tc := range []struct {
		condition       string
		wantValidations int
	}{
		{"object.metadata.namespace == 'shop'", 1},
		{"object.metadata.namespace == 'billing'", 0},
	} {
		policy := policyWith(`
  matchConditions:
  - name: namespace
    expression: "` + tc.condition + `"
  validations:
  - expression: "object.spec.replicas < 10"
`)
		results := evaluate(t, policy, deployment, "", "")

		if len(results.Validations) != tc.wantValidations {
			t.Errorf("%s: expected %d validations, got %d", tc.condition, tc.wantValidations, len(results.Validations))
		}
	}
}

func TestVariableErrorsPropagate(t *testing.T) {
	policy := policyWith(`
  variables:
  - name: missing
    expression: "object.spec.template.spec.containers"
  validations:
  - expression: "size(variables.missing) > 0"
`)
	results := evaluate(t, policy, deployment, "", "")

	if results.Variables[0].Error == "" {
		t.Error("expected the variable to fail")
	}
	if v := validation(t, results, 0); !strings.Contains(v.Error, "no such key") {
		t.Errorf("expected the validation to fail with the variable error, got result %v, error %q", v.Result, v.Error)
	}
}

func TestUndeclaredReferencesFail(t *testing.T) {
	policy := policyWith(`
  validations:
  - expression: "objet.spec.replicas < 10"
`)
	results := evaluate(t, policy, deployment, "", "")

	if v := validation(t, results, 0); !strings.Contains(v.Error, "objet") {
		t.Errorf("expected an error about 'objet', got result %v, error %q", v.Result, v.Error)
	}
}

func evaluateWith(t *testing.T, policy, params, namespace string) EvaluationResults {
	t.Helper()
	evaluator, err := NewAdmissionPolicyEvaluator([]byte(policy), []byte(deployment), nil, nil, []byte(params), []byte(namespace))
	if err != nil {
		t.Fatalf("NewAdmissionPolicyEvaluator: %v", err)
	}
	evaluator.CheckMatchConstraints()
	if !evaluator.Results.MatchConstraints {
		t.Fatal("policy does not match the object")
	}
	evaluator.Evaluate()
	return evaluator.Results
}

func TestEmptyParamsAndNamespaceAreNull(t *testing.T) {
	policy := policyWith(`
  validations:
  - expression: "params == null"
  - expression: "namespaceObject == null"
`)
	results := evaluateWith(t, policy, "", "")
	expectBool(t, "params == null", validation(t, results, 0), true)
	expectBool(t, "namespaceObject == null", validation(t, results, 1), true)

	results = evaluateWith(t, policy, "settings: {}\n", "metadata:\n  name: shop\n")
	expectBool(t, "params == null", validation(t, results, 0), false)
	expectBool(t, "namespaceObject == null", validation(t, results, 1), false)
}

func TestWholeNumbersAreIntegers(t *testing.T) {
	policy := policyWith(`
  variables:
  - name: infinite
    expression: "params.ratio / 0.0"
  validations:
  - expression: "object.spec.replicas % 2 == 1"
  - expression: "object.spec.replicas + 1 == 6 && object.spec.replicas * 2 == 10"
  - expression: "type(object.spec.replicas) == int && type(params.limit) == int"
  - expression: "type(params.ratio) == double && params.ratio < 1"
  - expression: "object.spec.replicas / 0 == 1"
`)
	results := evaluateWith(t, policy, "ratio: 0.5\nlimit: 10\n", "")

	for i := range 4 {
		expectBool(t, results.Validations[i].Expression, validation(t, results, i), true)
	}
	if v := validation(t, results, 4); !strings.Contains(v.Error, "division by zero") {
		t.Errorf("expected a division by zero, got result %v, error %q", v.Result, v.Error)
	}
	// a double divided by zero is infinite, which JSON cannot hold
	if got := results.Variables[0].Result; got != "+Inf" {
		t.Errorf("expected the infinite variable as text, got %v", got)
	}
	if _, err := json.Marshal(results); err != nil {
		t.Errorf("the results should be JSON: %v", err)
	}
}

func TestMatchConditionsGetNoNamespace(t *testing.T) {
	policy := policyWith(`
  matchConditions:
  - name: no-namespace
    expression: "namespaceObject == null"
  validations:
  - expression: "namespaceObject.metadata.name == 'shop'"
`)
	results := evaluateWith(t, policy, "", "metadata:\n  name: shop\n")

	if !results.MatchConditionsMatched || results.MatchConditionError != "" {
		t.Errorf("expected namespaceObject to be null in the match condition, got %+v", results.MatchConditions[0])
	}
	expectBool(t, "validation", validation(t, results, 0), true)
}

func TestRequestOfANamespaceNamesItself(t *testing.T) {
	policy := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test
spec:
  matchConstraints:
    resourceRules:
    - {apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [namespaces]}
  validations:
  - expression: "request.namespace == 'shop' && request.name == 'shop'"
`
	results := evaluate(t, policy, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shop\n", "", "")

	expectBool(t, "request.namespace", validation(t, results, 0), true)
}

func TestMatchConditionsCannotUseVariables(t *testing.T) {
	policy := policyWith(`
  variables:
  - name: shop
    expression: "object.metadata.namespace == 'shop'"
  matchConditions:
  - name: in-shop
    expression: "variables.shop"
  validations:
  - expression: "object.spec.replicas < 10"
`)
	results := evaluate(t, policy, deployment, "", "")

	if !strings.Contains(results.Error, "the match condition in-shop uses variables") {
		t.Errorf("expected an error about the variables, got %q", results.Error)
	}
	if len(results.Validations) != 0 {
		t.Errorf("expected no validations, got %d", len(results.Validations))
	}
}

func TestMatchConditionsMatched(t *testing.T) {
	for _, tc := range []struct {
		conditions string
		matched    bool
		err        bool
	}{
		{"", true, false},
		{"  matchConditions:\n  - name: shop\n    expression: \"object.metadata.namespace == 'shop'\"\n", true, false},
		{"  matchConditions:\n  - name: billing\n    expression: \"object.metadata.namespace == 'billing'\"\n", false, false},
		// a condition that is false wins over one that fails
		{"  matchConditions:\n  - name: fails\n    expression: \"object.missing\"\n  - name: billing\n    expression: \"object.metadata.namespace == 'billing'\"\n", false, false},
		{"  matchConditions:\n  - name: fails\n    expression: \"object.missing\"\n", true, true},
	} {
		// a policy with only audit annotations has no validations
		policy := policyWith(tc.conditions + `
  auditAnnotations:
  - key: replicas
    valueExpression: "string(object.spec.replicas)"
`)
		results := evaluate(t, policy, deployment, "", "")

		if results.MatchConditionsMatched != tc.matched {
			t.Errorf("%q: expected matchConditionsMatched %v, got %v", tc.conditions, tc.matched, results.MatchConditionsMatched)
		}
		if (results.MatchConditionError != "") != tc.err {
			t.Errorf("%q: expected an error %v, got %q", tc.conditions, tc.err, results.MatchConditionError)
		}
		wantAnnotations := 0
		if tc.matched && !tc.err {
			wantAnnotations = 1
		}
		if len(results.AuditAnnotations) != wantAnnotations {
			t.Errorf("%q: expected %d audit annotations, got %d", tc.conditions, wantAnnotations, len(results.AuditAnnotations))
		}
	}
}

func TestFailureMessages(t *testing.T) {
	long := strings.Repeat("x", 5*1024+1)
	for _, tc := range []struct {
		name, message, messageExpression, want string
	}{
		{"messageExpression without surrounding space", "fallback", `"'  too many  '"`, "too many"},
		// YAML leaves the escapes of a single-quoted string to CEL
		{"message when the messageExpression has a line break", " fallback ", `'"too\nmany"'`, "fallback"},
		{"messageExpression with a line break around it", "fallback", `'"too many\n"'`, "too many"},
		{"messageExpression of the longest length", "fallback", `"'` + long[1:] + `'"`, long[1:]},
		{"message when the messageExpression is not a string", "fallback", `"1"`, "fallback"},
		{"message when the messageExpression fails", "fallback", `"object.missing"`, "fallback"},
		{"message when the messageExpression is empty", "fallback", `"'  '"`, "fallback"},
		{"message when the messageExpression is too long", "fallback", `"'` + long + `'"`, "fallback"},
		{"message without surrounding space", "  spaced  ", "", "spaced"},
		{"expression without message", "", `"'  '"`, "failed expression: object.spec.replicas < 3"},
	} {
		spec := `
  validations:
  - expression: " object.spec.replicas < 3 "
`
		if tc.message != "" {
			spec += "    message: \"" + tc.message + "\"\n"
		}
		if tc.messageExpression != "" {
			spec += "    messageExpression: " + tc.messageExpression + "\n"
		}
		results := evaluate(t, policyWith(spec), deployment, "", "")

		if got := validation(t, results, 0).Message; got != tc.want {
			t.Errorf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestAuditAnnotationsThatReject(t *testing.T) {
	annotations := `
  auditAnnotations:
  - key: name
    valueExpression: "object.metadata.name"
  - key: none
    valueExpression: "null"
`
	results := evaluate(t, policyWith(annotations), deployment, "", "")
	if results.AuditAnnotationError != "" {
		t.Errorf("expected strings and null to be accepted, got %q", results.AuditAnnotationError)
	}

	// a value that is not a string rejects the request, also with failurePolicy Ignore
	for _, failurePolicy := range []string{"Fail", "Ignore"} {
		policy := policyWith(`  failurePolicy: ` + failurePolicy + `
  auditAnnotations:
  - key: replicas
    valueExpression: "object.spec.replicas"
`)
		results = evaluate(t, policy, deployment, "", "")
		if !strings.Contains(results.AuditAnnotations[0].Error, "unsupported return type") ||
			!strings.HasPrefix(results.AuditAnnotationError, "replicas: ") {
			t.Errorf("%s: expected the type to reject, got %+v, %q", failurePolicy, results.AuditAnnotations[0], results.AuditAnnotationError)
		}
	}

	// one that fails only rejects it when the failurePolicy is Fail
	for failurePolicy, rejects := range map[string]bool{"Fail": true, "Ignore": false} {
		policy := policyWith(`  failurePolicy: ` + failurePolicy + `
  auditAnnotations:
  - key: missing
    valueExpression: "object.missing"
`)
		results = evaluate(t, policy, deployment, "", "")
		if results.AuditAnnotations[0].Error == "" || (results.AuditAnnotationError != "") != rejects {
			t.Errorf("%s: expected rejecting %v, got %+v, %q", failurePolicy, rejects, results.AuditAnnotations[0], results.AuditAnnotationError)
		}
	}
}
