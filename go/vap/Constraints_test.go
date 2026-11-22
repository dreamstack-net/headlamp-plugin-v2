package vap

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestMakePlural(t *testing.T) {
	for kind, want := range map[string]string{
		"Deployment":    "deployments",
		"Ingress":       "ingresses",
		"IngressClass":  "ingressclasses",
		"StorageClass":  "storageclasses",
		"NetworkPolicy": "networkpolicies",
		"PriorityClass": "priorityclasses",
		"Gateway":       "gateways",
		"Endpoints":     "endpoints",
		"EndpointSlice": "endpointslices",
		"Pod":           "pods",
		"":              "",
	} {
		if got := makePlural(kind); got != want {
			t.Errorf("makePlural(%q) = %q, want %q", kind, got, want)
		}
	}
}

const ingress = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: shop
  labels: {tier: frontend}
`

const namespaceObject = `
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels: {env: dev}
`

func constraintsPolicy(constraints string) string {
	return `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test
spec:
  matchConstraints:
` + constraints + `
  validations:
  - expression: "true"
`
}

func matches(t *testing.T, policy, object, namespace string) (bool, string) {
	t.Helper()
	evaluator, err := NewAdmissionPolicyEvaluator([]byte(policy), []byte(object), nil, nil, nil, []byte(namespace))
	if err != nil {
		t.Fatalf("NewAdmissionPolicyEvaluator: %v", err)
	}
	evaluator.CheckMatchConstraints()
	return evaluator.Results.MatchConstraints, evaluator.Results.MatchReason
}

const ingressRule = `    resourceRules:
    - {apiGroups: [networking.k8s.io], apiVersions: [v1], operations: [CREATE], resources: [ingresses]`

func TestIngressMatchesItsResource(t *testing.T) {
	if matched, reason := matches(t, constraintsPolicy(ingressRule+"}"), ingress, ""); !matched {
		t.Errorf("an Ingress should match the ingresses rule: %s", reason)
	}
}

func TestExcludeResourceRules(t *testing.T) {
	policy := constraintsPolicy(ingressRule + `}
    excludeResourceRules:
    - {apiGroups: ["*"], apiVersions: ["*"], operations: ["*"], resources: [ingresses], resourceNames: [web]}`)
	matched, reason := matches(t, policy, ingress, "")
	if matched || !strings.Contains(reason, "excludeResourceRule") {
		t.Errorf("an excluded resource should not match, got %v %q", matched, reason)
	}
	other := strings.Replace(ingress, "name: web", "name: api", 1)
	if matched, reason := matches(t, policy, other, ""); !matched {
		t.Errorf("a resource of another name should match: %s", reason)
	}
}

func TestResourceNamesAndScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		{"named", `, resourceNames: [web]}`, true},
		{"other name", `, resourceNames: [api]}`, false},
		{"namespaced scope", `, scope: Namespaced}`, true},
		{"cluster scope", `, scope: Cluster}`, false},
		{"any scope", `, scope: "*"}`, true},
	} {
		if matched, _ := matches(t, constraintsPolicy(ingressRule+tc.rule), ingress, ""); matched != tc.want {
			t.Errorf("%s: expected %v, got %v", tc.name, tc.want, matched)
		}
	}
	// a Namespace is cluster-scoped
	namespaceRule := `    resourceRules:
    - {apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [namespaces], scope: Cluster}`
	if matched, reason := matches(t, constraintsPolicy(namespaceRule), namespaceObject, ""); !matched {
		t.Errorf("a Namespace should match the Cluster scope: %s", reason)
	}
}

func TestScopeOfAResourceWithoutNamespace(t *testing.T) {
	anyResource := `    resourceRules:
    - {apiGroups: ["*"], apiVersions: ["*"], operations: ["*"], resources: ["*"]`
	selector := "}\n    namespaceSelector: {matchLabels: {env: dev}}"
	for _, tc := range []struct {
		name        string
		object      string
		rule        string
		want        bool
		wantGuessed string
	}{
		// a namespaceSelector never leaves out a cluster-scoped object
		{"known cluster-scoped kind", "apiVersion: kubescape.io/v1\nkind: ControlConfiguration\nmetadata: {name: basic}\n", selector, true, ""},
		{"kind that starts with Cluster", "apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata: {name: ca}\n", selector, true, ""},
		{"other kind", "apiVersion: cert-manager.io/v1\nkind: Issuer\nmetadata: {name: ca}\n", selector, false, "taken as a namespaced one"},
		{"cluster scope, known kind", "apiVersion: networking.k8s.io/v1\nkind: ServiceCIDR\nmetadata: {name: extra}\n", ", scope: Cluster}", true, ""},
		{"namespaced scope, known kind", "apiVersion: networking.k8s.io/v1\nkind: ServiceCIDR\nmetadata: {name: extra}\n", ", scope: Namespaced}", false, ""},
		{"namespaced scope, kind that starts with Cluster", "apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata: {name: ca}\n", ", scope: Namespaced}", false, "taken as a cluster-scoped one"},
		{"cluster scope, other kind", "apiVersion: cert-manager.io/v1\nkind: Issuer\nmetadata: {name: ca}\n", ", scope: Cluster}", false, "taken as a namespaced one"},
		// a Namespace is cluster-scoped, although its request names it as its namespace
		{"namespaced scope, Namespace", namespaceObject, ", scope: Namespaced}", false, ""},
		// the scope of an object in a namespace is no guess
		{"cluster scope, object in a namespace", ingress, ", scope: Cluster}", false, ""},
	} {
		matched, reason := matches(t, constraintsPolicy(anyResource+tc.rule), tc.object, "")
		if matched != tc.want {
			t.Errorf("%s: expected %v, got %v (%s)", tc.name, tc.want, matched, reason)
		}
		if guessed := strings.Contains(reason, "was taken as"); guessed != (tc.wantGuessed != "") || !strings.Contains(reason, tc.wantGuessed) {
			t.Errorf("%s: expected the reason to say %q, got %q", tc.name, tc.wantGuessed, reason)
		}
	}
}

func TestNamespaceSelector(t *testing.T) {
	for _, tc := range []struct {
		selector string
		want     bool
	}{
		{`{matchLabels: {env: dev}}`, true},
		{`{matchLabels: {env: prd}}`, false},
		{`{matchExpressions: [{key: env, operator: In, values: [dev, tst]}]}`, true},
		{`{matchExpressions: [{key: env, operator: NotIn, values: [dev]}]}`, false},
		{`{matchExpressions: [{key: team, operator: DoesNotExist}]}`, true},
		{`{matchExpressions: [{key: team, operator: Exists}]}`, false},
		{`{}`, true},
	} {
		policy := constraintsPolicy(ingressRule + "}\n    namespaceSelector: " + tc.selector)
		if matched, reason := matches(t, policy, ingress, namespaceObject); matched != tc.want {
			t.Errorf("%s: expected %v, got %v (%s)", tc.selector, tc.want, matched, reason)
		}
	}
	// the selector applies to the labels of a Namespace itself
	namespaceRule := `    resourceRules:
    - {apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [namespaces]}
    namespaceSelector: {matchLabels: {env: dev}}`
	if matched, reason := matches(t, constraintsPolicy(namespaceRule), namespaceObject, ""); !matched {
		t.Errorf("a Namespace with the label should be selected: %s", reason)
	}
}

func TestObjectSelector(t *testing.T) {
	selected := constraintsPolicy(ingressRule + "}\n    objectSelector: {matchLabels: {tier: frontend}}")
	if matched, reason := matches(t, selected, ingress, ""); !matched {
		t.Errorf("the labelled Ingress should be selected: %s", reason)
	}
	other := constraintsPolicy(ingressRule + "}\n    objectSelector: {matchLabels: {tier: backend}}")
	if matched, reason := matches(t, other, ingress, ""); matched || !strings.Contains(reason, "objectSelector") {
		t.Errorf("an Ingress without the label should not be selected, got %v %q", matched, reason)
	}
}

func TestFailingMatchConditionAppliesTheFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		failurePolicy string
		wantIgnore    bool
	}{{"", false}, {"failurePolicy: Fail", false}, {"failurePolicy: Ignore", true}} {
		policy := policyWith(`
  ` + tc.failurePolicy + `
  matchConditions:
  - name: broken
    expression: "object.spec.missing.field == 1"
  validations:
  - expression: "false"
`)
		results := evaluate(t, policy, deployment, "", "")
		if !strings.HasPrefix(results.MatchConditionError, "broken: ") {
			t.Errorf("%q: expected the error of the condition, got %q", tc.failurePolicy, results.MatchConditionError)
		}
		if results.FailurePolicyIgnore != tc.wantIgnore {
			t.Errorf("%q: expected ignore %v", tc.failurePolicy, tc.wantIgnore)
		}
		if len(results.Validations) != 0 {
			t.Errorf("%q: the validations should not run", tc.failurePolicy)
		}
	}

	// a condition that is false skips the policy, also when another one fails
	skipped := evaluate(t, policyWith(`
  matchConditions:
  - name: broken
    expression: "object.spec.missing.field == 1"
  - name: other
    expression: "false"
`), deployment, "", "")
	if skipped.MatchConditionError != "" {
		t.Errorf("a false condition should skip the policy, got %q", skipped.MatchConditionError)
	}
}

func TestMessageExpressionComesBeforeMessage(t *testing.T) {
	results := evaluate(t, policyWith(`
  validations:
  - expression: "false"
    message: "static"
    messageExpression: "'replicas: ' + string(object.spec.replicas)"
  - expression: "false"
    message: "static"
    messageExpression: "object.spec.missing"
  - expression: "false"
    messageExpression: "'only the expression'"
`), deployment, "", "")
	for i, want := range []string{"replicas: 5", "static", "only the expression"} {
		if got := validation(t, results, i).Message; got != want {
			t.Errorf("validation %d: expected message %q, got %v", i+1, want, got)
		}
	}
}

func TestAuditAnnotationsAreConverted(t *testing.T) {
	results := evaluate(t, policyWith(`
  auditAnnotations:
  - key: replicas
    valueExpression: "string(object.spec.replicas)"
  - key: nothing
    valueExpression: "null"
`), deployment, "", "")
	if len(results.AuditAnnotations) != 2 {
		t.Fatalf("expected 2 audit annotations, got %+v", results.AuditAnnotations)
	}
	value, ok := results.AuditAnnotations[0].Result.(*structpb.Value)
	if !ok || value.GetStringValue() != "5" {
		t.Errorf("expected the annotation 5, got %v", results.AuditAnnotations[0].Result)
	}
	null, ok := results.AuditAnnotations[1].Result.(*structpb.Value)
	if !ok {
		t.Fatalf("expected a JSON value, got %T", results.AuditAnnotations[1].Result)
	}
	if _, isNull := null.GetKind().(*structpb.Value_NullValue); !isNull {
		t.Errorf("expected null, got %v", null)
	}
}
