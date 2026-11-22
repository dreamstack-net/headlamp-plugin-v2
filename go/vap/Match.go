package vap

import (
	"log"
	"slices"
	"strings"
)

// requestAttributes are the attributes of the admission request that resource rules match on
type requestAttributes struct {
	operation   string
	group       string
	version     string
	resource    string
	subResource string
	name        string
	// whether the object is namespaced, for the scope of a rule
	namespaced bool
}

func stringField(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

// clusterScopedKinds are the kinds of the cluster-scoped resources of Kubernetes and Kubescape,
// which the scope of a rule tells apart from namespaced ones.
var clusterScopedKinds = map[string]bool{
	"Namespace":                        true,
	"Node":                             true,
	"PersistentVolume":                 true,
	"ComponentStatus":                  true,
	"StorageClass":                     true,
	"CSIDriver":                        true,
	"CSINode":                          true,
	"VolumeAttachment":                 true,
	"VolumeAttributesClass":            true,
	"StorageVersionMigration":          true,
	"StorageVersion":                   true,
	"ClusterRole":                      true,
	"ClusterRoleBinding":               true,
	"CustomResourceDefinition":         true,
	"APIService":                       true,
	"PriorityClass":                    true,
	"RuntimeClass":                     true,
	"IngressClass":                     true,
	"IPAddress":                        true,
	"ServiceCIDR":                      true,
	"MutatingWebhookConfiguration":     true,
	"ValidatingWebhookConfiguration":   true,
	"ValidatingAdmissionPolicy":        true,
	"ValidatingAdmissionPolicyBinding": true,
	"MutatingAdmissionPolicy":          true,
	"MutatingAdmissionPolicyBinding":   true,
	"CertificateSigningRequest":        true,
	"ClusterTrustBundle":               true,
	"TokenReview":                      true,
	"SelfSubjectReview":                true,
	"SubjectAccessReview":              true,
	"SelfSubjectAccessReview":          true,
	"SelfSubjectRulesReview":           true,
	"FlowSchema":                       true,
	"PriorityLevelConfiguration":       true,
	"DeviceClass":                      true,
	"ResourceSlice":                    true,
	"DeviceTaintRule":                  true,
	"GatewayClass":                     true,
	"ClusterSecurityException":         true,
	"ControlConfiguration":             true,
	"RuntimeRuleAlertBinding":          true,
}

// resourceScope tells whether the object of the request is a namespaced resource, and whether
// that is a guess. The API server knows the scope of every resource; here an object that names
// a namespace is namespaced and a Namespace is cluster-scoped, although its request names it as
// its namespace. An object without a namespace is cluster-scoped when its kind is a known
// cluster-scoped one. Otherwise its scope is guessed: cluster-scoped for a kind that starts
// with Cluster, such as the ClusterIssuer of a CRD, and namespaced for any other kind, as the
// YAML of a namespaced object often leaves out the namespace.
func (evaluator *AdmissionPolicyEvaluator) resourceScope() (namespaced, guessed bool) {
	kind, _ := evaluator.object["kind"].(string)
	switch {
	case kind == "Namespace":
		return false, false
	case stringField(evaluator.request, "namespace") != "":
		return true, false
	case clusterScopedKinds[kind]:
		return false, false
	case strings.HasPrefix(kind, "Cluster"):
		return false, true
	}
	return true, true
}

// usesScope tells whether one of the rules is only for namespaced or for cluster-scoped
// resources
func usesScope(rules []NamedRuleWithOperations) bool {
	for _, rule := range rules {
		if rule.Scope != nil && *rule.Scope != AllScopes {
			return true
		}
	}
	return false
}

// CheckMatchConstraints matches the request against the match constraints of the policy like
// the API server does: the resource rules on operation, API group, API version, resource, name
// and scope, where '*' matches any value, without the excluded resource rules, and the
// namespace and object selectors. MatchReason says why a request does not match.
func (evaluator *AdmissionPolicyEvaluator) CheckMatchConstraints() {

	if value, ok := evaluator.object["apiVersion"]; !ok || value == nil {
		evaluator.Results.MatchReason = "The resource has no apiVersion."
		return
	}
	if value, ok := evaluator.object["kind"]; !ok || value == nil {
		evaluator.Results.MatchReason = "The resource has no kind."
		return
	}
	constraints := evaluator.policy.Spec.MatchConstraints
	if constraints == nil {
		evaluator.Results.MatchReason = "The policy has no matchConstraints."
		return
	}

	resource, _ := evaluator.request["resource"].(map[string]any)
	namespaced, guessed := evaluator.resourceScope()
	attributes := requestAttributes{
		operation:   stringField(evaluator.request, "operation"),
		group:       stringField(resource, "group"),
		version:     stringField(resource, "version"),
		resource:    stringField(resource, "resource"),
		subResource: stringField(evaluator.request, "subResource"),
		name:        stringField(evaluator.request, "name"),
		namespaced:  namespaced,
	}
	// said after a reason that depends on a scope that was guessed
	scopeGuess := ""
	if guessed && namespaced {
		scopeGuess = " The resource names no namespace and was taken as a namespaced one, as its kind is not a known cluster-scoped kind."
	} else if guessed {
		scopeGuess = " The resource names no namespace and was taken as a cluster-scoped one, as its kind starts with Cluster."
	}

	matched := false
	for _, resourceRule := range constraints.ResourceRules {
		if match(resourceRule, attributes) {
			matched = true
			break
		}
	}
	if !matched {
		log.Printf("Request %+v NOT matched", attributes)
		evaluator.Results.MatchReason = "No resourceRule of the policy matches the request."
		if usesScope(constraints.ResourceRules) {
			evaluator.Results.MatchReason += scopeGuess
		}
		return
	}
	for _, resourceRule := range constraints.ExcludeResourceRules {
		if match(resourceRule, attributes) {
			evaluator.Results.MatchReason = "An excludeResourceRule of the policy matches the request."
			if usesScope(constraints.ExcludeResourceRules) {
				evaluator.Results.MatchReason += scopeGuess
			}
			return
		}
	}
	if !evaluator.namespaceSelected(constraints.NamespaceSelector, attributes.namespaced) {
		evaluator.Results.MatchReason = "The namespaceSelector of the policy does not select the namespace." + scopeGuess
		return
	}
	if !evaluator.objectSelected(constraints.ObjectSelector) {
		evaluator.Results.MatchReason = "The objectSelector of the policy does not select the resource."
		return
	}
	evaluator.Results.MatchConstraints = true
}

// namespaceSelected applies the namespace selector like the API server: to the labels of the
// namespace of a namespaced object, to the labels of a Namespace itself, and not to other
// cluster-scoped objects.
func (evaluator *AdmissionPolicyEvaluator) namespaceSelected(selector *LabelSelector, namespaced bool) bool {
	if selector == nil {
		return true
	}
	if kind, _ := evaluator.object["kind"].(string); kind == "Namespace" {
		return selector.Matches(labelsOf(evaluator.object))
	}
	if !namespaced {
		return true
	}
	return selector.Matches(labelsOf(evaluator.namespaceObject))
}

// objectSelected applies the object selector to the object and the old object, like the API
// server, which runs the policy when either of them is selected.
func (evaluator *AdmissionPolicyEvaluator) objectSelected(selector *LabelSelector) bool {
	if selector == nil {
		return true
	}
	if evaluator.object != nil && selector.Matches(labelsOf(evaluator.object)) {
		return true
	}
	return evaluator.oldObject != nil && selector.Matches(labelsOf(evaluator.oldObject))
}

func labelsOf(object ObjectData) map[string]string {
	labels := map[string]string{}
	metadata, _ := object["metadata"].(map[string]any)
	values, _ := metadata["labels"].(map[string]any)
	for key, value := range values {
		if text, ok := value.(string); ok {
			labels[key] = text
		}
	}
	return labels
}

// Matches reports whether the labels satisfy the selector. An empty selector selects
// everything.
func (selector *LabelSelector) Matches(labels map[string]string) bool {
	for key, value := range selector.MatchLabels {
		if actual, found := labels[key]; !found || actual != value {
			return false
		}
	}
	for _, requirement := range selector.MatchExpressions {
		value, found := labels[requirement.Key]
		switch requirement.Operator {
		case LabelSelectorOpIn:
			if !found || !contains(requirement.Values, value) {
				return false
			}
		case LabelSelectorOpNotIn:
			if found && contains(requirement.Values, value) {
				return false
			}
		case LabelSelectorOpExists:
			if !found {
				return false
			}
		case LabelSelectorOpDoesNotExist:
			if found {
				return false
			}
		default:
			// the API server rejects other operators
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	return slices.Contains(values, value)
}

// pluralExceptions are the resources of Kubernetes whose plural the rules below do not form
var pluralExceptions = map[string]string{
	"endpoints": "endpoints",
}

// makePlural guesses the resource of a kind, as the API server names it: Ingress becomes
// ingresses, NetworkPolicy networkpolicies and Gateway gateways.
func makePlural(kind string) string {
	singular := strings.ToLower(kind)
	if plural, found := pluralExceptions[singular]; found {
		return plural
	}
	switch {
	case singular == "":
		return ""
	case strings.HasSuffix(singular, "s"), strings.HasSuffix(singular, "x"),
		strings.HasSuffix(singular, "ch"), strings.HasSuffix(singular, "sh"):
		return singular + "es"
	case strings.HasSuffix(singular, "y") && len(singular) > 1 &&
		!strings.ContainsRune("aeiou", rune(singular[len(singular)-2])):
		return singular[:len(singular)-1] + "ies"
	}
	return singular + "s"
}

func match(resourceRule NamedRuleWithOperations, attributes requestAttributes) bool {
	return matchesAny(resourceRule.Operations, attributes.operation) &&
		matchesAny(resourceRule.APIGroups, attributes.group) &&
		matchesAny(resourceRule.APIVersions, attributes.version) &&
		matchesResource(resourceRule.Resources, attributes.resource, attributes.subResource) &&
		matchesName(resourceRule.ResourceNames, attributes.name) &&
		matchesScope(resourceRule.Scope, attributes.namespaced)
}

// matchesAny reports whether one of the values is '*' or the given value
func matchesAny[T ~string](values []T, value string) bool {
	for _, v := range values {
		if string(v) == "*" || string(v) == value {
			return true
		}
	}
	return false
}

// matchesName reports whether the rule applies to the name: an empty list allows all names
func matchesName(names []string, name string) bool {
	return len(names) == 0 || contains(names, name)
}

// matchesScope reports whether the scope of the rule includes the resource, "*" by default
func matchesScope(scope *ScopeType, namespaced bool) bool {
	if scope == nil {
		return true
	}
	switch *scope {
	case ClusterScope:
		return !namespaced
	case NamespacedScope:
		return namespaced
	}
	return true
}

// matchesResource reports whether the resource and subresource match one of the patterns:
// 'pods' matches pods, 'pods/log' its log subresource, 'pods/*' pods and all its subresources,
// '*' all resources but no subresources, '*/scale' all scale subresources and '*/*' everything.
func matchesResource(patterns []string, resource, subResource string) bool {
	for _, pattern := range patterns {
		patternResource, patternSubResource, _ := strings.Cut(pattern, "/")
		if (patternResource == "*" || patternResource == resource) &&
			(patternSubResource == "*" || patternSubResource == subResource) {
			return true
		}
	}
	return false
}
