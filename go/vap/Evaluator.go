package vap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/types/known/structpb"
	"sigs.k8s.io/yaml"
)

var celDefaultEnvOptions = []cel.EnvOption{
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
	ext.Strings(ext.StringsVersion(2)),
	cel.CrossTypeNumericComparisons(true),
	cel.OptionalTypes(),

	// library.Lists(),
	// library.Regex(),
	// library.CIDR(),
	// library.IP(),
	// library.URLs(),
}

type EvalResult struct {
	Name       string `json:"name,omitempty"`
	Expression string `json:"expression,omitempty"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	Message    any    `json:"message,omitempty"`
}

type EvaluationResults struct {
	Error            string        `json:"error,omitempty"`
	Variables        []*EvalResult `json:"variables,omitempty"`
	MatchConstraints bool          `json:"matchConstraints"`
	// why the request does not match the constraints
	MatchReason     string        `json:"matchReason,omitempty"`
	MatchConditions []*EvalResult `json:"matchConditions,omitempty"`
	// false when a match condition is false, so the API server skips the policy; only set when
	// the request matches the constraints
	MatchConditionsMatched bool `json:"matchConditionsMatched"`
	// a match condition that failed while none is false. The API server then applies the
	// failurePolicy: Ignore admits the request, Fail, the default, makes it a violation, which
	// the validationActions of the binding deny, warn about or audit
	MatchConditionError string `json:"matchConditionError,omitempty"`
	// whether the failurePolicy of the policy is Ignore, which admits a request whose
	// evaluation fails
	FailurePolicyIgnore bool          `json:"failurePolicyIgnore,omitempty"`
	Validations         []*EvalResult `json:"validations,omitempty"`
	AuditAnnotations    []*EvalResult `json:"auditAnnotations,omitempty"`
	// an audit annotation for which the API server rejects the request, whatever the
	// validationActions of the binding: its value is not a string or null, or, unless the
	// failurePolicy is Ignore, it failed
	AuditAnnotationError string `json:"auditAnnotationError,omitempty"`
}

// the longest message of a messageExpression the API server uses
// (k8s.io/apiserver/pkg/apis/cel.MaxEvaluatedMessageExpressionSizeBytes)
const maxMessageExpressionBytes = 5 * 1024

type ObjectData map[string]any

// AdmissionPolicyEvaluator holds policy, data and results for a single validation run
type AdmissionPolicyEvaluator struct {
	policy          ValidatingAdmissionPolicy
	object          ObjectData
	oldObject       ObjectData
	request         ObjectData
	paramsObject    ObjectData
	namespaceObject ObjectData

	celEnvironment *cel.Env

	Results EvaluationResults
}

// 'object' - The object from the incoming request. The value is null for DELETE requests.
// 'oldObject' - The existing object. The value is null for CREATE requests.
// 'request' - Attributes of the admission request. Missing attributes are those of the CREATE or UPDATE request for the object.
// 'params' - Parameter resource referred to by the policy binding being evaluated. The value is null if ParamKind is not specified.
// namespaceObject - The namespace, as a Kubernetes resource, that the incoming object belongs to. The value is null if the incoming object is cluster-scoped.
// authorizer - A CEL Authorizer. May be used to perform authorization checks for the principal (authenticated user) of the request. See AuthzSelectors and Authz in the Kubernetes CEL library documentation for more details.
// authorizer.requestResource - A shortcut for an authorization check configured with the request resource (group, resource, (subresource), namespace, name).
func NewAdmissionPolicyEvaluator(policy, object, oldObject, request, params, namespace []byte) (*AdmissionPolicyEvaluator, error) {

	evaluator := AdmissionPolicyEvaluator{
		Results: EvaluationResults{},
	}

	if err := yaml.Unmarshal(policy, &evaluator.policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	var err error
	if evaluator.object, err = unmarshalObject(object); err != nil {
		return nil, fmt.Errorf("failed to parse object YAML: %w", err)
	}

	if evaluator.oldObject, err = unmarshalObject(oldObject); err != nil {
		return nil, fmt.Errorf("failed to parse oldObject YAML: %w", err)
	}

	if evaluator.request, err = unmarshalObject(request); err != nil {
		return nil, fmt.Errorf("failed to parse request YAML: %w", err)
	}
	// Attributes missing from the request are those of the request for the object
	defaults := evaluator.defaultRequest()
	if evaluator.request == nil {
		evaluator.request = defaults
	}
	for key, value := range defaults {
		if _, found := evaluator.request[key]; !found {
			evaluator.request[key] = value
		}
	}

	if evaluator.paramsObject, err = unmarshalObject(params); err != nil {
		return nil, fmt.Errorf("failed to parse params YAML: %w", err)
	}

	if evaluator.namespaceObject, err = unmarshalObject(namespace); err != nil {
		return nil, fmt.Errorf("failed to parse namespace YAML: %w", err)
	}

	// Declare input data as variables, policy variables are accessed as variables.<name>
	envOptions := append([]cel.EnvOption{}, celDefaultEnvOptions...)
	envOptions = append(envOptions,
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("params", cel.DynType),
		cel.Variable("namespaceObject", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)))
	// Init CEL environment
	if celEnvironment, err := cel.NewEnv(envOptions...); err == nil {
		evaluator.celEnvironment = celEnvironment
	} else {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	return &evaluator, nil
}

// unmarshalObject reads an object with whole numbers as integers and the other numbers as
// doubles, as the API server reads the JSON of a request, rather than all of them as the
// doubles of JSON: integer arithmetic on a double, such as replicas % 2, has no overload
func unmarshalObject(data []byte) (ObjectData, error) {
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	var object ObjectData
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	convertNumbers(map[string]any(object))
	return object, nil
}

func convertNumbers(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			v[key] = convertNumbers(item)
		}
	case []any:
		for i, item := range v {
			v[i] = convertNumbers(item)
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	}
	return value
}

// defaultRequest returns the attributes of the request the API server would send when the
// object is admitted: an UPDATE when there is an old object, a CREATE otherwise.
func (evaluator *AdmissionPolicyEvaluator) defaultRequest() ObjectData {
	apiVersion, _ := evaluator.object["apiVersion"].(string)
	kind, _ := evaluator.object["kind"].(string)
	group, version, found := strings.Cut(apiVersion, "/")
	if !found {
		group, version = "", apiVersion
	}
	metadata, _ := evaluator.object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	// the request for a Namespace names the Namespace itself as its namespace
	if kind == "Namespace" && group == "" {
		namespace = name
	}

	operation := "CREATE"
	if evaluator.oldObject != nil {
		operation = "UPDATE"
	}
	groupVersionKind := map[string]any{"group": group, "version": version, "kind": kind}
	groupVersionResource := map[string]any{"group": group, "version": version, "resource": strings.ToLower(makePlural(kind))}

	return ObjectData{
		"kind":            groupVersionKind,
		"resource":        groupVersionResource,
		"requestKind":     groupVersionKind,
		"requestResource": groupVersionResource,
		"name":            name,
		"namespace":       namespace,
		"operation":       operation,
		"userInfo":        map[string]any{},
		"dryRun":          false,
	}
}

func (evaluator *AdmissionPolicyEvaluator) Evaluate() {

	// Input Variables. Like the API server, params and namespaceObject are null when there are
	// none, rather than empty maps
	variables := map[string]any{}
	inputData := map[string]any{
		"object":          evaluator.object,
		"oldObject":       nullIfEmpty(evaluator.oldObject),
		"request":         evaluator.request,
		"params":          nullIfEmpty(evaluator.paramsObject),
		"namespaceObject": nullIfEmpty(evaluator.namespaceObject),
		"variables":       variables,
	}

	// Policy variables, which may refer to the variables defined before them
	for _, variable := range evaluator.policy.Spec.Variables {
		value, err := evaluator.evalExpression(inputData, variable.Expression)
		if err != nil {
			// Expressions that use the variable fail with its error
			variables[variable.Name] = types.WrapErr(err)
		} else {
			variables[variable.Name] = value
		}

		evaluator.Results.Variables = append(evaluator.Results.Variables, &EvalResult{
			Name:   variable.Name,
			Result: getResult(value),
			Error:  errorString(err),
		})
	}

	evaluator.Results.FailurePolicyIgnore = evaluator.policy.Spec.FailurePolicy != nil &&
		*evaluator.policy.Spec.FailurePolicy == Ignore

	// The API server evaluates the match conditions before the variables, and does not accept a
	// policy whose match conditions use them. It gives them no namespace either: namespaceObject
	// is null in a match condition, also for an object in a namespace
	matchConditionData := map[string]any{}
	for key, value := range inputData {
		if key != "variables" {
			matchConditionData[key] = value
		}
	}
	matchConditionData["namespaceObject"] = nil
	for _, matchCondition := range evaluator.policy.Spec.MatchConditions {
		if evaluator.usesVariables(matchCondition.Expression) {
			evaluator.Results.Error = fmt.Sprintf("the match condition %s uses variables, which the "+
				"API server does not accept: it evaluates match conditions before the variables",
				matchCondition.Name)
			return
		}
	}

	// MatchConditions: a condition that is false skips the policy; one that fails, while no
	// other is false, applies the failurePolicy
	matched := true
	var conditionError string
	for _, matchCondition := range evaluator.policy.Spec.MatchConditions {
		value, err := evaluator.evalExpression(matchConditionData, matchCondition.Expression)
		evaluator.Results.MatchConditions = append(evaluator.Results.MatchConditions, &EvalResult{
			Name:   matchCondition.Name,
			Result: getResult(value),
			Error:  errorString(err),
		})
		switch {
		case err != nil:
			if conditionError == "" {
				conditionError = fmt.Sprintf("%s: %v", matchCondition.Name, err)
			}
		case value == nil || value.Value() != true:
			matched = false
		}
	}

	evaluator.Results.MatchConditionsMatched = matched
	if !matched {
		return
	}
	if conditionError != "" {
		evaluator.Results.MatchConditionError = conditionError
		return
	}

	// Validations
	for idx, validation := range evaluator.policy.Spec.Validations {
		value, err := evaluator.evalExpression(inputData, validation.Expression)
		evalResult := &EvalResult{
			Name:       fmt.Sprintf("%d", idx+1),
			Expression: validation.Expression,
			Result:     getResult(value),
			Error:      errorString(err),
		}

		if err == nil && value != nil && value.Value() != true {
			evalResult.Message = evaluator.failureMessage(inputData, validation)
		}

		evaluator.Results.Validations = append(evaluator.Results.Validations, evalResult)
	}

	// AuditAnnotations: the API server publishes a string, leaves out null and an empty string,
	// and rejects the request for any other value, whatever the failurePolicy and the
	// validationActions; an annotation that fails rejects it unless the failurePolicy is Ignore
	for _, auditAnnotation := range evaluator.policy.Spec.AuditAnnotations {
		value, err := evaluator.evalExpression(inputData, auditAnnotation.ValueExpression)
		result := &EvalResult{
			Name:       auditAnnotation.Key,
			Expression: auditAnnotation.ValueExpression,
			Result:     getResult(value),
			Error:      errorString(err),
		}
		if err == nil && value != nil {
			switch value.(type) {
			case types.String, types.Null:
			default:
				result.Error = fmt.Sprintf("valueExpression '%v' resulted in unsupported return type: %v. "+
					"Return type must be either string or null.", auditAnnotation.ValueExpression, value.Type())
				if evaluator.Results.AuditAnnotationError == "" {
					evaluator.Results.AuditAnnotationError = fmt.Sprintf("%s: %s", auditAnnotation.Key, result.Error)
				}
			}
		}
		if err != nil && !evaluator.Results.FailurePolicyIgnore && evaluator.Results.AuditAnnotationError == "" {
			evaluator.Results.AuditAnnotationError = fmt.Sprintf("%s: %v", auditAnnotation.Key, err)
		}
		evaluator.Results.AuditAnnotations = append(evaluator.Results.AuditAnnotations, result)
	}
}

// failureMessage is the message of a validation that is not true, as the API server makes it:
// the result of the messageExpression, without surrounding white space, unless it fails, is not
// a string, is empty, longer than 5 KiB or more than one line; else the message, without
// surrounding white space; else the expression.
func (evaluator *AdmissionPolicyEvaluator) failureMessage(inputData map[string]any, validation Validation) string {
	message := ""
	if validation.MessageExpression != "" {
		value, err := evaluator.evalExpression(inputData, validation.MessageExpression)
		if err == nil && value != nil {
			if text, ok := value.Value().(string); ok {
				text = strings.TrimSpace(text)
				if len(text) <= maxMessageExpressionBytes && !strings.Contains(text, "\n") {
					message = text
				}
			}
		}
	}
	if message == "" {
		message = strings.TrimSpace(validation.Message)
	}
	if message == "" {
		message = fmt.Sprintf("failed expression: %v", strings.TrimSpace(validation.Expression))
	}
	return message
}

// usesVariables tells whether the expression refers to the variables of the policy
func (evaluator *AdmissionPolicyEvaluator) usesVariables(expression string) bool {
	parsed, issues := evaluator.celEnvironment.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return false
	}
	found := false
	celast.PreOrderVisit(parsed.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() == celast.IdentKind && e.AsIdent() == "variables" {
			found = true
		}
	}))
	return found
}

// nullIfEmpty binds absent input as null, like the API server does for oldObject on CREATE
func nullIfEmpty(data ObjectData) any {
	if data == nil {
		return nil
	}
	return data
}

func errorString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// evalExpression parses and evaluates the expression. Unlike the API server, it does not
// type-check: the Kubernetes CEL libraries (quantity, regex, ...) are not part of this
// environment, and the checker would reject every expression that calls them, even when
// evaluation never reaches the call.
func (evaluator *AdmissionPolicyEvaluator) evalExpression(inputData map[string]any, expression string) (ref.Val, error) {
	ast, issues := evaluator.celEnvironment.Parse(expression)
	if issues != nil && issues.Err() != nil {
		log.Printf("Parse: %v", issues.String())
		return nil, issues.Err()
	}
	prog, err := evaluator.celEnvironment.Program(ast)
	if err != nil {
		log.Printf("Program: %v", err)
		return nil, err
	}
	result, _, err := prog.Eval(inputData)
	if err != nil {
		log.Printf("Eval %v", err)
		return nil, err
	}
	return result, nil
}

func getResult(val ref.Val) any {
	if val == nil {
		return nil
	}
	if err, ok := val.Value().(error); ok {
		return err.Error()
	}
	value, err := val.ConvertToNative(reflect.TypeFor[*structpb.Value]())
	if err != nil {
		return err.Error()
	}
	// JSON has no NaN and no infinity, which a division of doubles by zero gives; such a value
	// is shown as text, as it would fail the JSON of all results
	if jsonValue, ok := value.(*structpb.Value); ok {
		if _, err := jsonValue.MarshalJSON(); err != nil {
			return fmt.Sprintf("%v", val.Value())
		}
	}
	return value
}
