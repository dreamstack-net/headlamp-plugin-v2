package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"sigs.k8s.io/yaml"
)

const (
	// admissionEventType is the event type of the rules the operator evaluates against the
	// requests of its admission webhook, rather than the node-agent against runtime events
	admissionEventType = "k8s-admission"
	// dnsQueryEventType selects the expressions for DNS queries and error responses; the
	// node-agent evaluates them with the tracer's event type, dns
	dnsQueryEventType = "dnsQuery"
	httpEventType     = "http"
)

var celBaseOptions = []cel.EnvOption{
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
}

// RuleExprResult is the evaluation result for a single ruleExpression entry.
type RuleExprResult struct {
	EventType  string `json:"eventType"`
	Expression string `json:"expression"`
	Result     *bool  `json:"result"`
	Error      string `json:"error,omitempty"`
	// CompileError tells that the error is of the expression itself, which does not compile for
	// any event, rather than of evaluating it against this event
	CompileError bool `json:"compileError,omitempty"`
}

// StringExprResult is the evaluation result for message or uniqueId expressions.
type StringExprResult struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
	// CompileError tells that the error is of the expression itself, as in RuleExprResult
	CompileError bool `json:"compileError,omitempty"`
}

// RuleEvalResults is the top-level result returned by Evaluate().
type RuleEvalResults struct {
	Error             string           `json:"error,omitempty"`
	EventTypeMismatch string           `json:"eventTypeMismatch,omitempty"`
	RuleExpression    []RuleExprResult `json:"ruleExpression"`
	// Fired tells whether the rule alerts on the event: every expression of the event type is
	// true, as the node-agent and the operator require
	Fired bool `json:"fired"`
	// Prefiltered is why the node-agent skips the event before it evaluates the expressions:
	// the prefilter parameters of the rule's state exclude it, so the rule does not fire
	Prefiltered string           `json:"prefiltered,omitempty"`
	Message     StringExprResult `json:"message"`
	UniqueID    StringExprResult `json:"uniqueId"`
}

// RuleEvaluator holds everything needed for a single evaluation run.
type RuleEvaluator struct {
	rule      Rule
	eventType string
	event     map[string]any
	inputData map[string]any
	celEnv    *cel.Env
}

// NewRuleEvaluator parses its raw YAML/JSON inputs and builds the CEL environment.
//
//   - ruleYAML:   full Rules CR YAML; the first rule in spec.rules is evaluated
//   - eventType:  e.g. "exec", "open", "dns", "dnsQuery", "k8s-admission"
//   - eventData:  raw JSON/YAML for the event fields; of a k8s-admission event, its Object,
//     OldObject and Options are the variables object, oldObject and options
//   - profileData: optional ApplicationProfile mock (YAML keyed by containerId); empty slice → empty profile
//   - networkData: optional NetworkNeighborhood mock (YAML keyed by containerId); empty slice → empty network
//   - k8sData: optional Kubernetes mock (API server address and pods); empty slice → nothing known
func NewRuleEvaluator(ruleYAML []byte, eventType string, eventData, profileData, networkData, k8sData []byte) (*RuleEvaluator, error) {
	var rulesDoc Rules
	if err := yaml.Unmarshal(ruleYAML, &rulesDoc); err != nil {
		return nil, fmt.Errorf("failed to parse rule YAML: %w", err)
	}
	if len(rulesDoc.Spec.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in YAML")
	}

	event, err := parseEvent(eventData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event data: %w", err)
	}

	var profile MockProfile
	if len(profileData) > 0 {
		if err := yaml.Unmarshal(profileData, &profile); err != nil {
			return nil, fmt.Errorf("failed to parse profile YAML: %w", err)
		}
	}

	var network MockNetwork
	if len(networkData) > 0 {
		if err := yaml.Unmarshal(networkData, &network); err != nil {
			return nil, fmt.Errorf("failed to parse network YAML: %w", err)
		}
	}

	var k8sMock MockK8s
	if len(k8sData) > 0 {
		if err := yaml.Unmarshal(k8sData, &k8sMock); err != nil {
			return nil, fmt.Errorf("failed to parse Kubernetes YAML: %w", err)
		}
	}

	envOptions, inputData, err := environment(eventType, event, profile, network, k8sMock)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	celEnv, err := cel.NewEnv(envOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &RuleEvaluator{
		rule:      rulesDoc.Spec.Rules[0],
		eventType: eventType,
		event:     event,
		inputData: inputData,
		celEnv:    celEnv,
	}, nil
}

// parseEvent reads the event, with whole numbers as integers like the fields of the events
// and the objects of admission requests, rather than as the doubles of JSON
func parseEvent(data []byte) (map[string]any, error) {
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	var event map[string]any
	if len(bytes.TrimSpace(jsonData)) > 0 && !bytes.Equal(bytes.TrimSpace(jsonData), []byte("null")) {
		decoder := json.NewDecoder(bytes.NewReader(jsonData))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			return nil, err
		}
	}
	if event == nil {
		return map[string]any{}, nil
	}
	return convertNumbers(event).(map[string]any), nil
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

func mapOrEmpty(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// environment is the CEL environment of the event type and the variables of the event. The
// operator evaluates the k8s-admission rules, with the CEL extensions it enables and without
// the node-agent's libraries; the node-agent evaluates all others, with the event as an object
// with the types of its fields (event.go).
func environment(eventType string, event map[string]any, profile MockProfile, network MockNetwork, k8sMock MockK8s) ([]cel.EnvOption, map[string]any, error) {
	options := append([]cel.EnvOption{}, celBaseOptions...)
	if eventType == admissionEventType {
		options = append(options,
			// an accommodation of the playground: the numbers of the mock event are JSON
			// numbers, which are compared with those of the rules whatever their type
			cel.CrossTypeNumericComparisons(true),
			cel.OptionalTypes(),
			ext.Network(),
			cel.Variable("event", cel.DynType),
			cel.Variable("eventType", cel.StringType),
			cel.Variable("object", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("oldObject", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("options", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
			ext.Strings(),
			ext.Sets(),
			ext.Lists(),
			ext.Math(),
			ext.TwoVarComprehensions(),
			ext.Bindings(),
			ext.Encoders(),
			ext.Regex(),
		)
		return options, map[string]any{
			"event":     event,
			"eventType": eventType,
			"object":    mapOrEmpty(event["Object"]),
			"oldObject": mapOrEmpty(event["OldObject"]),
			"options":   mapOrEmpty(event["Options"]),
			"params":    map[string]any{},
		}, nil
	}

	provider, err := newEventProvider()
	if err != nil {
		return nil, nil, err
	}
	options = append(options,
		cel.Variable("event", eventObjectType),
		// HTTP events are also the variable http
		cel.Variable("http", eventObjectType),
		cel.Variable("eventType", cel.StringType),
		cel.CustomTypeProvider(provider),
		ext.Strings(),
	)
	options = append(options, libraryEnvOptions(profile, network, k8sMock, event)...)
	typedEvent := mockObject{objectType: eventObjectType, fields: event}
	inputData := map[string]any{"event": typedEvent, "eventType": eventType}
	if eventType == dnsQueryEventType {
		inputData["eventType"] = "dns"
	}
	if eventType == httpEventType {
		inputData["http"] = typedEvent
	}
	return options, inputData, nil
}

// Evaluate runs the rule expressions, message, and uniqueId against the event data. The rule
// fires when every expression of the event type is true. Like the node-agent, it only
// evaluates the message and uniqueId when the rule fires; otherwise they are only compiled.
func (e *RuleEvaluator) Evaluate() RuleEvalResults {
	results := RuleEvalResults{
		RuleExpression: []RuleExprResult{},
	}

	// Collect matching ruleExpression entries.
	var matched []RuleExpression
	for _, expr := range e.rule.Expressions.RuleExpression {
		if expr.EventType == e.eventType {
			matched = append(matched, expr)
		}
	}

	// If no ruleExpression entry handles this event type, report the mismatch and stop.
	if len(matched) == 0 {
		validTypes := make([]string, 0, len(e.rule.Expressions.RuleExpression))
		seen := map[string]bool{}
		for _, expr := range e.rule.Expressions.RuleExpression {
			if !seen[expr.EventType] {
				validTypes = append(validTypes, expr.EventType)
				seen[expr.EventType] = true
			}
		}
		results.EventTypeMismatch = fmt.Sprintf(
			"rule %q handles event types %v, not %q",
			e.rule.ID, validTypes, e.eventType,
		)
		return results
	}

	// Evaluate each matching ruleExpression; the node-agent stops at the first that is not
	// true, but the playground answers each of them.
	results.Fired = true
	for _, expr := range matched {
		r := RuleExprResult{
			EventType:  expr.EventType,
			Expression: expr.Expression,
		}
		if program, err := e.compile(expr.Expression); err != nil {
			r.Error = err.Error()
			r.CompileError = true
		} else if val, _, err := program.Eval(e.inputData); err != nil {
			log.Printf("Eval error: %v", err)
			r.Error = err.Error()
		} else if b, ok := val.Value().(bool); ok {
			r.Result = &b
		} else {
			r.Error = fmt.Sprintf("expression must return bool, got %T", val.Value())
		}
		results.Fired = results.Fired && r.Result != nil && *r.Result
		results.RuleExpression = append(results.RuleExpression, r)
	}
	// The node-agent skips the event before the expressions when the prefilter of the rule's
	// state excludes it; the playground still answers each expression. The operator, which
	// evaluates the k8s-admission rules, has no prefilter.
	if e.eventType != admissionEventType {
		if reason := parsePrefilter(e.rule.State).skipReason(prefilterFields(e.eventType, e.event)); reason != "" {
			results.Prefiltered = "The node-agent skips this event before evaluating the rule: " + reason
			results.Fired = false
		}
	}

	results.Message = e.stringExpression(e.rule.Expressions.Message, results.Fired)
	results.UniqueID = e.stringExpression(e.rule.Expressions.UniqueID, results.Fired)
	// The node-agent sends no alert for an event whose unique id cannot be evaluated or is not
	// a string, while a message that fails is only left empty; a unique id that does not
	// compile is an empty one for it. The operator alerts without the unique id.
	if e.eventType != admissionEventType && results.UniqueID.Error != "" && !results.UniqueID.CompileError {
		results.Fired = false
	}
	return results
}

// stringExpression evaluates the message or the unique id of a rule that fired, and only
// compiles it otherwise. Like the node-agent and the operator, it only takes a string.
func (e *RuleEvaluator) stringExpression(expression string, fired bool) StringExprResult {
	var result StringExprResult
	if expression == "" {
		return result
	}
	program, err := e.compile(expression)
	if err != nil {
		result.Error = err.Error()
		result.CompileError = true
		return result
	}
	if !fired {
		return result
	}
	val, _, err := program.Eval(e.inputData)
	if err != nil {
		result.Error = err.Error()
	} else if text, ok := val.Value().(string); ok {
		result.Result = text
	} else {
		result.Error = fmt.Sprintf("expression returned %T, expected string", val.Value())
	}
	return result
}

// compile parses and checks an expression, which reports the functions, variables and fields of
// the event that do not exist, and calls and comparisons with values of the wrong type or
// number, as the node-agent does when it compiles a rule; an admission event is dyn, so its
// fields are only checked when evaluated
func (e *RuleEvaluator) compile(expression string) (cel.Program, error) {
	ast, issues := e.celEnv.Compile(expression)
	if issues != nil && issues.Err() != nil {
		log.Printf("Compile error: %v", issues.String())
		return nil, issues.Err()
	}
	prog, err := e.celEnv.Program(ast)
	if err != nil {
		log.Printf("Program error: %v", err)
		return nil, err
	}
	return prog, nil
}
