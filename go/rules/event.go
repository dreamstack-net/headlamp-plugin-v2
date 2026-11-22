package rules

// The event of the node-agent's rules, declared with the types of its fields as the node-agent
// declares them (pkg/utils/cel.go: CelFields and HttpRequestFields), so that the checker
// reports what the node-agent reports when it compiles a rule: a field that does not exist, and
// a field used as a value of another type, such as the unsigned event.pid compared with the
// integer 1. The node-agent does not load such a rule.

import (
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const (
	eventTypeName   = "Event"
	requestTypeName = "HttpRequest"
)

var (
	eventObjectType   = cel.ObjectType(eventTypeName)
	requestObjectType = cel.ObjectType(requestTypeName)
)

// fieldKind is the type of a field of the event
type fieldKind int

const (
	stringKind fieldKind = iota
	uintKind
	intKind
	boolKind
	listKind
	mapKind
	requestKind
)

func (k fieldKind) celType() *cel.Type {
	switch k {
	case uintKind:
		return cel.UintType
	case intKind:
		return cel.IntType
	case boolKind:
		return cel.BoolType
	case listKind:
		return cel.ListType(cel.DynType)
	case mapKind:
		return cel.MapType(cel.DynType, cel.DynType)
	case requestKind:
		return requestObjectType
	}
	return cel.StringType
}

func (k fieldKind) String() string {
	return [...]string{"a string", "an unsigned integer", "an integer", "a boolean", "a list", "a map", "a map"}[k]
}

// eventField is a field of the event or of its request. The node-agent has a value for every
// field of every event, the zero value where the event has no such data, and has() is true for
// it; only a field with whenPresent is absent for has() unless the mock has it, as the
// node-agent only sets it where it was measured (rcode on a DNS response, the terminal and the
// file of an exec, the URL of a request).
type eventField struct {
	kind        fieldKind
	whenPresent bool
}

var eventFields = map[string]eventField{
	"args":          {kind: listKind},
	"attrSize":      {kind: uintKind},
	"capName":       {kind: stringKind},
	"cmd":           {kind: uintKind},
	"comm":          {kind: stringKind},
	"containerId":   {kind: stringKind},
	"containerName": {kind: stringKind},
	"cwd":           {kind: stringKind},
	"direction":     {kind: stringKind},
	"dstAddr":       {kind: stringKind},
	"dstIp":         {kind: stringKind},
	"dstNamespace":  {kind: stringKind},
	"dstPodLabels":  {kind: mapKind},
	"dstPort":       {kind: intKind},
	"exepath":       {kind: stringKind},
	"file":          {kind: stringKind, whenPresent: true},
	"flags":         {kind: listKind},
	"flagsRaw":      {kind: intKind},
	"hasTty":        {kind: boolKind, whenPresent: true},
	"module":        {kind: stringKind},
	"name":          {kind: stringKind},
	"namespace":     {kind: stringKind},
	"newPath":       {kind: stringKind},
	"numAnswers":    {kind: intKind},
	"oldPath":       {kind: stringKind},
	"opcode":        {kind: intKind},
	"path":          {kind: stringKind},
	"pcomm":         {kind: stringKind},
	"pid":           {kind: uintKind},
	"pktType":       {kind: stringKind},
	"podName":       {kind: stringKind},
	"ppid":          {kind: uintKind},
	"proto":         {kind: stringKind},
	"pupperlayer":   {kind: boolKind},
	"qr":            {kind: stringKind},
	"qtype":         {kind: stringKind},
	"rcode":         {kind: stringKind, whenPresent: true},
	"request":       {kind: requestKind},
	"srcPort":       {kind: intKind},
	"syscallName":   {kind: stringKind},
	"tty":           {kind: intKind, whenPresent: true},
	"ttyMajor":      {kind: uintKind, whenPresent: true},
	"ttyMinor":      {kind: uintKind, whenPresent: true},
	"uid":           {kind: uintKind},
	"upperlayer":    {kind: boolKind},
}

var requestFields = map[string]eventField{
	"body":    {kind: stringKind},
	"headers": {kind: mapKind},
	"host":    {kind: stringKind},
	"method":  {kind: stringKind},
	"path":    {kind: stringKind, whenPresent: true},
	"url":     {kind: stringKind, whenPresent: true},
}

var objectFields = map[string]map[string]eventField{
	eventTypeName:   eventFields,
	requestTypeName: requestFields,
}

// mockObject is the event of the mock, or its request, as a value of its object type; fields
// is nil for an event without a request
type mockObject struct {
	objectType *types.Type
	fields     map[string]any
}

func (o mockObject) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("type conversion error from '%s' to '%v'", o.objectType.TypeName(), typeDesc)
}

func (o mockObject) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case o.objectType:
		return o
	case types.TypeType:
		return o.objectType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", o.objectType.TypeName(), typeVal.TypeName())
}

func (o mockObject) Equal(other ref.Val) ref.Val {
	object, ok := other.(mockObject)
	return types.Bool(ok && object.objectType == o.objectType && reflect.DeepEqual(object.fields, o.fields))
}

func (o mockObject) Type() ref.Type {
	return o.objectType
}

func (o mockObject) Value() any {
	return o.fields
}

// isSet tells whether has() is true for the field
func (f eventField) isSet(name string, fields map[string]any) bool {
	return !f.whenPresent || fields[name] != nil
}

// value is the value of the field with the type of the field. The numbers of the mock are
// integers or doubles (parseEvent); a field the mock leaves out has the zero value.
func (f eventField) value(name string, fields map[string]any) (any, error) {
	value := fields[name]
	switch f.kind {
	case stringKind:
		if value == nil {
			return "", nil
		}
		if text, ok := value.(string); ok {
			return text, nil
		}
	case uintKind:
		if value == nil {
			return uint64(0), nil
		}
		if number, ok := value.(int64); ok && number >= 0 {
			return uint64(number), nil
		}
	case intKind:
		if value == nil {
			return int64(0), nil
		}
		if number, ok := value.(int64); ok {
			return number, nil
		}
	case boolKind:
		if value == nil {
			return false, nil
		}
		if flag, ok := value.(bool); ok {
			return flag, nil
		}
	case listKind:
		if value == nil {
			return []any{}, nil
		}
		if list, ok := value.([]any); ok {
			return list, nil
		}
	case mapKind:
		if value == nil {
			return map[string]any{}, nil
		}
		if entries, ok := value.(map[string]any); ok {
			return entries, nil
		}
	case requestKind:
		if value == nil {
			return mockObject{objectType: requestObjectType}, nil
		}
		if request, ok := value.(map[string]any); ok {
			return mockObject{objectType: requestObjectType, fields: request}, nil
		}
	}
	return nil, fmt.Errorf("%s of the mock event must be %s, got %v", name, f.kind, value)
}

// eventProvider declares the object types of the event and of its request, next to the types
// of CEL
type eventProvider struct {
	types.Provider
}

func newEventProvider() (types.Provider, error) {
	registry, err := types.NewRegistry()
	if err != nil {
		return nil, err
	}
	return eventProvider{Provider: registry}, nil
}

func (p eventProvider) FindStructType(structType string) (*types.Type, bool) {
	switch structType {
	case eventTypeName:
		return types.NewTypeTypeWithParam(eventObjectType), true
	case requestTypeName:
		return types.NewTypeTypeWithParam(requestObjectType), true
	}
	return p.Provider.FindStructType(structType)
}

func (p eventProvider) FindStructFieldNames(structType string) ([]string, bool) {
	fields, found := objectFields[structType]
	if !found {
		return p.Provider.FindStructFieldNames(structType)
	}
	return slices.Sorted(maps.Keys(fields)), true
}

func (p eventProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	fields, found := objectFields[structType]
	if !found {
		return p.Provider.FindStructFieldType(structType, fieldName)
	}
	field, found := fields[fieldName]
	if !found {
		return nil, false
	}
	// a request that the event does not have has no field that is set
	isRequest := structType == requestTypeName
	return &types.FieldType{
		Type: field.kind.celType(),
		IsSet: func(target any) bool {
			values, _ := target.(map[string]any)
			return (!isRequest || values != nil) && field.isSet(fieldName, values)
		},
		GetFrom: func(target any) (any, error) {
			values, _ := target.(map[string]any)
			return field.value(fieldName, values)
		},
	}, true
}
