package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

// Tool is a registered tool the model may call. Only Name, Description, and
// Schema are persistable; the bound invoker is a Go func and is never
// serialized. After a reload the invoker is re-bound by name (see
// [LoadConversation] and [ToolRegistry]).
type Tool struct {
	// Name is the tool name derived from the Go func (see [ReflectTool]).
	Name string
	// Description is the human/model-facing description supplied at
	// registration.
	Description string
	// Schema is the JSON Schema of the tool's single argument struct, derived
	// from its exported fields and json tags.
	Schema json.RawMessage

	// invoker decodes a JSON arguments object, calls the bound func, and
	// encodes its result. It is nil for a descriptor reloaded from the store
	// until re-bound.
	invoker func(ctx context.Context, args json.RawMessage) (json.RawMessage, error)
}

// Bound reports whether the tool has a callable invoker. A descriptor loaded
// from the store is unbound until its Go func is re-registered.
func (t Tool) Bound() bool { return t.invoker != nil }

// ReflectTool derives a [Tool] from a Go func. The accepted signatures are:
//
//	func(ctx context.Context, in ArgStruct) (Result, error)
//	func(ctx context.Context, in ArgStruct) (Result)
//	func(in ArgStruct) (Result, error)
//	func(in ArgStruct) (Result)
//
// where ArgStruct is a struct (the tool's parameters; its JSON Schema is
// derived from exported fields and json tags) and Result is any
// JSON-encodable type. The tool name is the func's own name, lower-cased; pass
// desc as the model-facing description.
//
// Unsupported parameter or result kinds (channels, funcs, unnamed function
// literals, non-struct arguments) return a configuration-time error rather
// than a runtime capability gap.
func ReflectTool(fn any, desc string) (Tool, error) {
	v := reflect.ValueOf(fn)
	t := v.Type()
	if t.Kind() != reflect.Func {
		return Tool{}, fmt.Errorf("ai: ReflectTool requires a func, got %s", t.Kind())
	}

	name, err := funcName(fn)
	if err != nil {
		return Tool{}, err
	}

	argType, ctxFirst, err := toolArgType(t)
	if err != nil {
		return Tool{}, err
	}
	if err := checkResults(t); err != nil {
		return Tool{}, err
	}

	schema, err := structSchema(argType)
	if err != nil {
		return Tool{}, fmt.Errorf("ai: tool %q: %w", name, err)
	}

	tool := Tool{
		Name:        name,
		Description: desc,
		Schema:      schema,
		invoker:     makeInvoker(v, argType, ctxFirst),
	}
	return tool, nil
}

// funcName returns the lower-cased base name of fn. Anonymous function
// literals (whose runtime name ends in a generated suffix) are rejected
// because a tool needs a stable, model-facing name.
func funcName(fn any) (string, error) {
	pc := reflect.ValueOf(fn).Pointer()
	rf := runtime.FuncForPC(pc)
	if rf == nil {
		return "", fmt.Errorf("ai: cannot resolve tool func name")
	}
	full := rf.Name() // e.g. github.com/x/y.GetWeather or .../pkg.glob..func1
	// Anonymous function literals compile to names containing a ".func"
	// segment (for example "pkg.glob..func1" or "pkg.Outer.func1"); a tool
	// needs a stable, model-facing name, so reject them.
	if strings.Contains(full, ".func") {
		return "", fmt.Errorf("ai: tool func must be a named func, not an anonymous literal")
	}
	base := full
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	if base == "" {
		return "", fmt.Errorf("ai: cannot resolve tool func name")
	}
	return strings.ToLower(base), nil
}

// toolArgType validates the func's parameters and returns the argument struct
// type and whether a context.Context is the first parameter.
func toolArgType(t reflect.Type) (argType reflect.Type, ctxFirst bool, err error) {
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	switch t.NumIn() {
	case 1:
		argType = t.In(0)
	case 2:
		if !t.In(0).Implements(ctxType) {
			return nil, false, fmt.Errorf("ai: two-arg tool func must take context.Context first")
		}
		ctxFirst = true
		argType = t.In(1)
	default:
		return nil, false, fmt.Errorf("ai: tool func must take (ArgStruct) or (context.Context, ArgStruct)")
	}
	if argType.Kind() != reflect.Struct {
		return nil, false, fmt.Errorf("ai: tool func argument must be a struct, got %s", argType.Kind())
	}
	return argType, ctxFirst, nil
}

// checkResults validates the func's return signature.
func checkResults(t reflect.Type) error {
	errType := reflect.TypeOf((*error)(nil)).Elem()
	switch t.NumOut() {
	case 1:
		if t.Out(0) == errType {
			return nil // (error) alone is fine: tool returns no value
		}
		return nil
	case 2:
		if !t.Out(1).Implements(errType) {
			return fmt.Errorf("ai: two-result tool func must return (Result, error)")
		}
		return nil
	default:
		return fmt.Errorf("ai: tool func must return (Result), (error), or (Result, error)")
	}
}

// makeInvoker builds the closure that decodes a JSON arguments object into a
// fresh argType value, calls fn, and JSON-encodes the result (or surfaces the
// returned error).
func makeInvoker(fn reflect.Value, argType reflect.Type, ctxFirst bool) func(context.Context, json.RawMessage) (json.RawMessage, error) {
	t := fn.Type()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	// hasErr reports whether the last result is an error.
	hasErr := t.NumOut() == 2 || (t.NumOut() == 1 && t.Out(0).Implements(errType))
	// hasValue reports whether a non-error result value is returned.
	hasValue := t.NumOut() == 2 || (t.NumOut() == 1 && !t.Out(0).Implements(errType))

	return func(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
		argPtr := reflect.New(argType)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, argPtr.Interface()); err != nil {
				return nil, fmt.Errorf("ai: decoding tool arguments: %w", err)
			}
		}

		var in []reflect.Value
		if ctxFirst {
			in = []reflect.Value{reflect.ValueOf(ctx), argPtr.Elem()}
		} else {
			in = []reflect.Value{argPtr.Elem()}
		}
		out := fn.Call(in)

		if hasErr {
			if errVal := out[len(out)-1]; !errVal.IsNil() {
				return nil, errVal.Interface().(error)
			}
		}
		if !hasValue {
			return json.RawMessage("null"), nil
		}
		encoded, err := json.Marshal(out[0].Interface())
		if err != nil {
			return nil, fmt.Errorf("ai: encoding tool result: %w", err)
		}
		return json.RawMessage(encoded), nil
	}
}

// Invoke decodes args, calls the bound func, and encodes its result. It
// returns [ErrToolUnbound] if the tool descriptor has no invoker (for example
// after a store reload before re-binding).
func (t Tool) Invoke(ctx context.Context, args json.RawMessage) (json.RawMessage, error) {
	if t.invoker == nil {
		return nil, ErrToolUnbound
	}
	return t.invoker(ctx, args)
}

// jsonSchema is the minimal JSON Schema subset emitted for tool arguments.
type jsonSchema struct {
	Type       string                `json:"type"`
	Properties map[string]jsonSchema `json:"properties,omitempty"`
	Items      *jsonSchema           `json:"items,omitempty"`
	Required   []string              `json:"required,omitempty"`
	Desc       string                `json:"description,omitempty"`
}

// structSchema derives a JSON Schema object from a struct's exported fields,
// honoring json tags (name and omitempty) and a "desc" tag for descriptions.
func structSchema(t reflect.Type) (json.RawMessage, error) {
	s, err := schemaForType(t)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func schemaForType(t reflect.Type) (jsonSchema, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return jsonSchema{Type: "string"}, nil
	case reflect.Bool:
		return jsonSchema{Type: "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return jsonSchema{Type: "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return jsonSchema{Type: "number"}, nil
	case reflect.Slice, reflect.Array:
		item, err := schemaForType(t.Elem())
		if err != nil {
			return jsonSchema{}, err
		}
		return jsonSchema{Type: "array", Items: &item}, nil
	case reflect.Struct:
		out := jsonSchema{Type: "object", Properties: map[string]jsonSchema{}}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, omitempty, skip := jsonField(f)
			if skip {
				continue
			}
			fs, err := schemaForType(f.Type)
			if err != nil {
				return jsonSchema{}, err
			}
			if d := f.Tag.Get("desc"); d != "" {
				fs.Desc = d
			}
			out.Properties[name] = fs
			if !omitempty {
				out.Required = append(out.Required, name)
			}
		}
		return out, nil
	default:
		return jsonSchema{}, fmt.Errorf("unsupported parameter kind %s", t.Kind())
	}
}

// jsonField resolves a struct field's JSON name and omitempty flag, and
// reports whether the field is skipped (json:"-").
func jsonField(f reflect.StructField) (name string, omitempty, skip bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	name = f.Name
	parts := strings.Split(tag, ",")
	if parts[0] != "" {
		name = parts[0]
	}
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return name, omitempty, false
}

// ToolRegistry maps a tool name to the Go func that implements it. It re-binds
// invokers after [LoadConversation], which persists only tool descriptors. On
// bind each func's freshly reflected schema must match the persisted schema
// for that name, otherwise [ErrToolSchemaMismatch] is returned.
type ToolRegistry struct {
	byName map[string]Tool
}

// NewToolRegistry returns an empty registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{byName: map[string]Tool{}}
}

// Add reflects fn into a [Tool] and indexes it by its derived name, ready to
// re-bind a persisted descriptor of the same name.
func (r *ToolRegistry) Add(fn any, desc string) error {
	tool, err := ReflectTool(fn, desc)
	if err != nil {
		return err
	}
	if r.byName == nil {
		r.byName = map[string]Tool{}
	}
	r.byName[tool.Name] = tool
	return nil
}

// bind returns the registered tool for name with its invoker, validating that
// its freshly reflected schema matches the persisted schema. It returns
// [ErrToolUnbound] if no func is registered for the name and
// [ErrToolSchemaMismatch] if the schemas differ.
func (r *ToolRegistry) bind(name string, persisted json.RawMessage) (Tool, error) {
	if r == nil {
		return Tool{}, ErrToolUnbound
	}
	tool, ok := r.byName[name]
	if !ok {
		return Tool{}, ErrToolUnbound
	}
	if !schemaEqual(tool.Schema, persisted) {
		return Tool{}, ErrToolSchemaMismatch
	}
	return tool, nil
}

// schemaEqual compares two JSON schemas for semantic equality, ignoring
// formatting differences.
func schemaEqual(a, b json.RawMessage) bool {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}
