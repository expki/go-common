package ai

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// --- sample tool funcs for reflection ---

type weatherArgs struct {
	City  string `json:"city" desc:"the city to look up"`
	Units string `json:"units,omitempty"`
}

type weatherResult struct {
	TempC float64 `json:"temp_c"`
}

func GetWeather(ctx context.Context, in weatherArgs) (weatherResult, error) {
	if in.City == "" {
		return weatherResult{}, errors.New("city required")
	}
	return weatherResult{TempC: 21}, nil
}

type echoArgs struct {
	Msg string `json:"msg"`
}

func Echo(in echoArgs) string { return in.Msg }

type countArgs struct {
	Items []string `json:"items"`
}

func CountItems(in countArgs) int { return len(in.Items) }

func NoResult(in echoArgs) error { return nil }

func TestReflectTool_Name(t *testing.T) {
	tool, err := ReflectTool(GetWeather, "look up weather")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	if tool.Name != "getweather" {
		t.Errorf("name = %q, want getweather", tool.Name)
	}
	if tool.Description != "look up weather" {
		t.Errorf("desc = %q", tool.Description)
	}
}

func TestReflectTool_Schema(t *testing.T) {
	tool, err := ReflectTool(GetWeather, "")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	var s map[string]any
	if err := json.Unmarshal(tool.Schema, &s); err != nil {
		t.Fatalf("schema not valid json: %v", err)
	}
	if s["type"] != "object" {
		t.Errorf("type = %v, want object", s["type"])
	}
	props, _ := s["properties"].(map[string]any)
	if _, ok := props["city"]; !ok {
		t.Errorf("missing city property: %v", props)
	}
	city, _ := props["city"].(map[string]any)
	if city["description"] != "the city to look up" {
		t.Errorf("city desc = %v", city["description"])
	}
	// units has omitempty -> not required; city has no omitempty -> required.
	req, _ := s["required"].([]any)
	if len(req) != 1 || req[0] != "city" {
		t.Errorf("required = %v, want [city]", req)
	}
}

func TestReflectTool_BadSignatures(t *testing.T) {
	tests := []struct {
		name string
		fn   any
	}{
		{"not a func", 42},
		{"non-struct arg", func(x int) {}},
		{"anonymous literal", func(in echoArgs) string { return in.Msg }},
		{"too many args", func(a context.Context, b echoArgs, c int) {}},
		{"three results", func(in echoArgs) (int, int, error) { return 0, 0, nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ReflectTool(tt.fn, ""); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestTool_Invoke(t *testing.T) {
	tool, err := ReflectTool(GetWeather, "")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	out, err := tool.Invoke(context.Background(), json.RawMessage(`{"city":"Paris"}`))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var r weatherResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if r.TempC != 21 {
		t.Errorf("temp = %v, want 21", r.TempC)
	}
}

func TestTool_InvokeError(t *testing.T) {
	tool, _ := ReflectTool(GetWeather, "")
	_, err := tool.Invoke(context.Background(), json.RawMessage(`{"city":""}`))
	if err == nil || !strings.Contains(err.Error(), "city required") {
		t.Errorf("err = %v, want city required", err)
	}
}

func TestTool_InvokeNoCtxNoResultValue(t *testing.T) {
	echo, _ := ReflectTool(Echo, "")
	out, err := echo.Invoke(context.Background(), json.RawMessage(`{"msg":"hi"}`))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var s string
	if err := json.Unmarshal(out, &s); err != nil || s != "hi" {
		t.Errorf("out = %s (%v)", out, err)
	}

	nr, _ := ReflectTool(NoResult, "")
	out, err = nr.Invoke(context.Background(), json.RawMessage(`{"msg":"x"}`))
	if err != nil {
		t.Fatalf("Invoke NoResult: %v", err)
	}
	if string(out) != "null" {
		t.Errorf("NoResult out = %s, want null", out)
	}
}

func TestTool_UnboundInvoke(t *testing.T) {
	var tool Tool
	if _, err := tool.Invoke(context.Background(), nil); !errors.Is(err, ErrToolUnbound) {
		t.Errorf("err = %v, want ErrToolUnbound", err)
	}
	if tool.Bound() {
		t.Error("zero Tool should not be Bound")
	}
}

func TestToolRegistry_BindSchemaMismatch(t *testing.T) {
	reg := NewToolRegistry()
	if err := reg.Add(GetWeather, "w"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Matching schema binds.
	good, _ := ReflectTool(GetWeather, "")
	if _, err := reg.bind("getweather", good.Schema); err != nil {
		t.Errorf("bind matching: %v", err)
	}
	// Different schema -> mismatch.
	if _, err := reg.bind("getweather", json.RawMessage(`{"type":"object","properties":{}}`)); !errors.Is(err, ErrToolSchemaMismatch) {
		t.Errorf("bind mismatch err = %v, want ErrToolSchemaMismatch", err)
	}
	// Unknown name -> unbound.
	if _, err := reg.bind("missing", good.Schema); !errors.Is(err, ErrToolUnbound) {
		t.Errorf("bind unknown err = %v, want ErrToolUnbound", err)
	}
}

func TestReflectTool_ArrayParam(t *testing.T) {
	tool, err := ReflectTool(CountItems, "")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	var s map[string]any
	_ = json.Unmarshal(tool.Schema, &s)
	props := s["properties"].(map[string]any)
	items := props["items"].(map[string]any)
	if items["type"] != "array" {
		t.Errorf("items type = %v, want array", items["type"])
	}
}
