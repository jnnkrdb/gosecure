package jcloak

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}

func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
			Type:    ParseAPIErrType(err),
		}
	}

	if resp == nil {
		return &APIError{
			Message: "empty response",
			Type:    ParseAPIErrType(err),
		}
	}

	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &APIError{
			Code:    resp.StatusCode(),
			Message: msg,
			Type:    ParseAPIErrType(err),
		}
	}

	return nil
}

func injectTracingHeaders(ctx context.Context, req *resty.Request) *resty.Request {
	// look for span in context, do nothing if span is not found
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return req
	}

	// look for tracer in context, use global tracer if not found
	tracer, ok := ctx.Value(tracerContextKey).(opentracing.Tracer)
	if !ok || tracer == nil {
		tracer = opentracing.GlobalTracer()
	}

	// inject tracing header into request
	err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))
	if err != nil {
		return req
	}

	return req
}

func getID(resp *resty.Response) string {
	header := resp.Header().Get("Location")
	splittedPath := strings.Split(header, urlSeparator)

	return splittedPath[len(splittedPath)-1]
}

func findUsedKey(usedKeyID string, keys []CertResponseKey) *CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == usedKeyID {
			return &key
		}
	}

	return nil
}

type contextKey string

var tracerContextKey = contextKey("tracer")

// StringP returns a pointer of a string variable
func StringP(value string) *string {
	return &value
}

// PString returns a string value from a pointer
func PString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// BoolP returns a pointer of a boolean variable
func BoolP(value bool) *bool {
	return &value
}

// PBool returns a boolean value from a pointer
func PBool(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

// IntP returns a pointer of an integer variable
func IntP(value int) *int {
	return &value
}

// Int32P returns a pointer of an int32 variable
func Int32P(value int32) *int32 {
	return &value
}

// Int64P returns a pointer of an int64 variable
func Int64P(value int64) *int64 {
	return &value
}

// PInt returns an integer value from a pointer
func PInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

// PInt32 returns an int32 value from a pointer
func PInt32(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

// PInt64 returns an int64 value from a pointer
func PInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// Float32P returns a pointer of a float32 variable
func Float32P(value float32) *float32 {
	return &value
}

// Float64P returns a pointer of a float64 variable
func Float64P(value float64) *float64 {
	return &value
}

// PFloat32 returns an flaot32 value from a pointer
func PFloat32(value *float32) float32 {
	if value == nil {
		return 0
	}
	return *value
}

// PFloat64 returns an flaot64 value from a pointer
func PFloat64(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

// NilOrEmpty returns true if string is empty or has a nil value
func NilOrEmpty(value *string) bool {
	return value == nil || len(*value) == 0
}

// NilOrEmptyArray returns true if string is empty or has a nil value
func NilOrEmptyArray(value *[]string) bool {

	if value == nil || len(*value) == 0 {
		return true
	}

	return (*value)[0] == ""

}

// DecisionStrategyP returns a pointer for a DecisionStrategy value
func DecisionStrategyP(value DecisionStrategy) *DecisionStrategy {
	return &value
}

// LogicP returns a pointer for a Logic value
func LogicP(value Logic) *Logic {
	return &value
}

// PolicyEnforcementModeP returns a pointer for a PolicyEnforcementMode value
func PolicyEnforcementModeP(value PolicyEnforcementMode) *PolicyEnforcementMode {
	return &value
}

// PStringSlice converts a pointer to []string or returns ampty slice if nill value
func PStringSlice(value *[]string) []string {
	if value == nil {
		return []string{}
	}
	return *value
}

// NilOrEmptySlice returns true if list is empty or has a nil value
func NilOrEmptySlice(value *[]string) bool {
	return value == nil || len(*value) == 0
}

// WithTracer generates a context that has a tracer attached
func WithTracer(ctx context.Context, tracer opentracing.Tracer) context.Context {
	return context.WithValue(ctx, tracerContextKey, tracer)
}
