package web

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type body struct {
	ID string `json:"id"`
}

func TestEmptyOf(t *testing.T) {
	assert.NotNil(t, Of())
}

func TestOfWithBody(t *testing.T) {
	s := Of(WithBody(body{}))

	assert.NotNil(t, s)
	assert.NotNil(t, s.Body)
}

func TestOfWithParams(t *testing.T) {
	s := Of(
		WithParam(ParamLocationPath, "id"),
		WithParam(ParamLocationPath, "key"),
		WithParam(ParamLocationQuery, "sort"),
		WithParam(ParamLocationHeader, "api-key"),
	)

	assert.NotNil(t, s)
	assert.Len(t, s.Parameters, 4)
}

func TestOfWithMethod(t *testing.T) {
	s := Of(WithMethod(MethodGet))

	assert.NotNil(t, s)
	assert.Equal(t, MethodGet, s.Method)
}

func TestOfWithPath(t *testing.T) {
	s := Of(WithPath("/test/path"))

	assert.NotNil(t, s)
	assert.Equal(t, "/test/path", s.Path)
}

func TestOfWithPathPrefix(t *testing.T) {
	s := Of(WithPathPrefix("/test/path"))

	assert.NotNil(t, s)
	assert.Equal(t, "/test/path", s.PathPrefix)
}

func TestOfWithResponse(t *testing.T) {
	s := Of(
		WithResponse(body{}),
		WithResponse(body{}, http.StatusNotFound),
	)

	assert.NotNil(t, s)
	assert.Len(t, s.Responses, 2)
}

func TestOfWithTags(t *testing.T) {
	s := Of(WithTags("tag1", "tag2"))

	assert.NotNil(t, s)
	assert.Len(t, s.Tags, 2)
}

func TestOfWithSummary(t *testing.T) {
	s := Of(WithSummary("test"))

	assert.NotNil(t, s)
	assert.Equal(t, "test", s.Summary)
}

func TestOfWithDescription(t *testing.T) {
	s := Of(WithDescription("test"))

	assert.NotNil(t, s)
	assert.Equal(t, "test", s.Description)
}

func TestGet(t *testing.T) {
	s := GetOp("path", body{})

	assert.NotNil(t, s)
	assert.Equal(t, "path", s.Path)
	assert.Equal(t, MethodGet, s.Method)
	assert.Len(t, s.Responses, 1)
	assert.Len(t, s.Parameters, 0)
}

func TestDelete(t *testing.T) {
	s := DeleteOp("path", body{})

	assert.NotNil(t, s)
	assert.Equal(t, "path", s.Path)
	assert.Equal(t, MethodDelete, s.Method)
	assert.Len(t, s.Responses, 1)
	assert.Len(t, s.Parameters, 0)
}

func TestPost(t *testing.T) {
	s := PostOp("path", body{}, body{})

	assert.NotNil(t, s)
	assert.Equal(t, "path", s.Path)
	assert.Equal(t, MethodPost, s.Method)
	assert.Len(t, s.Responses, 1)
	assert.Len(t, s.Parameters, 0)
}

func TestPut(t *testing.T) {
	s := PutOp("path", body{}, body{})

	assert.NotNil(t, s)
	assert.Equal(t, "path", s.Path)
	assert.Equal(t, MethodPut, s.Method)
	assert.Len(t, s.Responses, 1)
	assert.Len(t, s.Parameters, 0)
}

func TestPatch(t *testing.T) {
	s := PatchOp("path", body{}, body{})

	assert.NotNil(t, s)
	assert.Equal(t, "path", s.Path)
	assert.Equal(t, MethodPatch, s.Method)
	assert.Len(t, s.Responses, 1)
	assert.Len(t, s.Parameters, 0)
}

func TestWithErrBadRequest(t *testing.T) {
	s := Of(WithErrBadRequest())

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusBadRequest, s.Responses[0].Code)
}

func TestWithErrNotFound(t *testing.T) {
	s := Of(WithErrNotFound())

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusNotFound, s.Responses[0].Code)
}

func TestWithError(t *testing.T) {
	s := Of(WithError(http.StatusTeapot, "im a teapot"))

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusTeapot, s.Responses[0].Code)
}

func TestWithForbidden(t *testing.T) {
	s := Of(WithForbidden())

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusForbidden, s.Responses[0].Code)
}

func TestWithInternalError(t *testing.T) {
	s := Of(WithInternalError())

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusInternalServerError, s.Responses[0].Code)
}

func TestWithUnauthorized(t *testing.T) {
	s := Of(WithUnauthorized())

	assert.NotNil(t, s)
	assert.Equal(t, http.StatusUnauthorized, s.Responses[0].Code)
}

func TestCreateReflector(t *testing.T) {
	ref := CreateReflector(&ReflectorOptions{
		Title:       "Example",
		Description: "API",
		Version:     "1.33.7",
	})

	assert.NotNil(t, ref)
	assert.Equal(t, "1.33.7", ref.Spec.Info.Version)
}

func TestBuildMinimal(t *testing.T) {
	ref := CreateReflector(&ReflectorOptions{
		Title:       "Example",
		Description: "API",
		Version:     "1.33.7",
	})

	err := GetOp("path", body{}).Build(ref)

	assert.NotNil(t, ref)
	assert.Nil(t, err)
}
