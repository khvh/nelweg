package nelweg

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/swaggest/openapi-go/openapi3"
)

// Spec holds dao for creating an OpenAPI spec for a route
type Spec struct {
	Path         string
	OriginalPath string
	PathPrefix   string
	Method       Method
	Body         interface{}
	Responses    []*Response
	Parameters   []*Parameter
	Tags         []string
	Summary      string
	Description  string
	Op           *openapi3.Operation
	Auth         bool
	Validate     bool
	AuthAPI      bool
	Route        *Route
}

// JSONObject represents a map[string]interface{} shorthand
type JSONObject map[string]interface{}

// Error is dao object for returning errors
type Error struct {
	ID             int         `json:"id,omitempty" yaml:"id,omitempty"`
	Code           string      `json:"code,omitempty" yaml:"code,omitempty"`
	Msg            string      `json:"message,omitempty" yaml:"message,omitempty"`
	AdditionalData *JSONObject `json:"data,omitempty" yaml:"data,omitempty"`
	Errors         []any       `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// Err is the constructor for Error
func Err(code string) *Error {
	return &Error{
		Code: code,
	}
}

// SetID sets the error ID
func (e *Error) SetID(id int) *Error {
	e.ID = id

	return e
}

// Message sets the message for Error
func (e *Error) Message(msg string) *Error {
	e.Msg = msg

	return e
}

// Data sets the dao property for Error
func (e *Error) Data(data *JSONObject) *Error {
	e.AdditionalData = data

	return e
}

// Errs reutnrs nelweg.Error with provided errors
func (e *Error) Errs(data []any) *Error {
	e.Errors = data

	return e
}

// ParamLocation is a type for parameter location (header, path, query)
type ParamLocation string

// Possible values for ParamLocation
const (
	ParamLocationHeader ParamLocation = "header"
	ParamLocationPath   ParamLocation = "path"
	ParamLocationQuery  ParamLocation = "query"
)

// Method is a HTTP method
type Method string

// Method values (straight from the net/http)
const (
	MethodGet    Method = http.MethodGet
	MethodPost   Method = http.MethodPost
	MethodPut    Method = http.MethodPut
	MethodPatch  Method = http.MethodPatch
	MethodDelete Method = http.MethodDelete
)

// Parameter definition
type Parameter struct {
	Title    string
	Type     string
	Location ParamLocation
}

// Response defines a single response dao (code + entity)
type Response struct {
	Code int
	Body any
}

// Opt defines an option function for Spec
type Opt func(s *Spec) error

// Of constructs a new Spec
func Of(opts ...Opt) *Spec {
	s := &Spec{}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil
		}
	}

	if s.Op == nil {
		s.Op = &openapi3.Operation{}
	}

	return s
}

// WithValidation ...
func (s *Spec) WithValidation() *Spec {
	s.Validate = true

	return s
}

// WithAuth set auth for spec
func (s *Spec) WithAuth() *Spec {
	s.Auth = true

	return s
}

// WithAPIAuth set api auth for spec
func (s *Spec) WithAPIAuth() *Spec {
	s.AuthAPI = true

	return s
}

// WithQueryObject ...
func (s *Spec) WithQueryObject(obj any) *Spec {
	s.Body = obj

	return s
}

// With is a generic method to add/replace opts after Spec is already created
func (s *Spec) With(opts ...Opt) *Spec {
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil
		}
	}

	return s
}

// FullPath returns url with prefix if present
func (s *Spec) FullPath() string {
	p := s.Path

	if s.PathPrefix != "" {
		p = strings.TrimSuffix(s.PathPrefix, "/") + "/" + strings.TrimPrefix(p, "/")
	}

	return p
}

// FullRouterPath returns url with prefix if present
func (s *Spec) FullRouterPath() string {
	p := s.OriginalPath

	if s.PathPrefix != "" {
		p = strings.TrimSuffix(s.PathPrefix, "/") + "/" + strings.TrimPrefix(p, "/")
	}

	return p
}

// Build builds an openapi3.Spec
func (s *Spec) Build(ref *openapi3.Reflector) error {
	op := openapi3.Operation{}

	var (
		params []openapi3.ParameterOrRef
	)

	for _, p := range s.Parameters {
		params = append(params, openapi3.ParameterOrRef{
			Parameter: createParam(p),
		})
	}

	s.Op.
		WithParameters(params...).
		WithTags(s.Tags...).
		WithSummary(s.Summary).
		WithDescription(s.Description)

	if s.Auth {
		s.Op.WithSecurity(
			append(op.Security, map[string][]string{
				"bearer": {},
			})...,
		)
	}

	if s.AuthAPI {
		s.Op.WithSecurity(
			append(op.Security, map[string][]string{
				"apikey": {},
			})...,
		)
	}

	for _, response := range s.Responses {
		if err := ref.SetJSONResponse(s.Op, response.Body, response.Code); err != nil {
			return errors.Wrap(err, "oas: when setting response")
		}
	}

	if s.Method == http.MethodPost || s.Method == http.MethodPut || s.Method == http.MethodPatch {
		if err := ref.SetRequest(s.Op, s.Body, string(s.Method)); err != nil {
			return errors.Wrap(err, "oas: when setting request")
		}
	}

	if err := ref.Spec.AddOperation(string(s.Method), s.FullPath(), *s.Op); err != nil {
		return errors.Wrap(err, "oas: when adding op to spec")
	}

	return nil
}

// GetOp constructs a GET operation
func GetOp(routePath string, res any, opts ...Opt) *Spec {
	rp, params := parseParams(routePath, ParamLocationPath)

	return Of(append([]Opt{
		WithPath(rp),
		WithOriginalPath(routePath),
		WithResponse(res),
		WithErrNotFound(),
		WithMethod(MethodGet),
		WithParams(params),
	}, opts...)...)
}

// DeleteOp constructs a GET operation
func DeleteOp(routePath string, res any, opts ...Opt) *Spec {
	rp, params := parseParams(routePath, ParamLocationPath)

	return Of(append([]Opt{
		WithPath(rp),
		WithOriginalPath(routePath),
		WithResponse(res),
		WithErrNotFound(),
		WithMethod(MethodDelete),
		WithParams(params),
	}, opts...)...)
}

// PostOp constructs a POST operation
func PostOp(routePath string, body any, res any, opts ...Opt) *Spec {
	rp, params := parseParams(routePath, ParamLocationPath)

	return Of(append([]Opt{
		WithPath(rp),
		WithOriginalPath(routePath),
		WithBody(body),
		WithResponse(res, http.StatusCreated),
		WithErrBadRequest(),
		WithMethod(MethodPost),
		WithParams(params),
	}, opts...)...)
}

// PutOp constructs a PUT operation
func PutOp(routePath string, body any, res any, opts ...Opt) *Spec {
	rp, params := parseParams(routePath, ParamLocationPath)

	return Of(append([]Opt{
		WithPath(rp),
		WithOriginalPath(routePath),
		WithBody(body),
		WithResponse(res, http.StatusOK),
		WithErrNotFound(),
		WithErrBadRequest(),
		WithMethod(MethodPut),
		WithParams(params),
	}, opts...)...)
}

// PatchOp constructs a PATCH operation
func PatchOp(routePath string, body any, res any, opts ...Opt) *Spec {
	rp, params := parseParams(routePath, ParamLocationPath)

	return Of(append([]Opt{
		WithPath(rp),
		WithOriginalPath(routePath),
		WithBody(body),
		WithResponse(res, http.StatusOK),
		WithErrNotFound(),
		WithErrBadRequest(),
		WithMethod(MethodPatch),
		WithParams(params),
	}, opts...)...)
}

// WithTags ...
func (s *Spec) WithTags(tags ...string) *Spec {
	s.Tags = append(s.Tags, tags...)

	return s
}

// WithMethod adds a method for the opration
func WithMethod(m Method) Opt {
	return func(s *Spec) error {
		s.Method = m

		return nil
	}
}

// WithPath adds a path to the request
func WithPath(p string) Opt {
	return func(s *Spec) error {
		s.Path = p

		return nil
	}
}

// WithOriginalPath adds a path to the request
func WithOriginalPath(p string) Opt {
	return func(s *Spec) error {
		s.OriginalPath = p

		return nil
	}
}

// WithPathPrefix adds a prefix for the request
func WithPathPrefix(p string) Opt {
	return func(s *Spec) error {
		s.PathPrefix = p

		return nil
	}
}

// WithBody adds a body for the operation
func WithBody(body any) Opt {
	return func(s *Spec) error {
		s.Body = body

		return nil
	}
}

// WithParam appends a path parameter
func WithParam(loc ParamLocation, title string, paramType ...string) Opt {
	return func(s *Spec) error {
		p := &Parameter{
			Location: loc,
			Title:    title,
			Type:     "string",
		}

		if len(paramType) > 0 {
			p.Type = paramType[0]
		}

		s.Parameters = append(s.Parameters, p)

		return nil
	}
}

// WithParams merges params to operation
func WithParams(params []*Parameter) Opt {
	return func(s *Spec) error {
		s.Parameters = append(s.Parameters, params...)

		return nil
	}
}

// WithResponse appends a response
func WithResponse(body any, code ...int) Opt {
	res := &Response{
		Body: body,
		Code: 200,
	}

	if len(code) > 0 {
		res.Code = code[0]
	}

	return func(s *Spec) error {
		s.Responses = append(s.Responses, res)

		return nil
	}
}

// WithTags appends tags to the operation
func WithTags(tags ...string) Opt {
	return func(s *Spec) error {
		s.Tags = append(s.Tags, tags...)

		return nil
	}
}

// WithSummary adds a summary
func WithSummary(summary string) Opt {
	return func(s *Spec) error {
		s.Summary = summary

		return nil
	}
}

// WithDescription adss a description
func WithDescription(description string) Opt {
	return func(s *Spec) error {
		s.Description = description

		return nil
	}
}

// WithError creates an error response Opt
func WithError(errorCode int, message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithResponse(Err("").SetID(errorCode).Message(msg), errorCode)
}

// WithErrNotFound creates a not found error response Opt
func WithErrNotFound(message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithError(http.StatusNotFound, msg)
}

// WithErrBadRequest creates a bad request error response Opt
func WithErrBadRequest(message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithError(http.StatusBadRequest, msg)
}

// WithInternalError creates an internal server error response Opt
func WithInternalError(message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithError(http.StatusInternalServerError, msg)
}

// WithForbidden creates a forbidden error response Opt
func WithForbidden(message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithError(http.StatusForbidden, msg)
}

// WithUnauthorized creates an unauthorized error response Opt
func WithUnauthorized(message ...string) Opt {
	msg := ""

	if len(message) > 0 {
		msg = message[0]
	}

	return WithError(http.StatusUnauthorized, msg)
}

// WithRoute adds a route to spec
func WithRoute(r *Route) Opt {
	return func(s *Spec) error {
		s.Route = r

		return nil
	}
}

// ReflectorOptions for initing openapi3.Reflector
type ReflectorOptions struct {
	OASVersion string
	Servers    []string
	Port       int

	Title       string
	Description string
	Version     string

	OpenAPIAuthorizationURL string
	OpenIDConnectURL        string
	APIKeyAuth              bool

	OpenAPIClientID string
	OpenAPISecret   string
}

// CreateReflector ...
func CreateReflector(opts *ReflectorOptions) *openapi3.Reflector {
	if opts.OASVersion == "" {
		opts.OASVersion = "3.0.3"
	}

	ref := &openapi3.Reflector{}

	ref.Spec = &openapi3.Spec{Openapi: opts.OASVersion}

	var servers []openapi3.Server

	for _, host := range opts.Servers {
		servers = append(servers, openapi3.Server{
			URL: fmt.Sprintf("http://%s:%d", host, opts.Port),
		})
	}

	ref.Spec.WithServers(servers...)

	ref.Spec.Info.
		WithTitle(opts.Title).
		WithDescription(opts.Description).
		WithVersion(opts.Version)

	if opts.OpenAPIAuthorizationURL != "" {
		ref.SpecEns().ComponentsEns().SecuritySchemesEns().WithMapOfSecuritySchemeOrRefValuesItem(
			"bearer",
			openapi3.SecuritySchemeOrRef{
				SecurityScheme: &openapi3.SecurityScheme{
					OAuth2SecurityScheme: (&openapi3.OAuth2SecurityScheme{}).
						WithFlows(openapi3.OAuthFlows{
							Implicit: &openapi3.ImplicitOAuthFlow{
								AuthorizationURL: opts.OpenAPIAuthorizationURL,
								Scopes:           map[string]string{},
								MapOfAnything: map[string]interface{}{
									"x-client-id":     opts.OpenAPIClientID,
									"x-client-secret": opts.OpenAPISecret,
								},
							},
						}),
				},
			},
		)
	}

	if opts.OpenIDConnectURL != "" {
		ref.SpecEns().ComponentsEns().SecuritySchemesEns().WithMapOfSecuritySchemeOrRefValuesItem(
			"bearer",
			openapi3.SecuritySchemeOrRef{
				SecurityScheme: &openapi3.SecurityScheme{
					OpenIDConnectSecurityScheme: &openapi3.OpenIDConnectSecurityScheme{
						OpenIDConnectURL: "http://localhost:8888/realms/haldri/.well-known/openid-configuration",
					},
				},
			},
		)
	}

	if opts.APIKeyAuth {
		ref.SpecEns().ComponentsEns().SecuritySchemesEns().WithMapOfSecuritySchemeOrRefValuesItem(
			"apikey",
			openapi3.SecuritySchemeOrRef{
				SecurityScheme: &openapi3.SecurityScheme{
					APIKeySecurityScheme: (&openapi3.APIKeySecurityScheme{}).
						WithName("x-api-key").
						WithDescription("API Key authentication").
						WithIn(openapi3.APIKeySecuritySchemeInHeader),
				},
			},
		)
	}

	return ref
}

func parseParams(path string, loc ParamLocation) (string, []*Parameter) {
	var p []*Parameter

	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, ":") {
			segment = strings.ReplaceAll(segment, ":", "")

			p = append(p, &Parameter{
				Title:    segment,
				Location: loc,
				Type:     "string",
			})

			path = strings.ReplaceAll(
				path,
				fmt.Sprintf(":%s", segment),
				fmt.Sprintf("{%s}", segment),
			)
		}
	}

	return path, p
}

func createParam(p *Parameter) *openapi3.Parameter {
	t := openapi3.SchemaType(p.Type)

	param := openapi3.Parameter{}

	param.
		WithName(p.Title).
		WithIn(openapi3.ParameterInPath).
		WithRequired(true).
		WithContentItem(p.Title, openapi3.MediaType{
			Schema: &openapi3.SchemaOrRef{
				Schema: &openapi3.Schema{
					Title: &p.Title,
					Type:  &t,
				},
			},
		})

	if p.Location == ParamLocationHeader {
		param.
			WithIn(openapi3.ParameterInHeader).
			WithLocation(openapi3.ParameterLocation{
				HeaderParameter: &openapi3.HeaderParameter{},
			})
	}

	if p.Location == ParamLocationQuery {
		param.
			WithIn(openapi3.ParameterInHeader).
			WithLocation(openapi3.ParameterLocation{
				QueryParameter: &openapi3.QueryParameter{},
			})
	}

	return &param
}

func handleError(err error) {
	if err != nil {
		log.Trace().Err(err).Send()
	}
}

// CreateGroup ...
func CreateGroup(path string, specs ...*Spec) (string, []*Spec) {
	return path, specs
}
