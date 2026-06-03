package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ── Structs ──────────────────────────────────────────────────────────────────

type APIEndpoint struct {
	File         string   `json:"file"`
	Framework    string   `json:"framework"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	FullPath     string   `json:"full_path"`
	Handler      string   `json:"handler,omitempty"`
	PathParams   []string `json:"path_params,omitempty"`
	AuthRequired bool     `json:"auth_required,omitempty"`
	AuthType     string   `json:"auth_type,omitempty"`
	Line         int      `json:"line"`
}

type ExternalAPI struct {
	File   string `json:"file"`
	URL    string `json:"url"`
	Method string `json:"method"`
	Line   int    `json:"line"`
}

type ScanSummary struct {
	TotalInternalAPIs int            `json:"total_internal_apis"`
	TotalExternalAPIs int            `json:"total_external_apis"`
	FilesScanned      int            `json:"files_scanned"`
	ByFramework       map[string]int `json:"by_framework"`
	ByMethod          map[string]int `json:"by_method"`
}

type APIReport struct {
	ScannedAt    string        `json:"scanned_at"`
	ScannedPath  string        `json:"scanned_path"`
	Summary      ScanSummary   `json:"summary"`
	InternalAPIs []APIEndpoint `json:"internal_apis"`
	ExternalAPIs []ExternalAPI `json:"external_apis"`
}

// ── Directory / path filtering ────────────────────────────────────────────────

var skipDirSet = map[string]bool{
	".venv": true, "venv": true, "env": true, ".env": true,
	"node_modules": true, "vendor": true,
	".git": true, "__pycache__": true,
	"dist": true, "build": true, "out": true,
	".eggs": true, ".idea": true, ".cache": true,
	"coverage": true, "htmlcov": true, ".tox": true,
	".pytest_cache": true, ".mypy_cache": true,
	"migrations": true, "testdata": true,
}

func shouldSkipDir(name string) bool {
	return skipDirSet[name] || strings.HasSuffix(name, ".egg-info")
}

func shouldSkipPath(p string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if shouldSkipDir(part) {
			return true
		}
	}
	return strings.Contains(p, "site-packages")
}

// ── Path-param extraction ─────────────────────────────────────────────────────

var pathParamPatterns = []*regexp.Regexp{
	regexp.MustCompile(`:(\w+)`),               // :param  — Express, Gin, Chi
	regexp.MustCompile(`\{(\w+)(?::[^}]*)?\}`), // {param} / {param:type} — FastAPI, Spring
	regexp.MustCompile(`<(?:\w+:)?(\w+)>`),     // <param> / <type:param>  — Flask
}

func extractPathParams(path string) []string {
	seen := map[string]bool{}
	var params []string
	for _, re := range pathParamPatterns {
		for _, m := range re.FindAllStringSubmatch(path, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				params = append(params, m[1])
			}
		}
	}
	return params // nil when empty → omitted from JSON via omitempty on slice
}

// ── Auth detection ────────────────────────────────────────────────────────────

var authPattern = regexp.MustCompile(
	`(?i)(login_required|jwt_required|require_auth|is_authenticated|token_required|` +
		`auth_required|requires_auth|authenticated|@protected|@secured|@authorize|` +
		`@security|bearer|oauth2|api_key|permission_required|roles_allowed|` +
		`JwtAuthGuard|AuthGuard|UseGuards|PreAuthorize|Secured|RolesAllowed)`)

func detectAuth(ctx []string) (bool, string) {
	joined := strings.Join(ctx, " ")
	if !authPattern.MatchString(joined) {
		return false, ""
	}
	low := strings.ToLower(joined)
	switch {
	case strings.Contains(low, "jwt") || strings.Contains(low, "bearer"):
		return true, "JWT"
	case strings.Contains(low, "oauth"):
		return true, "OAuth"
	case strings.Contains(low, "api_key") || strings.Contains(low, "apikey"):
		return true, "API Key"
	case strings.Contains(low, "basic"):
		return true, "Basic Auth"
	default:
		return true, "Auth"
	}
}

func ctxWindow(lines []string, i, before, after int) []string {
	s := i - before
	if s < 0 {
		s = 0
	}
	e := i + after + 1
	if e > len(lines) {
		e = len(lines)
	}
	return lines[s:e]
}

// ── Handler name helpers ──────────────────────────────────────────────────────

var pyDefRe = regexp.MustCompile(`(?:async\s+)?def\s+(\w+)\s*\(`)

func nextDefName(lines []string, i, maxLook int) string {
	for j := i + 1; j < len(lines) && j <= i+maxLook; j++ {
		if m := pyDefRe.FindStringSubmatch(lines[j]); m != nil {
			return m[1]
		}
	}
	return ""
}

var javaMethodRe = regexp.MustCompile(`(?:public|protected|private)\s+(?:static\s+)?\S+\s+(\w+)\s*\(`)

func nextJavaMethod(lines []string, i, maxLook int) string {
	for j := i + 1; j < len(lines) && j <= i+maxLook; j++ {
		if m := javaMethodRe.FindStringSubmatch(lines[j]); m != nil {
			return m[1]
		}
	}
	return ""
}

// lastCallArg returns the last named arg from the tail of a route call.
// e.g. ", authMW, controller.GetUser)" → "controller.GetUser"
var identOnlyRe = regexp.MustCompile(`^[\w]+(\.[\w]+)*$`)

func lastCallArg(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), ")")
	if s == "" || strings.ContainsAny(s, "{}") || strings.Contains(s, "func") || strings.Contains(s, "=>") {
		return ""
	}
	parts := strings.Split(s, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		t := strings.TrimSpace(parts[i])
		if identOnlyRe.MatchString(t) {
			return t
		}
	}
	return ""
}

// ── Deduplication ─────────────────────────────────────────────────────────────

type dedupKey struct{ method, fullPath, file string }

func deduplicateEndpoints(eps []APIEndpoint) []APIEndpoint {
	seen := map[dedupKey]bool{}
	var out []APIEndpoint
	for _, ep := range eps {
		k := dedupKey{ep.Method, ep.FullPath, ep.File}
		if !seen[k] {
			seen[k] = true
			out = append(out, ep)
		}
	}
	return out
}

// ── File reader ───────────────────────────────────────────────────────────────

func readLines(filePath string) ([]string, string, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, "", err
	}
	content := string(b)
	return strings.Split(content, "\n"), content, nil
}

// ── Go framework regexes (compiled once) ─────────────────────────────────────

var (
	goGinRouteRegex        = regexp.MustCompile(`r\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goGinGroupRouteRegex   = regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goEchoRouteRegex       = regexp.MustCompile(`e\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goEchoGroupRouteRegex  = regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goFiberRouteRegex      = regexp.MustCompile(`app\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goFiberGroupRouteRegex = regexp.MustCompile(`(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*["']([^"']*)["']\s*(.*)`)
	goChiRouteRegex        = regexp.MustCompile(`r\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*["']([^"']+)["']\s*(.*)`)
	goRevelControllerRegex = regexp.MustCompile(`func\s+\(\s*\w+\s+\*?\w*Controller\s*\)\s+(\w+)\s*\(`)
	goGoKitEndpointRegex   = regexp.MustCompile(`func\s+Make(\w+)Endpoint`)
	goHTTPHandleFuncRegex  = regexp.MustCompile(`http\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(.*)`)
	goHTTPHandleRegex      = regexp.MustCompile(`http\.Handle\s*\(\s*["']([^"']+)["']\s*,\s*(.*)`)
	goMuxHandleFuncRegex   = regexp.MustCompile(`mux\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(.*)`)
	goGroupRegex           = regexp.MustCompile(`(\w+)\s*:=\s*\w+\.Group\s*\(\s*["']([^"']+)["']`)
	goHTTPGetRegex         = regexp.MustCompile(`http\.(Get|Post|Head)\s*\(\s*["']([^"']+)["']`)
	goHTTPClientRegex      = regexp.MustCompile(`(client|http)\.(Get|Post|Put|Delete|Patch|Head|Do)\s*\(\s*["']([^"']+)["']`)
	goHTTPURLRegex         = regexp.MustCompile(`["']https?://[^"'\s]+["']`)
)

// ── Java framework regexes (compiled once) ───────────────────────────────────

var (
	javaSpringRequestMappingRegex = regexp.MustCompile(`@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["'](?:.*?method\s*=\s*RequestMethod\.([A-Z]+))?`)
	javaSpringGetMappingRegex     = regexp.MustCompile(`@GetMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaSpringPostMappingRegex    = regexp.MustCompile(`@PostMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaSpringPutMappingRegex     = regexp.MustCompile(`@PutMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaSpringDeleteMappingRegex  = regexp.MustCompile(`@DeleteMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaSpringPatchMappingRegex   = regexp.MustCompile(`@PatchMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaJaxrsPathRegex            = regexp.MustCompile(`@Path\s*\(\s*["']([^"']+)["']`)
	javaJaxrsGETRegex             = regexp.MustCompile(`@GET`)
	javaJaxrsPOSTRegex            = regexp.MustCompile(`@POST`)
	javaJaxrsPUTRegex             = regexp.MustCompile(`@PUT`)
	javaJaxrsDELETERegex          = regexp.MustCompile(`@DELETE`)
	javaJaxrsHEADRegex            = regexp.MustCompile(`@HEAD`)
	javaJaxrsOPTIONSRegex         = regexp.MustCompile(`@OPTIONS`)
	javaMicronautGetRegex         = regexp.MustCompile(`@Get\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaMicronautPostRegex        = regexp.MustCompile(`@Post\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaMicronautPutRegex         = regexp.MustCompile(`@Put\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaMicronautDeleteRegex      = regexp.MustCompile(`@Delete\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	javaVertxRouterRegex          = regexp.MustCompile(`router\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	javaPlayActionRegex           = regexp.MustCompile(`public\s+Result\s+(\w+)\s*\(`)
	javaHTTPClientRegex           = regexp.MustCompile(`(?:HttpClient|RestTemplate|WebClient|OkHttpClient).*?(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	javaHTTPURLRegex              = regexp.MustCompile(`["']https?://[^"'\s]+["']`)
	javaClassRequestMappingRegex  = regexp.MustCompile(`@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
)

// ── Node/TypeScript framework regexes (compiled once) ────────────────────────

// _nq matches one quote char: " ' or `
// _nqc matches any non-quote char
var (
	_nq  = `["'` + "`" + `]`
	_nqc = `[^"'` + "`" + `]`
)

var (
	nodeExpressAppRegex         = regexp.MustCompile(`app\.(get|post|put|delete|patch|head|options|all)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq + `\s*(.*)`)
	nodeExpressRouterRegex      = regexp.MustCompile(`router\.(get|post|put|delete|patch|head|options|all)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq + `\s*(.*)`)
	nodeExpressNamedRouterRegex = regexp.MustCompile(`(\w+)\.(get|post|put|delete|patch|head|options|all)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq + `\s*(.*)`)
	nodeAppUseRegex             = regexp.MustCompile(`app\.use\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq + `\s*,\s*(\w+)`)
	nodeKoaRouterRegex          = regexp.MustCompile(`koaRouter\.(get|post|put|delete|patch|head|options|all)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq)
	nodeNestJSDecoratorRegex    = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*` + _nq + `?(` + _nqc + `*)` + _nq + `?\s*\)`)
	nodeNestJSControllerRegex   = regexp.MustCompile(`@Controller\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq + `\s*\)`)
	nodeHapiMethodRegex         = regexp.MustCompile(`method:\s*` + _nq + `([^"'` + "`" + `]+)` + _nq)
	nodeHapiPathRegex           = regexp.MustCompile(`path:\s*` + _nq + `(` + _nqc + `+)` + _nq)
	nodeSailsRouteRegex         = regexp.MustCompile(_nq + `([A-Z]+)\s+([^"'` + "`" + `]+)` + _nq + `\s*:\s*` + _nq + `([^"'` + "`" + `]+)` + _nq)
	nodeLoopbackRemoteRegex     = regexp.MustCompile(`(\w+)\.remoteMethod\s*\(\s*` + _nq + `([^"'` + "`" + `]+)` + _nq)
	nodeNextJSHandlerRegex      = regexp.MustCompile(`export\s+default\s+function\s+handler\s*\(\s*req\s*,\s*res\s*\)`)
	nodeNextJSMethodRegex       = regexp.MustCompile(`if\s*\(\s*req\.method\s*===?\s*` + _nq + `([^"'` + "`" + `]+)` + _nq)
	nodeAxiosRegex              = regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq)
	nodeFetchRegex              = regexp.MustCompile(`fetch\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq)
	nodeRequestRegex            = regexp.MustCompile(`request\.(get|post|put|delete|patch)\s*\(\s*` + _nq + `(` + _nqc + `+)` + _nq)
	nodeHTTPURLRegex            = regexp.MustCompile(_nq + `https?://[^"'` + "`" + `\s]+` + _nq)
	nodeHandlerRe               = regexp.MustCompile(`(?:async\s+)?(\w+)\s*\(`)
)

// ── Python framework regexes (compiled once) ─────────────────────────────────

var (
	pyFlaskRouteRegex         = regexp.MustCompile(`@app\.route\s*\(\s*["']([^"']+)["'](?:.*?methods\s*=\s*\[["']([^"']+)["']\])?`)
	pyFlaskMethodRegex        = regexp.MustCompile(`@app\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	pyBlueprintDefRegex       = regexp.MustCompile(`(\w+)\s*=\s*Blueprint\s*\(\s*["']([^"']+)["']\s*,\s*__name__\s*(?:,\s*url_prefix\s*=\s*["']([^"']+)["'])?`)
	pyBlueprintRouteRegex     = regexp.MustCompile(`@(\w+)\.route\s*\(\s*["']([^"']+)["'](?:.*?methods\s*=\s*\[["']([^"']+)["']\])?`)
	pyBlueprintMethodRegex    = regexp.MustCompile(`@(\w+)\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	pyFastAPIRouterDefRegex   = regexp.MustCompile(`(\w+)\s*=\s*APIRouter\s*\(\s*(?:.*?prefix\s*=\s*["']([^"']+)["'])?`)
	pyFastAPIRouterRouteRegex = regexp.MustCompile(`@(\w+)\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	pyDjangoPathRegex         = regexp.MustCompile(`path\s*\(\s*["']([^"']+)["']`)
	pyDjangoURLRegex          = regexp.MustCompile(`url\s*\(\s*r?["']([^"']+)["']`)
	pyTornadoHandlerRegex     = regexp.MustCompile(`class\s+(\w+)\s*\(\s*RequestHandler\s*\)`)
	pyTornadoMethodRegex      = regexp.MustCompile(`def\s+(get|post|put|delete|patch|head|options)\s*\(`)
	pyFalconRouteRegex        = regexp.MustCompile(`app\.add_route\s*\(\s*["']([^"']+)["']`)
	pyDRFRouterRegex          = regexp.MustCompile(`router\.register\s*\(\s*r?["']([^"']+)["']\s*,\s*(\w+)`)
	pyPyramidRouteRegex       = regexp.MustCompile(`config\.add_route\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	pyPyramidViewRegex        = regexp.MustCompile(`@view_config\s*\(\s*route_name\s*=\s*["']([^"']+)["']`)
	pyRequestsGetRegex        = regexp.MustCompile(`requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	pyUrllibRegex             = regexp.MustCompile(`urllib\.request\.urlopen\s*\(\s*["']([^"']+)["']`)
	pyHTTPXRegex              = regexp.MustCompile(`httpx\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
	pyHTTPURLRegex            = regexp.MustCompile(`["']https?://[^"'\s]+["']`)
)

// ── Go parser ─────────────────────────────────────────────────────────────────

func parseGoFile(filePath string, verbose bool) (*APIReport, error) {
	lines, content, err := readLines(filePath)
	if err != nil {
		return nil, err
	}

	var report APIReport

	// Framework detection
	isGin := strings.Contains(content, `"github.com/gin-gonic/gin"`) || strings.Contains(content, "gin.")
	isEcho := strings.Contains(content, `"github.com/labstack/echo"`) || strings.Contains(content, "echo.")
	isFiber := strings.Contains(content, `"github.com/gofiber/fiber"`) || strings.Contains(content, "fiber.")
	isChi := strings.Contains(content, `"github.com/go-chi/chi"`) || strings.Contains(content, `"github.com/go-chi/chi/v5"`)

	routerGroups := map[string]string{}

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		lineNum := i + 1
		ctx := ctxWindow(lines, i, 5, 0)

		// Gin routes
		if matches := goGinRouteRegex.FindStringSubmatch(line); matches != nil && isGin {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Gin", Method: method,
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[3]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			if verbose {
				fmt.Printf("Gin: %s %s at %s:%d\n", method, path, filePath, lineNum)
			}
		}

		// Gin grouped routes
		if matches := goGinGroupRouteRegex.FindStringSubmatch(line); matches != nil && isGin {
			groupName := matches[1]
			if groupName == "r" || groupName == "e" || groupName == "app" {
				continue
			}
			method := strings.ToUpper(matches[2])
			routePath := matches[3]
			fullPath := routePath
			if prefix, ok := routerGroups[groupName]; ok {
				if routePath == "" {
					fullPath = prefix
				} else {
					fullPath = prefix + routePath
				}
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Gin", Method: method,
				Path: routePath, FullPath: fullPath,
				Handler:      lastCallArg(matches[4]),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			if verbose {
				fmt.Printf("Gin group: %s %s→%s at %s:%d\n", method, routePath, fullPath, filePath, lineNum)
			}
		}

		// Echo routes
		if matches := goEchoRouteRegex.FindStringSubmatch(line); matches != nil && isEcho {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Echo", Method: method,
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[3]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Echo grouped routes
		if matches := goEchoGroupRouteRegex.FindStringSubmatch(line); matches != nil && isEcho {
			groupName := matches[1]
			if groupName == "r" || groupName == "e" || groupName == "app" {
				continue
			}
			method := strings.ToUpper(matches[2])
			routePath := matches[3]
			fullPath := routePath
			if prefix, ok := routerGroups[groupName]; ok {
				if routePath == "" {
					fullPath = prefix
				} else {
					fullPath = prefix + routePath
				}
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Echo", Method: method,
				Path: routePath, FullPath: fullPath,
				Handler:      lastCallArg(matches[4]),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Fiber routes
		if matches := goFiberRouteRegex.FindStringSubmatch(line); matches != nil && isFiber {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
				continue
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Fiber", Method: method,
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[3]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Fiber grouped routes
		if matches := goFiberGroupRouteRegex.FindStringSubmatch(line); matches != nil && isFiber {
			groupName := matches[1]
			if groupName == "r" || groupName == "e" || groupName == "app" {
				continue
			}
			method := strings.ToUpper(matches[2])
			routePath := matches[3]
			if strings.HasPrefix(routePath, "http://") || strings.HasPrefix(routePath, "https://") {
				continue
			}
			fullPath := routePath
			if prefix, ok := routerGroups[groupName]; ok {
				if routePath == "" {
					fullPath = prefix
				} else {
					fullPath = prefix + routePath
				}
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Fiber", Method: method,
				Path: routePath, FullPath: fullPath,
				Handler:      lastCallArg(matches[4]),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Chi routes — guard prevents false matches on Gin/Echo files that also use `r.`
		if matches := goChiRouteRegex.FindStringSubmatch(line); matches != nil && isChi {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Chi", Method: method,
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[3]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Revel controller methods
		if matches := goRevelControllerRegex.FindStringSubmatch(line); matches != nil {
			methodName := matches[1]
			path := "/" + strings.ToLower(methodName)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Revel", Method: "GET",
				Path: path, FullPath: path,
				Handler: methodName,
				Line:    lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Go-Kit endpoints
		if matches := goGoKitEndpointRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			path := "/" + strings.ToLower(name)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Go-Kit", Method: "POST",
				Path: path, FullPath: path,
				Handler: "Make" + name + "Endpoint",
				Line:    lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// net/http HandleFunc
		if matches := goHTTPHandleFuncRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "net/http", Method: "GET",
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[2]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// net/http Handle
		if matches := goHTTPHandleRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "net/http", Method: "GET",
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[2]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Gorilla Mux HandleFunc
		if matches := goMuxHandleFuncRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Gorilla Mux", Method: "GET",
				Path: path, FullPath: path,
				Handler:      lastCallArg(matches[2]),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Router group detection
		if matches := goGroupRegex.FindStringSubmatch(line); matches != nil {
			routerGroups[matches[1]] = matches[2]
		}

		// External API detection
		var foundExt bool
		if matches := goHTTPGetRegex.FindStringSubmatch(line); matches != nil {
			report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
				File: filePath, URL: matches[2], Method: strings.ToUpper(matches[1]), Line: lineNum,
			})
			foundExt = true
		}
		if !foundExt {
			if matches := goHTTPClientRegex.FindStringSubmatch(line); matches != nil {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: matches[3], Method: strings.ToUpper(matches[2]), Line: lineNum,
				})
				foundExt = true
			}
		}
		if !foundExt {
			for _, u := range goHTTPURLRegex.FindAllString(line, -1) {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: strings.Trim(u, `"'`), Method: "UNKNOWN", Line: lineNum,
				})
			}
		}
	}

	return &report, nil
}

// ── Java parser ───────────────────────────────────────────────────────────────

func parseJavaFile(filePath string, verbose bool) (*APIReport, error) {
	lines, _, err := readLines(filePath)
	if err != nil {
		return nil, err
	}

	var report APIReport

	var currentJaxrsPath string
	var currentClassPath string
	var nextMethodInfo struct {
		method string
		line   int
	}

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		lineNum := i + 1
		ctx := ctxWindow(lines, i, 5, 1)

		// Class-level @RequestMapping
		if matches := javaClassRequestMappingRegex.FindStringSubmatch(line); matches != nil {
			if !strings.Contains(line, "public") && !strings.Contains(line, "def") {
				currentClassPath = matches[1]
			}
		}

		// Spring Boot RequestMapping (method-level)
		if matches := javaSpringRequestMappingRegex.FindStringSubmatch(line); matches != nil &&
			!strings.Contains(line, "class") && !strings.Contains(line, "@RestController") &&
			strings.Contains(line, "public") {
			method := "GET"
			if len(matches) > 2 && matches[2] != "" {
				method = matches[2]
			}
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: method,
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Spring Boot GetMapping
		if matches := javaSpringGetMappingRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: "GET",
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Spring Boot PostMapping
		if matches := javaSpringPostMappingRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: "POST",
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Spring Boot PutMapping
		if matches := javaSpringPutMappingRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: "PUT",
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Spring Boot DeleteMapping
		if matches := javaSpringDeleteMappingRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: "DELETE",
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Spring Boot PatchMapping
		if matches := javaSpringPatchMappingRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			fullPath := path
			if currentClassPath != "" {
				fullPath = currentClassPath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Spring Boot", Method: "PATCH",
				Path: path, FullPath: fullPath,
				Handler:      nextJavaMethod(lines, i, 3),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// JAX-RS @Path
		if matches := javaJaxrsPathRegex.FindStringSubmatch(line); matches != nil {
			currentJaxrsPath = matches[1]
		}

		// JAX-RS HTTP method annotations
		switch {
		case javaJaxrsGETRegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "GET", lineNum
		case javaJaxrsPOSTRegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "POST", lineNum
		case javaJaxrsPUTRegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "PUT", lineNum
		case javaJaxrsDELETERegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "DELETE", lineNum
		case javaJaxrsHEADRegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "HEAD", lineNum
		case javaJaxrsOPTIONSRegex.MatchString(line):
			nextMethodInfo.method, nextMethodInfo.line = "OPTIONS", lineNum
		}

		// JAX-RS method definition follows annotation
		if nextMethodInfo.method != "" && strings.Contains(line, "public") && strings.Contains(line, "(") {
			path := currentJaxrsPath
			if path == "" {
				path = "/unknown"
			}
			handlerName := ""
			if m := javaMethodRe.FindStringSubmatch(line); m != nil {
				handlerName = m[1]
			}
			authReq, authType := detectAuth(ctxWindow(lines, i, 8, 0))
			endpoint := APIEndpoint{
				File: filePath, Framework: "JAX-RS", Method: nextMethodInfo.method,
				Path: path, FullPath: path,
				Handler:      handlerName,
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: nextMethodInfo.line,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			nextMethodInfo.method = ""
		}

		// Micronaut
		for _, item := range []struct {
			re     *regexp.Regexp
			method string
		}{
			{javaMicronautGetRegex, "GET"}, {javaMicronautPostRegex, "POST"},
			{javaMicronautPutRegex, "PUT"}, {javaMicronautDeleteRegex, "DELETE"},
		} {
			if matches := item.re.FindStringSubmatch(line); matches != nil {
				path := matches[1]
				authReq, authType := detectAuth(ctx)
				endpoint := APIEndpoint{
					File: filePath, Framework: "Micronaut", Method: item.method,
					Path: path, FullPath: path,
					Handler:      nextJavaMethod(lines, i, 3),
					PathParams:   extractPathParams(path),
					AuthRequired: authReq, AuthType: authType,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// Vert.x
		if matches := javaVertxRouterRegex.FindStringSubmatch(line); matches != nil {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Vert.x", Method: method,
				Path: path, FullPath: path,
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Play Framework
		if matches := javaPlayActionRegex.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			path := "/" + strings.ToLower(name)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Play", Method: "GET",
				Path: path, FullPath: path,
				Handler: name,
				Line:    lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// External
		var foundExt bool
		if matches := javaHTTPClientRegex.FindStringSubmatch(line); matches != nil {
			report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
				File: filePath, URL: matches[1], Method: "UNKNOWN", Line: lineNum,
			})
			foundExt = true
		}
		if !foundExt {
			for _, u := range javaHTTPURLRegex.FindAllString(line, -1) {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: strings.Trim(u, `"'`), Method: "UNKNOWN", Line: lineNum,
				})
			}
		}
	}

	return &report, nil
}

// ── Node/TypeScript parser ────────────────────────────────────────────────────

func parseNodeFile(filePath string, verbose bool) (*APIReport, error) {
	lines, _, err := readLines(filePath)
	if err != nil {
		return nil, err
	}

	var report APIReport

	isNextJSAPIRoute := strings.Contains(filePath, "/api/") || strings.Contains(filePath, `\api\`)

	// First pass: collect router prefix mappings
	expressRouterPrefixes := map[string]string{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if m := nodeAppUseRegex.FindStringSubmatch(line); m != nil {
			expressRouterPrefixes[m[2]] = m[1]
		}
	}

	var currentMiddlewarePath string
	var nestJSControllerPrefix string
	var hapiCurrentMethod string
	nextJSHandlerFound := false

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		lineNum := i + 1
		ctx := ctxWindow(lines, i, 5, 0)

		if m := nodeAppUseRegex.FindStringSubmatch(line); m != nil {
			currentMiddlewarePath = m[1]
		}

		if m := nodeNestJSControllerRegex.FindStringSubmatch(line); m != nil {
			nestJSControllerPrefix = m[1]
		}

		// Express app routes
		if m := nodeExpressAppRegex.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := m[2]
			fullPath := path
			if currentMiddlewarePath != "" && !strings.HasPrefix(path, currentMiddlewarePath) {
				fullPath = currentMiddlewarePath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Express", Method: method,
				Path: path, FullPath: fullPath,
				Handler:      lastCallArg(m[3]),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Express router routes
		if m := nodeExpressRouterRegex.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := m[2]
			fullPath := path
			if currentMiddlewarePath != "" && !strings.HasPrefix(path, currentMiddlewarePath) {
				fullPath = currentMiddlewarePath + path
			}
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Express", Method: method,
				Path: path, FullPath: fullPath,
				Handler:      lastCallArg(m[3]),
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Express named router routes
		if m := nodeExpressNamedRouterRegex.FindStringSubmatch(line); m != nil {
			routerName := m[1]
			if routerName == "app" || routerName == "router" || routerName == "koaRouter" ||
				routerName == "axios" || routerName == "fetch" || routerName == "request" {
				goto afterNamedRouter
			}
			{
				method := strings.ToUpper(m[2])
				path := m[3]
				if strings.HasPrefix(path, "http") {
					goto afterNamedRouter
				}
				fullPath := path
				if prefix, ok := expressRouterPrefixes[routerName]; ok {
					fullPath = prefix + path
				}
				authReq, authType := detectAuth(ctx)
				endpoint := APIEndpoint{
					File: filePath, Framework: "Express", Method: method,
					Path: path, FullPath: fullPath,
					Handler:      lastCallArg(m[4]),
					PathParams:   extractPathParams(fullPath),
					AuthRequired: authReq, AuthType: authType,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}
	afterNamedRouter:

		// Koa
		if m := nodeKoaRouterRegex.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := m[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Koa", Method: method,
				Path: path, FullPath: path,
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// NestJS decorators
		if m := nodeNestJSDecoratorRegex.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := m[2]
			if path == "" {
				path = "/"
			}
			fullPath := path
			if nestJSControllerPrefix != "" {
				if strings.HasPrefix(path, "/") {
					fullPath = "/" + nestJSControllerPrefix + path
				} else {
					fullPath = "/" + nestJSControllerPrefix + "/" + path
				}
			}
			handler := ""
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if hm := nodeHandlerRe.FindStringSubmatch(strings.TrimSpace(lines[j])); hm != nil {
					handler = hm[1]
					break
				}
			}
			authReq, authType := detectAuth(ctxWindow(lines, i, 5, 0))
			endpoint := APIEndpoint{
				File: filePath, Framework: "NestJS", Method: method,
				Path: path, FullPath: fullPath,
				Handler:      handler,
				PathParams:   extractPathParams(fullPath),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Hapi method
		if m := nodeHapiMethodRegex.FindStringSubmatch(line); m != nil {
			hapiCurrentMethod = strings.ToUpper(m[1])
		}

		// Hapi path
		if m := nodeHapiPathRegex.FindStringSubmatch(line); m != nil && hapiCurrentMethod != "" {
			path := m[1]
			authReq, authType := detectAuth(ctxWindow(lines, i, 10, 0))
			endpoint := APIEndpoint{
				File: filePath, Framework: "Hapi", Method: hapiCurrentMethod,
				Path: path, FullPath: path,
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			hapiCurrentMethod = ""
		}

		// Sails
		if m := nodeSailsRouteRegex.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			path := strings.TrimSpace(m[2])
			endpoint := APIEndpoint{
				File: filePath, Framework: "Sails", Method: method,
				Path: path, FullPath: path,
				PathParams: extractPathParams(path),
				Line:       lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// LoopBack
		if m := nodeLoopbackRemoteRegex.FindStringSubmatch(line); m != nil {
			path := "/" + m[2]
			endpoint := APIEndpoint{
				File: filePath, Framework: "LoopBack", Method: "POST",
				Path: path, FullPath: path,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Next.js API routes
		if isNextJSAPIRoute {
			if nodeNextJSHandlerRegex.MatchString(line) {
				nextJSHandlerFound = true
				pathParts := strings.Split(filePath, "/api/")
				if len(pathParts) < 2 {
					pathParts = strings.Split(filePath, `\api\`)
				}
				if len(pathParts) >= 2 {
					routePath := "/" + strings.TrimSuffix(strings.TrimSuffix(pathParts[1], ".js"), ".ts")
					routePath = strings.ReplaceAll(routePath, `\`, "/")
					endpoint := APIEndpoint{
						File: filePath, Framework: "Next.js", Method: "GET",
						Path: routePath, FullPath: routePath,
						Line: lineNum,
					}
					report.InternalAPIs = append(report.InternalAPIs, endpoint)
				}
			}
			if nextJSHandlerFound {
				if m := nodeNextJSMethodRegex.FindStringSubmatch(line); m != nil {
					method := strings.ToUpper(m[1])
					pathParts := strings.Split(filePath, "/api/")
					if len(pathParts) < 2 {
						pathParts = strings.Split(filePath, `\api\`)
					}
					if len(pathParts) >= 2 {
						routePath := "/" + strings.TrimSuffix(strings.TrimSuffix(pathParts[1], ".js"), ".ts")
						routePath = strings.ReplaceAll(routePath, `\`, "/")
						endpoint := APIEndpoint{
							File: filePath, Framework: "Next.js", Method: method,
							Path: routePath, FullPath: routePath,
							Line: lineNum,
						}
						report.InternalAPIs = append(report.InternalAPIs, endpoint)
					}
				}
			}
		}

		// External
		var foundExt bool
		if m := nodeAxiosRegex.FindStringSubmatch(line); m != nil {
			report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
				File: filePath, URL: m[2], Method: strings.ToUpper(m[1]), Line: lineNum,
			})
			foundExt = true
		}
		if !foundExt {
			if m := nodeFetchRegex.FindStringSubmatch(line); m != nil {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: m[1], Method: "GET", Line: lineNum,
				})
				foundExt = true
			}
		}
		if !foundExt {
			if m := nodeRequestRegex.FindStringSubmatch(line); m != nil {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: m[2], Method: strings.ToUpper(m[1]), Line: lineNum,
				})
				foundExt = true
			}
		}
		if !foundExt {
			for _, u := range nodeHTTPURLRegex.FindAllString(line, -1) {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: strings.Trim(u, "`\"'"), Method: "UNKNOWN", Line: lineNum,
				})
			}
		}
	}

	return &report, nil
}

// ── Python parser ─────────────────────────────────────────────────────────────

func parsePythonFile(filePath string, verbose bool) (*APIReport, error) {
	lines, content, err := readLines(filePath)
	if err != nil {
		return nil, err
	}

	var report APIReport

	isFlask := strings.Contains(content, "from flask import") || strings.Contains(content, "import flask")
	isFastAPI := strings.Contains(content, "from fastapi import") || strings.Contains(content, "import fastapi")

	// Only detect Django URL patterns in URL config files to avoid false positives.
	isDjangoURLFile := strings.Contains(content, "urlpatterns") ||
		strings.Contains(content, "from django.urls") ||
		strings.Contains(content, "from django.conf.urls") ||
		strings.Contains(strings.ToLower(filepath.Base(filePath)), "url")

	blueprintPrefixes := map[string]string{}
	routerPrefixes := map[string]string{}
	var currentTornadoHandler string

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		lineNum := i + 1
		ctx := ctxWindow(lines, i, 5, 0)

		// FastAPI direct app decorators (check before Flask to avoid collision)
		if matches := pyFlaskMethodRegex.FindStringSubmatch(line); matches != nil && isFastAPI {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "FastAPI", Method: method,
				Path: path, FullPath: path,
				Handler:      nextDefName(lines, i, 3),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			continue
		}

		// Flask method decorators
		if matches := pyFlaskMethodRegex.FindStringSubmatch(line); matches != nil && isFlask {
			method := strings.ToUpper(matches[1])
			path := matches[2]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Flask", Method: method,
				Path: path, FullPath: path,
				Handler:      nextDefName(lines, i, 3),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
			continue
		}

		// Blueprint / FastAPI Router definition
		if matches := pyBlueprintDefRegex.FindStringSubmatch(line); matches != nil {
			prefix := ""
			if len(matches) > 3 {
				prefix = matches[3]
			}
			blueprintPrefixes[matches[1]] = prefix
		}
		if matches := pyFastAPIRouterDefRegex.FindStringSubmatch(line); matches != nil {
			prefix := ""
			if len(matches) > 2 {
				prefix = matches[2]
			}
			routerPrefixes[matches[1]] = prefix
		}

		// Flask Blueprint routes
		if matches := pyBlueprintRouteRegex.FindStringSubmatch(line); matches != nil && isFlask {
			bpName := matches[1]
			if bpName == "app" {
				goto afterBpRoute
			}
			{
				routePath := matches[2]
				method := "GET"
				if len(matches) > 3 && matches[3] != "" {
					method = strings.ToUpper(matches[3])
				}
				fullPath := routePath
				if prefix, ok := blueprintPrefixes[bpName]; ok && prefix != "" {
					fullPath = prefix + routePath
				}
				authReq, authType := detectAuth(ctx)
				endpoint := APIEndpoint{
					File: filePath, Framework: "Flask", Method: method,
					Path: routePath, FullPath: fullPath,
					Handler:      nextDefName(lines, i, 3),
					PathParams:   extractPathParams(fullPath),
					AuthRequired: authReq, AuthType: authType,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}
	afterBpRoute:

		// Flask Blueprint method decorators
		if matches := pyBlueprintMethodRegex.FindStringSubmatch(line); matches != nil && isFlask {
			bpName := matches[1]
			if bpName != "app" {
				method := strings.ToUpper(matches[2])
				routePath := matches[3]
				fullPath := routePath
				if prefix, ok := blueprintPrefixes[bpName]; ok && prefix != "" {
					fullPath = prefix + routePath
				}
				authReq, authType := detectAuth(ctx)
				endpoint := APIEndpoint{
					File: filePath, Framework: "Flask", Method: method,
					Path: routePath, FullPath: fullPath,
					Handler:      nextDefName(lines, i, 3),
					PathParams:   extractPathParams(fullPath),
					AuthRequired: authReq, AuthType: authType,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// FastAPI Router routes
		if matches := pyFastAPIRouterRouteRegex.FindStringSubmatch(line); matches != nil && isFastAPI {
			routerName := matches[1]
			if routerName != "app" {
				method := strings.ToUpper(matches[2])
				routePath := matches[3]
				fullPath := routePath
				if prefix, ok := routerPrefixes[routerName]; ok && prefix != "" {
					fullPath = prefix + routePath
				}
				authReq, authType := detectAuth(ctx)
				endpoint := APIEndpoint{
					File: filePath, Framework: "FastAPI", Method: method,
					Path: routePath, FullPath: fullPath,
					Handler:      nextDefName(lines, i, 3),
					PathParams:   extractPathParams(fullPath),
					AuthRequired: authReq, AuthType: authType,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// Flask @app.route
		if matches := pyFlaskRouteRegex.FindStringSubmatch(line); matches != nil && isFlask {
			method := "GET"
			if len(matches) > 2 && matches[2] != "" {
				method = strings.ToUpper(matches[2])
			}
			path := matches[1]
			authReq, authType := detectAuth(ctx)
			endpoint := APIEndpoint{
				File: filePath, Framework: "Flask", Method: method,
				Path: path, FullPath: path,
				Handler:      nextDefName(lines, i, 3),
				PathParams:   extractPathParams(path),
				AuthRequired: authReq, AuthType: authType,
				Line: lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// Django — guarded by isDjangoURLFile
		if isDjangoURLFile {
			if matches := pyDjangoPathRegex.FindStringSubmatch(line); matches != nil {
				path := matches[1]
				endpoint := APIEndpoint{
					File: filePath, Framework: "Django", Method: "GET",
					Path: path, FullPath: path,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
			if matches := pyDjangoURLRegex.FindStringSubmatch(line); matches != nil {
				path := matches[1]
				endpoint := APIEndpoint{
					File: filePath, Framework: "Django", Method: "GET",
					Path: path, FullPath: path,
					Line: lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// Tornado handler class
		if matches := pyTornadoHandlerRegex.FindStringSubmatch(line); matches != nil {
			currentTornadoHandler = matches[1]
		}

		// Tornado handler methods
		if currentTornadoHandler != "" {
			if matches := pyTornadoMethodRegex.FindStringSubmatch(line); matches != nil {
				method := strings.ToUpper(matches[1])
				path := "/" + strings.ToLower(currentTornadoHandler)
				endpoint := APIEndpoint{
					File: filePath, Framework: "Tornado", Method: method,
					Path: path, FullPath: path,
					Handler: currentTornadoHandler + "." + matches[1],
					Line:    lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// Falcon
		if matches := pyFalconRouteRegex.FindStringSubmatch(line); matches != nil {
			path := matches[1]
			endpoint := APIEndpoint{
				File: filePath, Framework: "Falcon", Method: "GET",
				Path: path, FullPath: path,
				PathParams: extractPathParams(path),
				Line:       lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// DRF ViewSet — generates CRUD endpoints
		if matches := pyDRFRouterRegex.FindStringSubmatch(line); matches != nil {
			basePath := matches[1]
			viewSet := matches[2]
			for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
				endpoint := APIEndpoint{
					File: filePath, Framework: "Django REST Framework", Method: method,
					Path: basePath, FullPath: basePath,
					Handler: viewSet,
					Line:    lineNum,
				}
				report.InternalAPIs = append(report.InternalAPIs, endpoint)
			}
		}

		// Pyramid
		if matches := pyPyramidRouteRegex.FindStringSubmatch(line); matches != nil {
			path := matches[2]
			endpoint := APIEndpoint{
				File: filePath, Framework: "Pyramid", Method: "GET",
				Path: path, FullPath: path,
				PathParams: extractPathParams(path),
				Line:       lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}
		if matches := pyPyramidViewRegex.FindStringSubmatch(line); matches != nil {
			path := "/" + matches[1]
			endpoint := APIEndpoint{
				File: filePath, Framework: "Pyramid", Method: "GET",
				Path: path, FullPath: path,
				Handler: nextDefName(lines, i, 3),
				Line:    lineNum,
			}
			report.InternalAPIs = append(report.InternalAPIs, endpoint)
		}

		// External
		var foundExt bool
		if matches := pyRequestsGetRegex.FindStringSubmatch(line); matches != nil {
			report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
				File: filePath, URL: matches[2], Method: strings.ToUpper(matches[1]), Line: lineNum,
			})
			foundExt = true
		}
		if !foundExt {
			if matches := pyUrllibRegex.FindStringSubmatch(line); matches != nil {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: matches[1], Method: "GET", Line: lineNum,
				})
				foundExt = true
			}
		}
		if !foundExt {
			if matches := pyHTTPXRegex.FindStringSubmatch(line); matches != nil {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: matches[2], Method: strings.ToUpper(matches[1]), Line: lineNum,
				})
				foundExt = true
			}
		}
		if !foundExt {
			for _, u := range pyHTTPURLRegex.FindAllString(line, -1) {
				report.ExternalAPIs = append(report.ExternalAPIs, ExternalAPI{
					File: filePath, URL: strings.Trim(u, `"'`), Method: "UNKNOWN", Line: lineNum,
				})
			}
		}
	}

	return &report, nil
}

// ── Scanner entry points ───────────────────────────────────────────────────────

func RunAPIFinder(path, output string, verbose bool) {
	fmt.Printf("Scanning: %s\n", path)

	report, filesScanned, err := scanDirectory(path, verbose)
	if err != nil {
		log.Fatalf("scan error: %v", err)
	}

	report.InternalAPIs = deduplicateEndpoints(report.InternalAPIs)
	report.ScannedAt = time.Now().UTC().Format(time.RFC3339)
	report.ScannedPath = path

	// Build summary
	byFramework := map[string]int{}
	byMethod := map[string]int{}
	for _, ep := range report.InternalAPIs {
		byFramework[ep.Framework]++
		byMethod[ep.Method]++
	}
	report.Summary = ScanSummary{
		TotalInternalAPIs: len(report.InternalAPIs),
		TotalExternalAPIs: len(report.ExternalAPIs),
		FilesScanned:      filesScanned,
		ByFramework:       byFramework,
		ByMethod:          byMethod,
	}

	jsonOutput, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("marshal error: %v", err)
	}

	fmt.Println(string(jsonOutput))

	if output != "" {
		if err := os.WriteFile(output, jsonOutput, 0644); err != nil {
			log.Fatalf("write error: %v", err)
		}
		fmt.Printf("Output written to: %s\n", output)
	}
}

func scanDirectory(root string, verbose bool) (*APIReport, int, error) {
	var report APIReport
	filesScanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipPath(path) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		var parser func(string, bool) (*APIReport, error)

		switch ext {
		case ".py":
			parser = parsePythonFile
		case ".go":
			parser = parseGoFile
		case ".js", ".ts":
			parser = parseNodeFile
		case ".java":
			parser = parseJavaFile
		default:
			return nil
		}

		filesScanned++
		fileReport, err := parser(path, verbose)
		if err != nil {
			if verbose {
				fmt.Printf("Warning: error parsing %s: %v\n", path, err)
			}
			return nil
		}

		report.InternalAPIs = append(report.InternalAPIs, fileReport.InternalAPIs...)
		report.ExternalAPIs = append(report.ExternalAPIs, fileReport.ExternalAPIs...)
		return nil
	})

	return &report, filesScanned, err
}
