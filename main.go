package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// --- Compiled regex patterns ---

// ARCH-001: Circular dependency risk patterns.
var (
	reGoImport = regexp.MustCompile(`^\s*"([^"]+)"`)
	rePyImport = regexp.MustCompile(`(?:^from\s+(\S+)\s+import|^import\s+(\S+))`)
	reJSImport = regexp.MustCompile(`(?:(?:import\s+.*\s+from|require)\s*\(?\s*['"](\.[^'"]+)['"])`)
)

// ARCH-002: God object / God file — export patterns.
var (
	reGoExport    = regexp.MustCompile(`^(?:func|type|var|const)\s+([A-Z]\w*)`)
	rePyExport    = regexp.MustCompile(`^(?:def|class)\s+([A-Za-z]\w*)\s*[\(:]`)
	reJSExport    = regexp.MustCompile(`(?:^export\s+(?:default\s+)?(?:function|class|const|let|var|interface|type|enum)\s+(\w+)|^module\.exports)`)
	rePyAllExport = regexp.MustCompile(`^__all__\s*=`)
)

// ARCH-003: Security-critical code patterns.
var (
	reCryptoGo  = regexp.MustCompile(`(?i)(?:crypto/|golang\.org/x/crypto|bcrypt|argon2|hmac\.New|cipher\.|hash\.)`)
	reCryptoPy  = regexp.MustCompile(`(?i)(?:from\s+cryptography|import\s+hashlib|import\s+hmac|from\s+Crypto|bcrypt\.|passlib\.)`)
	reCryptoJS  = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"]crypto['"]|from\s+['"]crypto['"]|bcrypt|argon2|jsonwebtoken|jose)`)
	reAuthGo    = regexp.MustCompile(`(?i)(?:func\s+\w*(?:Auth|Login|Verify|Validate(?:Token|JWT|Password)))\s*\(`)
	reAuthPy    = regexp.MustCompile(`(?i)(?:def\s+\w*(?:auth|login|verify|validate_(?:token|jwt|password)))\s*\(`)
	reAuthJS    = regexp.MustCompile(`(?i)(?:function\s+\w*(?:auth|login|verify|validate(?:Token|JWT|Password)))\s*\(`)
	reBizLogic  = regexp.MustCompile(`(?i)(?:func|def|function)\s+\w*(?:handle|process|create|update|delete|get|list|fetch|save|submit|calculate|compute)\w*\s*\(`)
	reDBAccess  = regexp.MustCompile(`(?i)(?:\.(?:Query|Exec|Execute|Find|Create|Save|Delete|Remove|Insert|Update)\s*\(|SELECT\s|INSERT\s|UPDATE\s|DELETE\s)`)
	reHTTPRoute = regexp.MustCompile(`(?i)(?:app\.(?:get|post|put|delete|patch)|http\.HandleFunc|router\.|@app\.route)`)
)

// ARCH-004: Missing abstraction layer patterns.
var (
	reSQLInHandler = regexp.MustCompile(`(?i)(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|db\.(?:Query|Exec|Execute|Raw)\s*\()`)
	reHandlerFunc  = regexp.MustCompile(`(?i)(?:func\s+\w*(?:Handle|handler|Controller|Ctrl)\w*|def\s+\w*(?:view|handler|controller)\w*|(?:app|router)\.\s*(?:get|post|put|delete|patch))`)
)

// sourceExtensions lists file extensions to scan.
var sourceExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs to skip during walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

// godFileThreshold is the line count above which a file may be flagged as a god object.
const godFileThreshold = 500

// godExportThreshold is the minimum number of exports for a large file to be flagged.
const godExportThreshold = 10

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/arch-lint", version).
		Capability("arch-lint", "Architecture risk and design lint for source code").
		Tool("scan", "Detect circular dependencies, god objects, security-critical code mixing, and missing abstraction layers", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	// Collect import information for circular dependency detection.
	importGraph := make(map[string][]string) // file -> imported modules

	var files []fileInfo

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !sourceExtensions[ext] {
			return nil
		}

		info, parseErr := parseFile(path, ext)
		if parseErr != nil {
			return nil
		}
		files = append(files, info)

		relPath, _ := filepath.Rel(workspaceRoot, path)
		if relPath == "" {
			relPath = path
		}
		for _, imp := range info.imports {
			importGraph[relPath] = append(importGraph[relPath], imp.module)
		}

		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// Analyze collected data.
	for _, fi := range files {
		// ARCH-001: Check for circular dependency indicators.
		checkCircularDeps(resp, fi, importGraph, workspaceRoot)

		// ARCH-002: Check for god objects.
		checkGodObject(resp, fi)

		// ARCH-003: Check for security-critical code without separation.
		checkSecurityMixing(resp, fi)

		// ARCH-004: Check for missing abstraction layer.
		checkMissingAbstraction(resp, fi)
	}

	return resp.Build(), nil
}

// importRef represents a detected import statement.
type importRef struct {
	module string
	line   int
}

// fileInfo holds parsed information about a source file.
type fileInfo struct {
	path      string
	ext       string
	lines     []string
	imports   []importRef
	exports   int
	lineCount int
}

// parseFile reads a file and extracts imports, exports, and line metadata.
func parseFile(filePath, ext string) (fileInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return fileInfo{}, err
	}
	defer f.Close()

	info := fileInfo{
		path: filePath,
		ext:  ext,
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		info.lines = append(info.lines, line)

		// Extract imports.
		switch ext {
		case ".go":
			if m := reGoImport.FindStringSubmatch(line); len(m) > 1 {
				info.imports = append(info.imports, importRef{module: m[1], line: lineNum})
			}
			if reGoExport.MatchString(line) {
				info.exports++
			}
		case ".py":
			if m := rePyImport.FindStringSubmatch(line); len(m) > 0 {
				mod := m[1]
				if mod == "" {
					mod = m[2]
				}
				if mod != "" {
					info.imports = append(info.imports, importRef{module: mod, line: lineNum})
				}
			}
			if rePyExport.MatchString(line) || rePyAllExport.MatchString(line) {
				info.exports++
			}
		case ".js", ".ts":
			if m := reJSImport.FindStringSubmatch(line); len(m) > 1 && m[1] != "" {
				info.imports = append(info.imports, importRef{module: m[1], line: lineNum})
			}
			if reJSExport.MatchString(line) {
				info.exports++
			}
		}
	}

	info.lineCount = lineNum
	return info, scanner.Err()
}

// checkCircularDeps detects mutual import patterns between files.
func checkCircularDeps(resp *sdk.ResponseBuilder, fi fileInfo, importGraph map[string][]string, workspaceRoot string) {
	relPath, _ := filepath.Rel(workspaceRoot, fi.path)
	if relPath == "" {
		relPath = fi.path
	}

	myDir := filepath.Dir(relPath)
	myPkg := filepath.Base(myDir)

	for _, imp := range fi.imports {
		// Check if any other file imports our package while we import theirs.
		impBase := filepath.Base(imp.module)
		for otherFile, otherImports := range importGraph {
			if otherFile == relPath {
				continue
			}
			otherDir := filepath.Dir(otherFile)
			otherPkg := filepath.Base(otherDir)

			// Mutual import: we import their package, they import ours.
			if impBase == otherPkg || strings.HasSuffix(imp.module, "/"+otherPkg) {
				for _, otherImp := range otherImports {
					otherImpBase := filepath.Base(otherImp)
					if otherImpBase == myPkg || strings.HasSuffix(otherImp, "/"+myPkg) {
						resp.Finding(
							"ARCH-001",
							sdk.SeverityMedium,
							sdk.ConfidenceHigh,
							fmt.Sprintf("Circular dependency risk: %s imports %s which imports back", relPath, imp.module),
						).
							At(fi.path, imp.line, imp.line).
							WithMetadata("imported_module", imp.module).
							WithMetadata("language", extToLanguage(fi.ext)).
							Done()
						return // Report once per file.
					}
				}
			}
		}
	}
}

// checkGodObject flags files that exceed the line threshold with many exports.
func checkGodObject(resp *sdk.ResponseBuilder, fi fileInfo) {
	if fi.lineCount > godFileThreshold && fi.exports >= godExportThreshold {
		resp.Finding(
			"ARCH-002",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			fmt.Sprintf("God object/file detected: %d lines with %d exports", fi.lineCount, fi.exports),
		).
			At(fi.path, 1, 1).
			WithMetadata("line_count", fmt.Sprintf("%d", fi.lineCount)).
			WithMetadata("export_count", fmt.Sprintf("%d", fi.exports)).
			WithMetadata("language", extToLanguage(fi.ext)).
			Done()
	}
}

// checkSecurityMixing detects crypto/auth logic mixed with business logic in the same file.
func checkSecurityMixing(resp *sdk.ResponseBuilder, fi fileInfo) {
	hasCrypto := false
	hasAuth := false
	hasBizLogic := false
	hasDBAccess := false
	hasHTTPRoutes := false

	var cryptoLine, authLine int

	for i, line := range fi.lines {
		switch fi.ext {
		case ".go":
			if reCryptoGo.MatchString(line) {
				hasCrypto = true
				if cryptoLine == 0 {
					cryptoLine = i + 1
				}
			}
			if reAuthGo.MatchString(line) {
				hasAuth = true
				if authLine == 0 {
					authLine = i + 1
				}
			}
		case ".py":
			if reCryptoPy.MatchString(line) {
				hasCrypto = true
				if cryptoLine == 0 {
					cryptoLine = i + 1
				}
			}
			if reAuthPy.MatchString(line) {
				hasAuth = true
				if authLine == 0 {
					authLine = i + 1
				}
			}
		case ".js", ".ts":
			if reCryptoJS.MatchString(line) {
				hasCrypto = true
				if cryptoLine == 0 {
					cryptoLine = i + 1
				}
			}
			if reAuthJS.MatchString(line) {
				hasAuth = true
				if authLine == 0 {
					authLine = i + 1
				}
			}
		}

		if reBizLogic.MatchString(line) {
			hasBizLogic = true
		}
		if reDBAccess.MatchString(line) {
			hasDBAccess = true
		}
		if reHTTPRoute.MatchString(line) {
			hasHTTPRoutes = true
		}
	}

	securityCritical := hasCrypto || hasAuth
	businessMixed := hasBizLogic || hasDBAccess || hasHTTPRoutes

	if securityCritical && businessMixed {
		reportLine := cryptoLine
		if reportLine == 0 {
			reportLine = authLine
		}
		detail := "crypto"
		if hasAuth {
			detail = "auth"
		}
		if hasCrypto && hasAuth {
			detail = "crypto/auth"
		}
		resp.Finding(
			"ARCH-003",
			sdk.SeverityHigh,
			sdk.ConfidenceHigh,
			fmt.Sprintf("Security-critical code (%s) mixed with business logic in same file", detail),
		).
			At(fi.path, reportLine, reportLine).
			WithMetadata("has_crypto", fmt.Sprintf("%t", hasCrypto)).
			WithMetadata("has_auth", fmt.Sprintf("%t", hasAuth)).
			WithMetadata("has_business_logic", fmt.Sprintf("%t", hasBizLogic)).
			WithMetadata("language", extToLanguage(fi.ext)).
			Done()
	}
}

// checkMissingAbstraction detects direct database calls in handler/controller files.
func checkMissingAbstraction(resp *sdk.ResponseBuilder, fi fileInfo) {
	isHandler := false

	for _, line := range fi.lines {
		if reHandlerFunc.MatchString(line) {
			isHandler = true
			break
		}
	}

	if !isHandler {
		return
	}

	for i, line := range fi.lines {
		if reSQLInHandler.MatchString(line) {
			resp.Finding(
				"ARCH-004",
				sdk.SeverityLow,
				sdk.ConfidenceMedium,
				fmt.Sprintf("Missing abstraction layer: direct database call in handler: %s", strings.TrimSpace(line)),
			).
				At(fi.path, i+1, i+1).
				WithMetadata("language", extToLanguage(fi.ext)).
				Done()
		}
	}
}

// extToLanguage maps file extensions to human-readable language names.
func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-arch-lint: %v\n", err)
		os.Exit(1)
	}
}
