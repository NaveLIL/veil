package auth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type wsAuthV3AllowedCallsite struct {
	path      string
	enclosing string
}

// TestWSAuthV3ActivationIsConfinedToReviewedEndpoint is an executable
// activation boundary. WS auth v3 is live only on the dedicated /v3/events
// route: future callsites must fail this test until they receive an explicit
// protocol and downgrade review.
func TestWSAuthV3ActivationIsConfinedToReviewedEndpoint(t *testing.T) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate nonactivation test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	allowed := map[string]wsAuthV3AllowedCallsite{
		"HandleWebSocketV3": {
			path: "veil-server/cmd/gateway/main.go", enclosing: "main",
		},
		"CreateChallengeV3": {
			path: "veil-server/internal/gateway/ws_v3.go", enclosing: "runWSAuthV3",
		},
		"VerifyResponseV3": {
			path: "veil-server/internal/gateway/ws_v3.go", enclosing: "runWSAuthV3",
		},
		"AdmitWSAuthV3": {
			path: "veil-server/internal/auth/ws_v3_verifier.go", enclosing: "VerifyResponseV3",
		},
	}
	targets := make(map[string]struct{}, len(allowed))
	for name := range allowed {
		targets[name] = struct{}{}
	}

	var violations []string
	allowedCalls := make(map[string]int, len(allowed))
	walkErr := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".gradle", "build", "node_modules", "target", "vendor":
				if path != repositoryRoot {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		fileSet := token.NewFileSet()
		parsedFile, parseErr := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		relativePath, relErr := filepath.Rel(repositoryRoot, path)
		if relErr != nil {
			return relErr
		}
		relativePath = filepath.ToSlash(relativePath)

		for _, declaration := range parsedFile.Decls {
			enclosing := "<package>"
			if function, isFunction := declaration.(*ast.FuncDecl); isFunction {
				enclosing = function.Name.Name
			}
			for _, reference := range wsAuthV3TargetReferences(declaration, targets) {
				callsite, isAllowed := allowed[reference.name]
				if reference.directCall && isAllowed && relativePath == callsite.path &&
					enclosing == callsite.enclosing {
					allowedCalls[reference.name]++
					continue
				}
				position := fileSet.Position(reference.position)
				action := "references"
				if reference.directCall {
					action = "calls"
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: %s %s %s", relativePath, position.Line, enclosing, action, reference.name,
				))
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	for name := range allowed {
		if allowedCalls[name] != 1 {
			violations = append(violations, fmt.Sprintf(
				"reviewed %s call count = %d, want exactly 1", name, allowedCalls[name],
			))
		}
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("WebSocket auth v3 is activated outside its reviewed boundary:\n%s", strings.Join(violations, "\n"))
	}
}

type wsAuthV3TargetReference struct {
	name       string
	position   token.Pos
	directCall bool
}

// wsAuthV3TargetReferences treats taking a method value or method expression
// as an activation reference even when the eventual CallExpr uses an unrelated
// alias identifier. Direct target calls are returned only once.
func wsAuthV3TargetReferences(declaration ast.Decl, targets map[string]struct{}) []wsAuthV3TargetReference {
	directSelectors := make(map[token.Pos]struct{})
	var references []wsAuthV3TargetReference
	ast.Inspect(declaration, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		name := wsAuthV3CalledName(call.Fun)
		if _, targeted := targets[name]; !targeted {
			return true
		}
		if selector := wsAuthV3CalledSelector(call.Fun); selector != nil {
			directSelectors[selector.Pos()] = struct{}{}
		}
		references = append(references, wsAuthV3TargetReference{
			name: name, position: call.Pos(), directCall: true,
		})
		return true
	})
	ast.Inspect(declaration, func(node ast.Node) bool {
		selector, isSelector := node.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		if _, targeted := targets[selector.Sel.Name]; !targeted {
			return true
		}
		if _, isDirectCall := directSelectors[selector.Pos()]; isDirectCall {
			return true
		}
		references = append(references, wsAuthV3TargetReference{
			name: selector.Sel.Name, position: selector.Pos(), directCall: false,
		})
		return true
	})
	return references
}

func TestWSAuthV3NonactivationScannerDetectsMethodValueAndExpressionAliases(t *testing.T) {
	const source = `package fixture
func aliases(service *Service, store Store, ctx Context, input Input) {
	verify := service.VerifyResponseV3
	verify(ctx, "connection", input)
	verifyExpression := (*Service).VerifyResponseV3
	_ = verifyExpression
	admit := store.AdmitWSAuthV3
	_ = admit
}`
	fileSet := token.NewFileSet()
	parsedFile, err := parser.ParseFile(fileSet, "alias_fixture.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]struct{}{"VerifyResponseV3": {}, "AdmitWSAuthV3": {}}
	var references []wsAuthV3TargetReference
	for _, declaration := range parsedFile.Decls {
		references = append(references, wsAuthV3TargetReferences(declaration, targets)...)
	}
	counts := make(map[string]int)
	for _, reference := range references {
		if reference.directCall {
			t.Fatalf("alias fixture was misclassified as a direct call: %#v", reference)
		}
		counts[reference.name]++
	}
	if counts["VerifyResponseV3"] != 2 || counts["AdmitWSAuthV3"] != 1 {
		t.Fatalf("alias reference counts = %#v, want VerifyResponseV3=2 AdmitWSAuthV3=1", counts)
	}
}

func wsAuthV3CalledName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	case *ast.ParenExpr:
		return wsAuthV3CalledName(value.X)
	case *ast.IndexExpr:
		return wsAuthV3CalledName(value.X)
	case *ast.IndexListExpr:
		return wsAuthV3CalledName(value.X)
	default:
		return ""
	}
}

func wsAuthV3CalledSelector(expression ast.Expr) *ast.SelectorExpr {
	switch value := expression.(type) {
	case *ast.SelectorExpr:
		return value
	case *ast.ParenExpr:
		return wsAuthV3CalledSelector(value.X)
	case *ast.IndexExpr:
		return wsAuthV3CalledSelector(value.X)
	case *ast.IndexListExpr:
		return wsAuthV3CalledSelector(value.X)
	default:
		return nil
	}
}
