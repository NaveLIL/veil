package authmw

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type restAuthV2ConstructorDefinition struct {
	file     string
	function string
}

var restAuthV2CallableDefinitions = map[string]restAuthV2ConstructorDefinition{
	"NewRESTAuthV2Verifier": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go")), function: "NewRESTAuthV2Verifier",
	},
	"newRESTAuthV2VerifierWithClock": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go")), function: "newRESTAuthV2VerifierWithClock",
	},
	"NewRESTAuthV2HTTPBoundary": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_http.go")), function: "NewRESTAuthV2HTTPBoundary",
	},
	"NewRESTAuthVersionDispatcher": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_dispatch.go")), function: "NewRESTAuthVersionDispatcher",
	},
	"newRESTAuthVersionDispatcherWithClock": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_dispatch.go")), function: "newRESTAuthVersionDispatcherWithClock",
	},
}

var restAuthV2PrivateCallAllowlist = map[string]restAuthV2ConstructorDefinition{
	"newRESTAuthV2VerifierWithClock": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go")), function: "NewRESTAuthV2Verifier",
	},
	"newRESTAuthVersionDispatcherWithClock": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_dispatch.go")), function: "NewRESTAuthVersionDispatcher",
	},
}

var restAuthV2CompositeDefinitions = map[string]restAuthV2ConstructorDefinition{
	"RESTAuthV2Verifier": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go")), function: "newRESTAuthV2VerifierWithClock",
	},
	"RESTAuthV2HTTPBoundary": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_http.go")), function: "NewRESTAuthV2HTTPBoundary",
	},
	"RESTAuthVersionDispatcher": {
		file: filepath.Clean(filepath.Join("internal", "authmw", "rest_dispatch.go")), function: "newRESTAuthVersionDispatcherWithClock",
	},
}

var restAuthV2ReviewedContainerTypes = map[string]string{
	"restAuthV2Preflight": filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go")),
}

func restAuthV2ModuleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("could not locate veil-server go.mod")
		}
		directory = parent
	}
}

func TestRESTAuthV2HTTPStackHasNoLiveCallSite(t *testing.T) {
	root := restAuthV2ModuleRoot(t)
	fileSet := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if info.IsDir() {
			if relative == ".git" || relative == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		for _, violation := range restAuthV2NonactivationViolations(fileSet, relative, parsed) {
			t.Error(violation)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func restAuthV2NonactivationViolations(
	fileSet *token.FileSet,
	relative string,
	parsed *ast.File,
) []string {
	var violations []string
	allowedIdentifiers := make(map[token.Pos]struct{})
	allowedCompositeRanges := make(map[string][2]token.Pos)

	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if definition, guarded := restAuthV2CallableDefinitions[function.Name.Name]; guarded &&
			relative == definition.file && function.Name.Name == definition.function {
			allowedIdentifiers[function.Name.Pos()] = struct{}{}
		}
		for typeName, definition := range restAuthV2CompositeDefinitions {
			if relative == definition.file && function.Name.Name == definition.function {
				allowedCompositeRanges[typeName] = [2]token.Pos{function.Body.Pos(), function.Body.End()}
			}
		}
		for callable, definition := range restAuthV2PrivateCallAllowlist {
			if relative != definition.file || function.Name.Name != definition.function {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, callOK := node.(*ast.CallExpr)
				if !callOK {
					return true
				}
				identifier := restAuthV2CalledIdentifier(call.Fun)
				if identifier != nil && identifier.Name == callable {
					allowedIdentifiers[identifier.Pos()] = struct{}{}
				}
				return true
			})
		}
	}

	position := func(node ast.Node) string { return fileSet.Position(node.Pos()).String() }
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch candidate := node.(type) {
		case *ast.Ident:
			if _, guarded := restAuthV2CallableDefinitions[candidate.Name]; guarded {
				if _, allowed := allowedIdentifiers[candidate.Pos()]; !allowed {
					violations = append(violations, fmt.Sprintf("non-activated REST v2 callable %q referenced at %s", candidate.Name, position(candidate)))
				}
			}
		case *ast.CompositeLit:
			typeName := restAuthV2GuardedTypeWithin(candidate.Type)
			if typeName != "" {
				allowedRange, allowed := allowedCompositeRanges[typeName]
				directConstruction := restAuthV2TypeName(candidate.Type) == typeName
				if !directConstruction || !allowed || candidate.Pos() < allowedRange[0] || candidate.End() > allowedRange[1] {
					violations = append(violations, fmt.Sprintf("%s composite literal bypasses its constructor at %s", typeName, position(candidate)))
				}
			}
		case *ast.CallExpr:
			if identifier := restAuthV2CalledIdentifier(candidate.Fun); identifier != nil &&
				(identifier.Name == "new" || identifier.Name == "make") && len(candidate.Args) >= 1 {
				if typeName := restAuthV2GuardedTypeWithin(candidate.Args[0]); typeName != "" {
					violations = append(violations, fmt.Sprintf("%s(...%s...) bypasses its constructor at %s", identifier.Name, typeName, position(candidate)))
				}
			} else if typeName := restAuthV2GuardedTypeWithin(candidate.Fun); typeName != "" {
				violations = append(violations, fmt.Sprintf("conversion to %s bypasses its constructor at %s", typeName, position(candidate)))
			}
		case *ast.TypeSpec:
			if definition, guarded := restAuthV2CompositeDefinitions[candidate.Name.Name]; guarded && relative == definition.file {
				break
			}
			if allowedFile, allowed := restAuthV2ReviewedContainerTypes[candidate.Name.Name]; allowed && relative == allowedFile {
				break
			}
			if typeName := restAuthV2GuardedTypeWithin(candidate.Type); typeName != "" {
				violations = append(violations, fmt.Sprintf("type %s aliases or redefines guarded %s at %s", candidate.Name.Name, typeName, position(candidate)))
			}
			if typeName := restAuthV2GuardedTypeWithinFields(candidate.TypeParams); typeName != "" {
				violations = append(violations, fmt.Sprintf("type %s has guarded type parameter %s at %s", candidate.Name.Name, typeName, position(candidate)))
			}
		case *ast.ValueSpec:
			if typeName := restAuthV2GuardedTypeWithin(candidate.Type); typeName != "" {
				violations = append(violations, fmt.Sprintf("zero-value declaration of %s bypasses its constructor at %s", typeName, position(candidate)))
			}
		case *ast.FuncDecl:
			reviewedConstructor := restAuthV2ReviewedConstructorFunction(relative, candidate.Name.Name)
			if typeName := restAuthV2GuardedTypeWithinFields(candidate.Type.Params); typeName != "" && !reviewedConstructor {
				violations = append(violations, fmt.Sprintf("function parameter containing %s enables an unconstructed zero value at %s", typeName, position(candidate)))
			}
			if typeName := restAuthV2GuardedTypeWithinFields(candidate.Type.Results); typeName != "" && !reviewedConstructor {
				violations = append(violations, fmt.Sprintf("function result containing %s bypasses its constructor at %s", typeName, position(candidate)))
			}
		case *ast.FuncLit:
			if typeName := restAuthV2GuardedTypeWithinFields(candidate.Type.Params); typeName != "" {
				violations = append(violations, fmt.Sprintf("function literal parameter containing %s enables an unconstructed zero value at %s", typeName, position(candidate)))
			}
			if typeName := restAuthV2GuardedTypeWithinFields(candidate.Type.Results); typeName != "" {
				violations = append(violations, fmt.Sprintf("function literal result containing %s bypasses its constructor at %s", typeName, position(candidate)))
			}
		case *ast.TypeAssertExpr:
			if typeName := restAuthV2GuardedTypeWithin(candidate.Type); typeName != "" {
				violations = append(violations, fmt.Sprintf("type assertion to %s can produce an unconstructed zero value at %s", typeName, position(candidate)))
			}
		case *ast.IndexExpr:
			if typeName := restAuthV2GuardedTypeWithin(candidate.Index); typeName != "" {
				violations = append(violations, fmt.Sprintf("generic instantiation with %s bypasses its constructor at %s", typeName, position(candidate)))
			}
		case *ast.IndexListExpr:
			for _, index := range candidate.Indices {
				if typeName := restAuthV2GuardedTypeWithin(index); typeName != "" {
					violations = append(violations, fmt.Sprintf("generic instantiation with %s bypasses its constructor at %s", typeName, position(candidate)))
					break
				}
			}
		}
		return true
	})
	return violations
}

func TestRESTAuthV2NonactivationScannerRejectsAliasesAndConstructorBypasses(t *testing.T) {
	for name, source := range map[string]string{
		"public constructor alias": `package sample
import "example/authmw"
var build = authmw.NewRESTAuthV2Verifier`,
		"private constructor alias": `package authmw
var build = newRESTAuthV2VerifierWithClock`,
		"selector call": `package sample
import "example/authmw"
func f() { authmw.NewRESTAuthV2HTTPBoundary(nil, nil) }`,
		"new guarded type": `package sample
import "example/authmw"
var value = new(authmw.RESTAuthV2Verifier)`,
		"type alias": `package sample
import "example/authmw"
type Alias = authmw.RESTAuthV2HTTPBoundary`,
		"defined alias": `package authmw
type Alias RESTAuthVersionDispatcher`,
		"composite literal": `package sample
import "example/authmw"
var value = authmw.RESTAuthVersionDispatcher{}`,
		"type conversion": `package authmw
func f(value RESTAuthV2Verifier) { _ = RESTAuthV2Verifier(value) }`,
		"zero value": `package sample
import "example/authmw"
var value authmw.RESTAuthV2HTTPBoundary`,
		"array zero value": `package authmw
var pool [1]RESTAuthV2Verifier`,
		"slice composite zero value": `package authmw
var pool = []RESTAuthV2HTTPBoundary{{}}`,
		"map value": `package authmw
var pool map[string]RESTAuthVersionDispatcher`,
		"make slice zero value": `package authmw
var pool = make([]RESTAuthVersionDispatcher, 1)`,
		"embedded anonymous struct": `package authmw
var pool struct { item RESTAuthV2HTTPBoundary }`,
		"container alias": `package authmw
type Pool [1]RESTAuthV2Verifier`,
		"named function result": `package authmw
func zero() (value RESTAuthV2Verifier) { return }`,
		"named function literal result": `package authmw
var zero = func() (value RESTAuthV2HTTPBoundary) { return }`,
		"unnamed container function result": `package authmw
func empty() map[string]RESTAuthV2Verifier { return nil }
var activated = empty()["missing"]`,
		"nil map function parameter": `package authmw
func activate(pool map[string]RESTAuthVersionDispatcher) { _ = pool["missing"].RequireSigned }
func run() { activate(nil) }`,
		"comma ok type assertion": `package authmw
var opaque any
var activated, _ = opaque.(RESTAuthV2Verifier)`,
		"generic type argument": `package authmw
var value = build[RESTAuthVersionDispatcher]()`,
		"generic function value alias": `package authmw
func zero[T any]() (value T) { return }
var build = zero[RESTAuthV2Verifier]
var activated = build()`,
	} {
		t.Run(name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, "synthetic.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if violations := restAuthV2NonactivationViolations(fileSet, filepath.Clean(filepath.Join("cmd", "synthetic.go")), parsed); len(violations) == 0 {
				t.Fatal("synthetic activation bypass was not detected")
			}
		})
	}
}

func TestRESTAuthV2NonactivationScannerAllowsReviewedImplementationContainer(t *testing.T) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "synthetic.go", `package authmw
type restAuthV2Preflight struct { verifier *RESTAuthV2Verifier }`, 0)
	if err != nil {
		t.Fatal(err)
	}
	relative := filepath.Clean(filepath.Join("internal", "authmw", "rest_v2_verifier.go"))
	if violations := restAuthV2NonactivationViolations(fileSet, relative, parsed); len(violations) != 0 {
		t.Fatalf("reviewed implementation container rejected: %v", violations)
	}
}

func restAuthV2CalledIdentifier(expression ast.Expr) *ast.Ident {
	switch value := expression.(type) {
	case *ast.Ident:
		return value
	case *ast.SelectorExpr:
		return value.Sel
	case *ast.ParenExpr:
		return restAuthV2CalledIdentifier(value.X)
	default:
		return nil
	}
}

func restAuthV2TypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	case *ast.StarExpr:
		return restAuthV2TypeName(value.X)
	case *ast.ParenExpr:
		return restAuthV2TypeName(value.X)
	default:
		return ""
	}
}

func restAuthV2GuardedTypeWithin(expression ast.Expr) string {
	if expression == nil {
		return ""
	}
	switch value := expression.(type) {
	case *ast.Ident:
		if restAuthV2GuardedType(value.Name) {
			return value.Name
		}
	case *ast.SelectorExpr:
		if restAuthV2GuardedType(value.Sel.Name) {
			return value.Sel.Name
		}
	case *ast.StarExpr:
		return restAuthV2GuardedTypeWithin(value.X)
	case *ast.ParenExpr:
		return restAuthV2GuardedTypeWithin(value.X)
	case *ast.Ellipsis:
		return restAuthV2GuardedTypeWithin(value.Elt)
	case *ast.ArrayType:
		return restAuthV2GuardedTypeWithin(value.Elt)
	case *ast.MapType:
		if typeName := restAuthV2GuardedTypeWithin(value.Key); typeName != "" {
			return typeName
		}
		return restAuthV2GuardedTypeWithin(value.Value)
	case *ast.ChanType:
		return restAuthV2GuardedTypeWithin(value.Value)
	case *ast.StructType:
		return restAuthV2GuardedTypeWithinFields(value.Fields)
	case *ast.InterfaceType:
		return restAuthV2GuardedTypeWithinFields(value.Methods)
	case *ast.FuncType:
		if typeName := restAuthV2GuardedTypeWithinFields(value.TypeParams); typeName != "" {
			return typeName
		}
		if typeName := restAuthV2GuardedTypeWithinFields(value.Params); typeName != "" {
			return typeName
		}
		return restAuthV2GuardedTypeWithinFields(value.Results)
	case *ast.IndexExpr:
		if typeName := restAuthV2GuardedTypeWithin(value.X); typeName != "" {
			return typeName
		}
		return restAuthV2GuardedTypeWithin(value.Index)
	case *ast.IndexListExpr:
		if typeName := restAuthV2GuardedTypeWithin(value.X); typeName != "" {
			return typeName
		}
		for _, index := range value.Indices {
			if typeName := restAuthV2GuardedTypeWithin(index); typeName != "" {
				return typeName
			}
		}
	}
	return ""
}

func restAuthV2GuardedTypeWithinFields(fields *ast.FieldList) string {
	if fields == nil {
		return ""
	}
	for _, field := range fields.List {
		if typeName := restAuthV2GuardedTypeWithin(field.Type); typeName != "" {
			return typeName
		}
	}
	return ""
}

func restAuthV2ReviewedConstructorFunction(relative, name string) bool {
	definition, ok := restAuthV2CallableDefinitions[name]
	return ok && relative == definition.file && name == definition.function
}

func restAuthV2GuardedType(typeName string) bool {
	_, guarded := restAuthV2CompositeDefinitions[typeName]
	return guarded
}
