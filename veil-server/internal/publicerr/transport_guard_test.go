package publicerr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// TestTransportBoundariesDoNotRenderErrorMethods is a structural tripwire for
// the regression this package prevents. Public transport files must pass an
// error object to publicerr instead of rendering any Error() method themselves.
func TestTransportBoundariesDoNotRenderErrorMethods(t *testing.T) {
	t.Parallel()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	internal := filepath.Dir(filepath.Dir(here))
	files := []string{
		"auth/handler.go",
		"auth/device_handler.go",
		"chat/handler.go",
		"chat/device_directory.go",
		"gateway/hub.go",
		"gateway/runtime_roster.go",
		"gateway/sender_key_device_routing.go",
		"gateway/sender_key_receipt.go",
		"mls/handler.go",
		"push/handler.go",
		"servers/handler.go",
		"uploads/handler.go",
	}
	fset := token.NewFileSet()
	for _, relative := range files {
		path := filepath.Join(internal, filepath.FromSlash(relative))
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", relative, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "Error" && len(call.Args) == 0 {
				t.Errorf("%s:%d calls Error() inside a client transport boundary", relative, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}
}
