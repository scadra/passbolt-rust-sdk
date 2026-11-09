// Command rename gives the bindings of uniffi-bindgen-go Go names, which its configuration cannot:
//
//   - initialisms in capitals: Id → ID, Url → URL, Json → JSON…, as golint and the standard
//     library write them (UserID, BaseURL, MetadataJSON);
//   - the plumbing unexported: FfiConverter…, FfiDestroyer…, RustBuffer…, which callers have no
//     use for, and AsyncPassboltClient, whose async methods the generator makes blocking: a
//     second PassboltClient;
//   - the PassboltClient methods that packaging/go replaces with option structs unexported, so
//     the package has one method of each name.
//
// It rewrites identifier tokens, never comments or strings, and leaves the selectors of the
// imported packages (C.RustBuffer, binary.Read…) alone. It refuses a renaming that would merge
// two names, a name that would clash with one already used, or a name in a //export comment
// (cgo would then miss it); a renaming it does not make breaks the build of packaging/go,
// never the behaviour.
//
//	go run packaging/go/rename/main.go passbolt_ffi.go
package main

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Initialisms, as golint lists them; the bindings use these.
var initialisms = map[string]string{
	"Id": "ID", "Ids": "IDs", "Url": "URL", "Urls": "URLs", "Uri": "URI", "Uris": "URIs",
	"Json": "JSON", "Api": "API", "Tls": "TLS", "Http": "HTTP",
}

// A capitalised word, ending before the next capital, a digit or the end of the name.
var word = regexp.MustCompile(`[A-Z][a-z]+`)

// The exported plumbing, by prefix.
var plumbing = []string{
	"FfiConverter", "FfiDestroyer", "FfiObject", "RustBuffer", "GoRustBuffer",
	"ExternalCRustBuffer", "BufReader", "BufWriter", "LowerIntoRustBuffer", "LiftFromRustBuffer",
	"CFromRustBuffer", "BufLifter", "BufLowerer", "NativeError", "PassboltClientInterface",
	"AsyncPassboltClient",
}

// The PassboltClient methods that packaging/go/options.go replaces.
var replaced = []string{
	"ListResources", "ListResourceViews", "ListFolders", "ListUsers",
	"UpdateGroup", "UpdateUser", "ShareResource", "ShareFolder",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rename <generated file>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "rename:", err)
		os.Exit(1)
	}
}

type ident struct {
	offset int
	name   string
}

func run(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	file := fset.AddFile(path, -1, len(src))
	var s scanner.Scanner
	var scanErr error
	s.Init(file, src, func(pos token.Position, msg string) { scanErr = fmt.Errorf("%s: %s", pos, msg) },
		scanner.ScanComments)

	// The identifiers, but those of the imports and the selectors of imported packages.
	imports := map[string]bool{"C": true}
	var idents []ident
	var comments []string
	var prev, prev2 token.Token
	var prevLit, alias string
	inImport := false
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT {
			comments = append(comments, lit)
			continue
		}
		if inImport {
			switch tok {
			case token.IMPORT, token.LPAREN, token.RPAREN, token.SEMICOLON:
				continue
			case token.IDENT:
				alias = lit
				continue
			case token.STRING:
				p, _ := strconv.Unquote(lit)
				if alias == "" {
					alias = p[strings.LastIndex(p, "/")+1:]
				}
				imports[alias] = true
				alias = ""
				continue
			}
			inImport = false
		}
		switch tok {
		case token.IMPORT:
			inImport = true
			continue
		case token.IDENT:
			if !(prev == token.PERIOD && prev2 == token.IDENT && imports[prevLit]) {
				idents = append(idents, ident{file.Offset(pos), lit})
			}
		}
		if prev == token.IDENT && tok != token.PERIOD {
			prevLit = ""
		}
		if tok == token.IDENT {
			prevLit = lit
		}
		prev2, prev = prev, tok
	}
	if scanErr != nil {
		return scanErr
	}

	names := map[string]bool{}
	for _, id := range idents {
		names[id.name] = true
	}
	mapping := map[string]string{}
	taken := map[string]string{}
	for name := range names {
		renamed := rename(name, names)
		if renamed == name {
			continue
		}
		if names[renamed] {
			return fmt.Errorf("%s → %s: the name is already used", name, renamed)
		}
		if other, ok := taken[renamed]; ok {
			return fmt.Errorf("%s and %s would both become %s", name, other, renamed)
		}
		for _, c := range comments {
			if strings.HasPrefix(c, "//export ") && strings.Contains(c, name) {
				return fmt.Errorf("%s is exported to C (%s)", name, c)
			}
		}
		mapping[name] = renamed
		taken[renamed] = name
	}
	for _, name := range replaced {
		if !names[name] {
			return fmt.Errorf("the bindings have no %s to replace", name)
		}
	}

	var out bytes.Buffer
	last := 0
	for _, id := range idents {
		if renamed, ok := mapping[id.name]; ok {
			out.Write(src[last:id.offset])
			out.WriteString(renamed)
			last = id.offset + len(id.name)
		}
	}
	out.Write(src[last:])
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		return err
	}
	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("rename: %d names in %s\n", len(keys), path)
	return nil
}

func rename(name string, names map[string]bool) string {
	for _, m := range replaced {
		if name == m {
			return lowerFirst(name)
		}
	}
	for _, p := range plumbing {
		if strings.HasPrefix(name, p) {
			if l := lowerFirst(name); !names[l] {
				return l
			}
			return "uniffi" + name
		}
	}
	return word.ReplaceAllStringFunc(name, func(w string) string {
		if i, ok := initialisms[w]; ok {
			return i
		}
		return w
	})
}

func lowerFirst(s string) string {
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}
