// Generates docs/documentation.md from docs/documentation.tmpl.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

func main() {
	root := findModRoot()
	out := filepath.Join(root, "docs", "documentation.md")
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	data := collect(root)
	tmplPath := filepath.Join(root, "docs", "documentation.tmpl")
	tmplBytes, err := os.ReadFile(tmplPath) //#nosec G304 -- fixed path in repo
	if err != nil {
		fatalf("read template: %v", err)
	}
	t, err := template.New("doc").Parse(string(tmplBytes))
	if err != nil {
		fatalf("parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		fatalf("execute template: %v", err)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil { //#nosec G306,G703 -- out is derived from repo path or CLI arg
		fatalf("write %s: %v", out, err)
	}
	fmt.Printf("wrote %s (%d lines)\n", out, bytes.Count(buf.Bytes(), []byte("\n")))
}

type docData struct {
	Module        string
	GoVersion     string
	GitRev        string
	Flags         string
	Packages      []pkgDoc
	PlatformFiles []platformFile
	Deps          string
	Metrics       codeMetrics
}

type pkgDoc struct {
	Name string
	Doc  string
}

type platformFile struct {
	File string
	Tag  string
	Desc string
}

type codeMetrics struct {
	Files    int
	Total    int
	Code     int
	Comments int
}

func collect(root string) docData {
	return docData{
		Module:        readGoMod(root, "module"),
		GoVersion:     readGoMod(root, "go"),
		GitRev:        run(root, "git", "rev-parse", "--short", "HEAD"),
		Flags:         cliFlags(root),
		Packages:      subpackageDocs(root),
		PlatformFiles: platformFiles(root),
		Deps:          dependencies(root),
		Metrics:       metrics(root),
	}
}

func cliFlags(root string) string {
	binary, err := os.MkdirTemp("", "gendocs_bin_")
	if err != nil {
		return ""
	}
	defer func() { _ = os.RemoveAll(binary) }()
	bin := filepath.Join(binary, "tcpdump_go")
	if out, err := exec.Command("go", "build", "-o", bin, root).CombinedOutput(); err != nil { //#nosec G204
		return strings.TrimSpace(string(out))
	}
	cmd := exec.Command(bin, "-h") //#nosec G204
	cmd.Dir = root
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

func subpackageDocs(root string) []pkgDoc {
	entries, _ := os.ReadDir(root)
	var result []pkgDoc
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "cmd" || e.Name() == "docs" || e.Name() == "testdata" {
			continue
		}
		goFiles, _ := filepath.Glob(filepath.Join(root, e.Name(), "*.go"))
		if len(goFiles) == 0 {
			continue
		}
		doc := run(root, "go", "doc", "-all", "./"+e.Name())
		if doc != "" {
			result = append(result, pkgDoc{Name: e.Name(), Doc: doc})
		}
	}
	return result
}

func platformFiles(root string) []platformFile {
	candidates := []string{
		"capture/signals_unix.go",
		"capture/signals_windows.go",
		"capture/offload_linux.go",
		"capture/offload_other.go",
	}
	var result []platformFile
	for _, rel := range candidates {
		path := filepath.Join(root, rel)
		data, err := os.ReadFile(path) //#nosec G304 -- fixed paths in repo
		if err != nil {
			continue
		}
		tag, desc := "", ""
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "//go:build ") && tag == "" {
				tag = strings.TrimPrefix(line, "//go:build ")
			}
			if strings.HasPrefix(line, "// ") && desc == "" && !strings.Contains(line, "go:build") && !strings.Contains(line, "Package") {
				desc = strings.TrimPrefix(line, "// ")
			}
		}
		if tag == "" {
			tag = "—"
		}
		if desc == "" {
			desc = "—"
		}
		result = append(result, platformFile{File: filepath.Base(path), Tag: tag, Desc: desc})
	}
	return result
}

func dependencies(root string) string {
	module := readGoMod(root, "module")
	out := run(root, "go", "list", "-m", "all")
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l != "" && !strings.HasPrefix(l, module) {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

func metrics(root string) codeMetrics {
	var m codeMetrics
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path) //#nosec G304,G122 -- walking own source tree
		if err != nil {
			return nil
		}
		m.Files++
		for _, line := range strings.Split(string(data), "\n") {
			m.Total++
			stripped := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(stripped, "//"):
				m.Comments++
			case stripped != "":
				m.Code++
			}
		}
		return nil
	})
	if err != nil {
		return m
	}
	return m
}

func readGoMod(root, key string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod")) //#nosec G304 -- fixed path
	if err != nil {
		return "?"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+" ") {
			return strings.Fields(line)[1]
		}
	}
	return "?"
}

func run(dir string, name string, args ...string) string {
	cmd := exec.Command(name, args...) //#nosec G204
	cmd.Dir = dir
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func findModRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// fallback: GOPATH
	return build.Default.GOPATH
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gendocs: "+format+"\n", args...)
	os.Exit(1)
}
