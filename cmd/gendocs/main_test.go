package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadGoMod(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module example.test/tool\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	module, err := readGoMod(directory, "module")
	if err != nil || module != "example.test/tool" {
		t.Fatalf("module = %q, %v", module, err)
	}
	if _, err := readGoMod(directory, "missing"); err == nil {
		t.Fatal("missing directive unexpectedly succeeded")
	}
}

func TestAtomicWriteReplacesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "documentation.md")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("new documentation\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new documentation\n" {
		t.Fatalf("document = %q", data)
	}
}

func TestSourceMetricsSkipsHiddenDirectories(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte("package main\n// comment\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(directory, ".cache")
	if err := os.Mkdir(hidden, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hidden, "ignored.go"), []byte("package ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metrics, err := sourceMetrics(directory)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.Files != 1 || metrics.Code != 2 || metrics.Comments != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestRunCommandIncludesFailureOutput(t *testing.T) {
	_, err := runCommand(t.TempDir(), "go", "definitely-not-a-command")
	if err == nil || !strings.Contains(err.Error(), "definitely-not-a-command") {
		t.Fatalf("error = %v", err)
	}
}

// Every build-tagged file must reach the table; a missed one is invisible in
// the docs.
func TestPlatformFilesAreDiscoveredNotHardcoded(t *testing.T) {
	root, err := findModRoot()
	if err != nil {
		t.Skipf("not inside the module: %v", err)
	}
	found, err := platformFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool, len(found))
	for _, entry := range found {
		listed[entry.File] = true
		if entry.Tag == "" || entry.Tag == "—" {
			t.Errorf("%s has no build tag in the table", entry.File)
		}
	}

	// Independently walk for //go:build files and require the same set.
	expected, err := findBuildTaggedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Fatal("no build-tagged sources found at all")
	}
	for _, relative := range expected {
		name := filepath.Base(relative)
		if !listed[name] {
			t.Errorf("%s carries a build tag but is missing from the documentation table", relative)
		}
	}
	if len(found) != len(expected) {
		t.Errorf("table has %d rows, discovery found %d files", len(found), len(expected))
	}
}

// Package documentation embeds build-tagged declarations, so an unpinned GOOS
// would make the generated file depend on the developer's machine and CI's
// "regenerate and diff" check could never pass.
func TestPackageDocsArePinnedToOneGOOS(t *testing.T) {
	root, err := findModRoot()
	if err != nil {
		t.Skipf("not inside the module: %v", err)
	}
	docs, err := subpackageDocs(root)
	if err != nil {
		t.Fatal(err)
	}
	var capture string
	for _, entry := range docs {
		if entry.Name == "capture" {
			capture = entry.Doc
		}
	}
	if capture == "" {
		t.Fatal("no documentation for the capture package")
	}
	// The Linux implementation restores offloads; the fallback only errors.
	if !strings.Contains(capture, "idempotent restoration closure") {
		t.Errorf("capture docs were not rendered for %s:\n%s", docsGOOS, capture)
	}
}
