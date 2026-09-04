// Command gendocs regenerates docs/documentation.md from source and help text.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

func main() {
	if err := execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "gendocs: %v\n", err)
		os.Exit(1)
	}
}

func execute() error {
	root, err := findModRoot()
	if err != nil {
		return err
	}
	outputPath := filepath.Join(root, "docs", "documentation.md")
	if len(os.Args) > 1 {
		outputPath = os.Args[1]
	}

	data, err := collect(root)
	if err != nil {
		return err
	}
	templatePath := filepath.Join(root, "docs", "documentation.tmpl")
	templateBytes, err := os.ReadFile(templatePath) //nolint:gosec // fixed repository path
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	documentTemplate, err := template.New("documentation").Parse(string(templateBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	var document bytes.Buffer
	if err := documentTemplate.Execute(&document, data); err != nil {
		return fmt.Errorf("render documentation: %w", err)
	}
	if err := atomicWrite(outputPath, document.Bytes()); err != nil {
		return err
	}
	_, err = fmt.Printf("wrote %s (%d lines)\n", outputPath, bytes.Count(document.Bytes(), []byte("\n")))
	return err
}

type docData struct {
	Module        string
	GoVersion     string
	Toolchain     string
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

func collect(root string) (docData, error) {
	module, err := readGoMod(root, "module")
	if err != nil {
		return docData{}, err
	}
	goVersion, err := readGoMod(root, "go")
	if err != nil {
		return docData{}, err
	}
	toolchain, err := readGoMod(root, "toolchain")
	if err != nil {
		return docData{}, err
	}
	flags, err := cliFlags(root)
	if err != nil {
		return docData{}, err
	}
	packages, err := subpackageDocs(root)
	if err != nil {
		return docData{}, err
	}
	platforms, err := platformFiles(root)
	if err != nil {
		return docData{}, err
	}
	deps, err := dependencies(root, module)
	if err != nil {
		return docData{}, err
	}
	metrics, err := sourceMetrics(root)
	if err != nil {
		return docData{}, err
	}
	return docData{
		Module:        module,
		GoVersion:     goVersion,
		Toolchain:     toolchain,
		Flags:         flags,
		Packages:      packages,
		PlatformFiles: platforms,
		Deps:          deps,
		Metrics:       metrics,
	}, nil
}

func cliFlags(root string) (result string, retErr error) {
	directory, err := os.MkdirTemp("", "gendocs-bin-")
	if err != nil {
		return "", fmt.Errorf("create build directory: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, os.RemoveAll(directory))
	}()
	binary := filepath.Join(directory, "tcpdump_go")
	if _, err := runCommand(root, "go", "build", "-o", binary, "."); err != nil {
		return "", err
	}
	output, err := runCommand(root, binary, "-h")
	if err != nil {
		return "", err
	}
	return output, nil
}

func subpackageDocs(root string) ([]pkgDoc, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("list repository: %w", err)
	}
	var result []pkgDoc
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == "cmd" || entry.Name() == "docs" || entry.Name() == "testdata" {
			continue
		}
		goFiles, err := filepath.Glob(filepath.Join(root, entry.Name(), "*.go"))
		if err != nil {
			return nil, fmt.Errorf("find Go files in %s: %w", entry.Name(), err)
		}
		if len(goFiles) == 0 {
			continue
		}
		// Pinned GOOS: package docs contain build-tagged declarations, so the
		// output would otherwise depend on the machine running the generator
		// and the committed file could never match CI.
		documentation, err := runCommandForOS(root, docsGOOS, "go", "doc", "-all", "./"+entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, pkgDoc{Name: entry.Name(), Doc: documentation})
	}
	return result, nil
}

// platformFiles discovers every build-tagged source rather than listing them.
// A hardcoded list silently goes stale the moment a platform file is added.
func platformFiles(root string) ([]platformFile, error) {
	candidates, err := findBuildTaggedFiles(root)
	if err != nil {
		return nil, err
	}
	result := make([]platformFile, 0, len(candidates))
	for _, relative := range candidates {
		path := filepath.Join(root, relative)
		data, err := os.ReadFile(path) //nolint:gosec // path was discovered inside the repository
		if err != nil {
			return nil, fmt.Errorf("read platform source %s: %w", relative, err)
		}
		tag, description := "", ""
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "//go:build ") && tag == "" {
				tag = strings.TrimPrefix(line, "//go:build ")
			}
			if strings.HasPrefix(line, "// ") && description == "" && !strings.Contains(line, "go:build") && !strings.Contains(line, "Package") {
				description = strings.TrimPrefix(line, "// ")
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan platform source %s: %w", relative, err)
		}
		if tag == "" {
			tag = "—"
		}
		if description == "" {
			description = "—"
		}
		result = append(result, platformFile{File: filepath.Base(path), Tag: tag, Desc: description})
	}
	return result, nil
}

// findBuildTaggedFiles returns the repository-relative paths of non-test Go
// files carrying a //go:build constraint, sorted for a stable document.
func findBuildTaggedFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // path is discovered inside the repository
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(data, []byte("//go:build ")) {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find build-tagged sources: %w", err)
	}
	sort.Strings(found)
	return found, nil
}

func dependencies(root, module string) (string, error) {
	output, err := runCommand(root, "go", "list", "-m", "all")
	if err != nil {
		return "", err
	}
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line != "" && !strings.HasPrefix(line, module+" ") && line != module {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func sourceMetrics(root string) (codeMetrics, error) {
	var metrics codeMetrics
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // path is discovered inside the repository
		if err != nil {
			return err
		}
		metrics.Files++
		for _, line := range strings.Split(string(data), "\n") {
			metrics.Total++
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "//"):
				metrics.Comments++
			case trimmed != "":
				metrics.Code++
			}
		}
		return nil
	})
	if err != nil {
		return codeMetrics{}, fmt.Errorf("measure source tree: %w", err)
	}
	return metrics, nil
}

func readGoMod(root, key string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // fixed repository path
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+" ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("go.mod has no %q directive", key)
}

// runCommand runs a build-time helper. The executable is resolved to an
// absolute path first and the process is built from that path directly, so no
// name is ever handed to a lookup that could pick up something else.
// docsGOOS is the platform the package documentation is rendered for. Linux is
// the project's primary target and what CI runs.
const docsGOOS = "linux"

func runCommand(directory, name string, args ...string) (string, error) {
	return runCommandForOS(directory, "", name, args...)
}

// runCommandForOS runs a helper with GOOS pinned when goos is non-empty.
func runCommandForOS(directory, goos, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("find %s: %w", name, err)
	}
	// #nosec G204 -- path is resolved with exec.LookPath and is then used directly,
	// so the command is not selected from an untrusted PATH lookup.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	command := exec.Command(name, args...)
	command.Path = path
	command.Dir = directory
	if goos != "" {
		command.Env = append(os.Environ(), "GOOS="+goos)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func findModRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect %s: %w", directory, err)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("could not find a parent directory containing go.mod")
		}
		directory = parent
	}
}

func atomicWrite(path string, data []byte) (retErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".documentation.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary documentation: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	renamed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, temporary.Close())
		}
		if !renamed {
			//nolint:gosec // temporaryPath comes from os.CreateTemp in this function
			if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, err)
			}
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set documentation permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write documentation: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close documentation: %w", err)
	}
	closed = true
	//nolint:gosec // both paths are chosen by this generator, not by input
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish documentation: %w", err)
	}
	renamed = true
	return nil
}
