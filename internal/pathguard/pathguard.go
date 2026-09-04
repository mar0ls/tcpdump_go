// Package pathguard refuses output paths that would clobber the capture
// being read, including the files a rotating writer will create later.
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateOutputPaths prevents os.Create from truncating an input or another
// output, including aliases through symlinks and hard links.
// ValidateOutputPaths reports an error when an output path would overwrite
// the input capture.
func ValidateOutputPaths(input, rawOutput, csvOutput string, rotating bool) error {
	type namedPath struct {
		name string
		path string
	}
	paths := []namedPath{{name: "input", path: input}}
	if rawOutput != "" {
		paths = append(paths, namedPath{name: "raw output", path: rawOutput})
	}
	if csvOutput != "" {
		paths = append(paths, namedPath{name: "CSV output", path: csvOutput})
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			same, err := samePath(paths[i].path, paths[j].path)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("%s %q and %s %q refer to the same file", paths[i].name, paths[i].path, paths[j].name, paths[j].path)
			}
		}
	}
	if rotating && rawOutput != "" && rawOutput != "-" {
		for _, protected := range []namedPath{{name: "input", path: input}, {name: "CSV output", path: csvOutput}} {
			if protected.path == "" || protected.path == "-" {
				continue
			}
			collides, candidate, err := rotationCollides(rawOutput, protected.path)
			if err != nil {
				return err
			}
			if collides {
				return fmt.Errorf("rotated raw output %q would overwrite %s %q", candidate, protected.name, protected.path)
			}
		}
	}
	return nil
}

func samePath(first, second string) (bool, error) {
	if first == "" || second == "" || first == "-" || second == "-" {
		return false, nil
	}
	firstCanonical, err := canonicalPath(first)
	if err != nil {
		return false, err
	}
	secondCanonical, err := canonicalPath(second)
	if err != nil {
		return false, err
	}
	if firstCanonical == secondCanonical {
		return true, nil
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	if firstErr == nil && secondErr == nil {
		return os.SameFile(firstInfo, secondInfo), nil
	}
	if firstErr != nil && !errors.Is(firstErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", first, firstErr)
	}
	if secondErr != nil && !errors.Is(secondErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect path %q: %w", second, secondErr)
	}
	return false, nil
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolve symlinks for %q: %w", path, err)
	}
	parent := filepath.Dir(absolute)
	if resolvedParent, parentErr := filepath.EvalSymlinks(parent); parentErr == nil {
		return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
	}
	return filepath.Clean(absolute), nil
}

func rotationCollides(base, protected string) (bool, string, error) {
	baseCanonical, err := canonicalPath(base)
	if err != nil {
		return false, "", err
	}
	protectedCanonical, err := canonicalPath(protected)
	if err != nil {
		return false, "", err
	}
	if isRotationFilename(baseCanonical, protectedCanonical) {
		return true, protectedCanonical, nil
	}

	entries, err := os.ReadDir(filepath.Dir(baseCanonical))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("inspect rotation directory: %w", err)
	}
	for _, entry := range entries {
		candidate := filepath.Join(filepath.Dir(baseCanonical), entry.Name())
		if !isRotationFilename(baseCanonical, candidate) {
			continue
		}
		same, err := samePath(candidate, protectedCanonical)
		if err != nil {
			return false, "", err
		}
		if same {
			return true, candidate, nil
		}
	}
	return false, "", nil
}

func isRotationFilename(base, candidate string) bool {
	// Treat case-only path differences conservatively. On a case-insensitive
	// filesystem capture_001.PCAP and capture_001.pcap are the same target;
	// rejecting that name on a case-sensitive filesystem is safer than
	// allowing an input file to be truncated on another platform.
	if !strings.EqualFold(filepath.Clean(filepath.Dir(base)), filepath.Clean(filepath.Dir(candidate))) {
		return false
	}
	baseName := filepath.Base(base)
	candidateName := filepath.Base(candidate)
	extension := filepath.Ext(baseName)
	candidateExtension := filepath.Ext(candidateName)
	if !strings.EqualFold(candidateExtension, extension) {
		return false
	}
	stem := strings.TrimSuffix(baseName, extension)
	candidateStem := strings.TrimSuffix(candidateName, candidateExtension)
	prefix := stem + "_"
	if len(candidateStem) < len(prefix) || !strings.EqualFold(candidateStem[:len(prefix)], prefix) {
		return false
	}
	suffix := candidateStem[len(prefix):]
	if len(suffix) < 3 {
		return false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
