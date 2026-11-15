package contracts

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateRelativePath checks that a path is a nonempty UTF-8 relative path using
// slash separators, without control characters, backslashes, empty components,
// or . or .. components. It checks spelling only. Input readers must also reject
// symlinks using operations relative to open directories, so a pathname change
// between checking and opening cannot redirect a read.
func ValidateRelativePath(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return fmt.Errorf("expected nonempty UTF-8 slash path")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control character in path")
		}
	}
	if strings.HasPrefix(value, "/") || (len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':') {
		return fmt.Errorf("absolute path is forbidden")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("empty, dot or traversal path component")
		}
	}
	return nil
}

// ValidateBasename applies ValidateRelativePath and requires a single name with
// no slash separators.
func ValidateBasename(value string) error {
	if err := ValidateRelativePath(value); err != nil {
		return err
	}
	if strings.Contains(value, "/") {
		return fmt.Errorf("expected one basename")
	}
	return nil
}

// StripPatchPath checks a diff header path and removes its first component:
// a/src/main.c becomes src/main.c. Quotes and whitespace, including Unicode
// whitespace, are unsupported. /dev/null returns an empty path; the diff parser
// must allow that marker only for the missing side of an addition or deletion.
func StripPatchPath(value string) (string, error) {
	if value == "/dev/null" {
		return "", nil
	}
	if err := ValidateRelativePath(value); err != nil {
		return "", err
	}
	if strings.ContainsAny(value, "\"'") {
		return "", fmt.Errorf("quoted patch paths are unsupported")
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return "", fmt.Errorf("whitespace patch paths are unsupported")
		}
	}
	_, target, ok := strings.Cut(value, "/")
	if !ok {
		return "", fmt.Errorf("patch path has no strip component")
	}
	if err := ValidateRelativePath(target); err != nil {
		return "", err
	}
	return target, nil
}
