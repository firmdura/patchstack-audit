package contracts

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// Validate checks manifest values without opening the files they name. It applies
// equally to manifests loaded from YAML and values constructed or changed in Go.
// Audit repeats these checks before using a manifest.
func (m Manifest) Validate() error {
	bad := func(field string) error {
		return &RunError{Stage: StageManifest, Reason: ReasonInvalidManifest, Err: fmt.Errorf("invalid %s", field)}
	}
	if m.SchemaVersion != SchemaVersion {
		return bad("schema_version")
	}
	if ValidateRelativePath(m.Source.Path) != nil || !strings.HasSuffix(m.Source.Path, ".tar.gz") {
		return bad("source.path")
	}
	if !hashPattern.MatchString(m.Source.SHA256) {
		return bad("source.sha256")
	}
	if ValidateBasename(m.Source.RootDir) != nil {
		return bad("source.root_dir")
	}
	if ValidateRelativePath(m.PatchDir) != nil {
		return bad("patch_dir")
	}
	if len(m.Patches) > MaxPatches {
		return bad("patches count")
	}
	ids := make(map[string]int)
	files := make(map[string]int)
	hashes := make(map[string]int)
	record := func(seen map[string]int, index int, name, value string) error {
		if first, ok := seen[value]; ok {
			return bad(fmt.Sprintf("patches[%d].%s (duplicates patches[%d].%s)", index, name, first, name))
		}
		seen[value] = index
		return nil
	}
	for i, p := range m.Patches {
		field := fmt.Sprintf("patches[%d]", i)
		if strings.TrimSpace(p.ID) == "" || !utf8.ValidString(p.ID) {
			return bad(field + ".id")
		}
		if err := record(ids, i, "id", p.ID); err != nil {
			return err
		}
		if ValidateBasename(p.File) != nil {
			return bad(field + ".file")
		}
		if err := record(files, i, "file", p.File); err != nil {
			return err
		}
		if !hashPattern.MatchString(p.SHA256) {
			return bad(field + ".sha256")
		}
		if err := record(hashes, i, "sha256", p.SHA256); err != nil {
			return err
		}
		if !validProvenance(p.Upstream) {
			return bad(field + ".upstream")
		}
		for _, cve := range p.CVEs {
			if !cvePattern.MatchString(cve) {
				return bad(field + ".cves")
			}
		}
	}
	return nil
}

func validProvenance(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	if reason, ok := strings.CutPrefix(value, "local:"); ok {
		return strings.TrimSpace(reason) != ""
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	u, err := url.ParseRequestURI(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.Opaque == ""
}
