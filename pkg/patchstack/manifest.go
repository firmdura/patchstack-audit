package patchstack

import (
	"bytes"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// LoadManifest loads and validates a single version 1 YAML manifest. It rejects
// documents larger than 1 MiB, unknown or duplicate fields, YAML aliases and
// anchors, automatic type conversions, and additional documents.
//
// Loading checks path spelling without opening the declared inputs. It does not
// extract files, run tools, write an output directory or access the network.
// Audit also checks that input reads stay within the selected input directory.
// On failure, LoadManifest returns an empty Manifest and a RunError.
func LoadManifest(reader io.Reader) (Manifest, error) {
	invalid := func() (Manifest, error) {
		return Manifest{}, &RunError{Stage: StageManifest, Reason: ReasonInvalidManifest, Err: fmt.Errorf("expected one strict version 1 manifest")}
	}
	if reader == nil {
		return invalid()
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, &RunError{Stage: StageManifest, Reason: ReasonIO, Err: err}
	}
	if int64(len(data)) > MaxManifestBytes {
		return invalid()
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if decoder.Decode(&document) != nil || len(document.Content) != 1 {
		return invalid()
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return invalid()
	}
	root := document.Content[0]
	if err := checkMapping(root, []string{"schema_version", "source", "patch_dir", "patches"}, nil); err != nil {
		return invalid()
	}
	fields := mapping(root)
	version := fields["schema_version"]
	if version.Kind != yaml.ScalarNode || version.Tag != "!!int" || version.Value != "1" || version.Anchor != "" {
		return invalid()
	}
	if checkMapping(fields["source"], []string{"path", "sha256", "root_dir"}, nil) != nil {
		return invalid()
	}
	source := mapping(fields["source"])
	m := Manifest{SchemaVersion: SchemaVersion}
	if m.Source.Path, err = scalar(source["path"]); err != nil {
		return invalid()
	}
	if m.Source.SHA256, err = scalar(source["sha256"]); err != nil {
		return invalid()
	}
	if m.Source.RootDir, err = scalar(source["root_dir"]); err != nil {
		return invalid()
	}
	if m.PatchDir, err = scalar(fields["patch_dir"]); err != nil {
		return invalid()
	}
	patches := fields["patches"]
	if patches.Kind != yaml.SequenceNode || patches.Tag != "!!seq" || patches.Anchor != "" || len(patches.Content) > MaxPatches {
		return invalid()
	}
	m.Patches = make([]Patch, 0, len(patches.Content))
	for _, node := range patches.Content {
		if checkMapping(node, []string{"id", "file", "sha256", "upstream"}, []string{"cves"}) != nil {
			return invalid()
		}
		fields := mapping(node)
		var p Patch
		if p.ID, err = scalar(fields["id"]); err != nil {
			return invalid()
		}
		if p.File, err = scalar(fields["file"]); err != nil {
			return invalid()
		}
		if p.SHA256, err = scalar(fields["sha256"]); err != nil {
			return invalid()
		}
		if p.Upstream, err = scalar(fields["upstream"]); err != nil {
			return invalid()
		}
		if cves, ok := fields["cves"]; ok {
			if cves.Kind != yaml.SequenceNode || cves.Tag != "!!seq" || cves.Anchor != "" {
				return invalid()
			}
			p.CVEs = make([]string, 0, len(cves.Content))
			for _, node := range cves.Content {
				value, err := scalar(node)
				if err != nil {
					return invalid()
				}
				p.CVEs = append(p.CVEs, value)
			}
		}
		m.Patches = append(m.Patches, p)
	}
	if err = m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func scalar(node *yaml.Node) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Anchor != "" {
		return "", fmt.Errorf("expected string scalar")
	}
	return node.Value, nil
}

func mapping(node *yaml.Node) map[string]*yaml.Node {
	result := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		result[node.Content[i].Value] = node.Content[i+1]
	}
	return result
}

func checkMapping(node *yaml.Node, required, optional []string) error {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || node.Anchor != "" || len(node.Content)%2 != 0 {
		return fmt.Errorf("expected mapping")
	}
	allowed := make(map[string]bool)
	seen := make(map[string]bool)
	for _, name := range required {
		allowed[name] = true
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, err := scalar(node.Content[i])
		if err != nil || !allowed[key] || seen[key] {
			return fmt.Errorf("unknown or duplicate key")
		}
		seen[key] = true
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("missing field")
		}
	}
	return nil
}
