package patchstack

import (
	"bytes"
	"errors"
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
		return Manifest{}, err
	}
	fields := mapping(root)
	version := fields["schema_version"]
	if version.Kind != yaml.ScalarNode || version.Tag != "!!int" || version.Value != "1" || version.Anchor != "" {
		return invalid()
	}
	if err := checkMapping(fields["source"], []string{"path", "sha256", "root_dir"}, nil); err != nil {
		return Manifest{}, err
	}
	source := mapping(fields["source"])
	m := Manifest{SchemaVersion: SchemaVersion}
	if m.Source.Path, err = stringField(source["path"], "source.path"); err != nil {
		return Manifest{}, err
	}
	if m.Source.SHA256, err = stringField(source["sha256"], "source.sha256"); err != nil {
		return Manifest{}, err
	}
	if m.Source.RootDir, err = stringField(source["root_dir"], "source.root_dir"); err != nil {
		return Manifest{}, err
	}
	if m.PatchDir, err = stringField(fields["patch_dir"], "patch_dir"); err != nil {
		return Manifest{}, err
	}
	patches := fields["patches"]
	if patches.Kind != yaml.SequenceNode || patches.Tag != "!!seq" || patches.Anchor != "" || len(patches.Content) > MaxPatches {
		return invalid()
	}
	m.Patches = make([]Patch, 0, len(patches.Content))
	for i, node := range patches.Content {
		if err := checkMapping(node, []string{"id", "file", "sha256", "upstream"}, []string{"cves"}); err != nil {
			return Manifest{}, err
		}
		fields := mapping(node)
		path := fmt.Sprintf("patches[%d]", i)
		var p Patch
		if p.ID, err = stringField(fields["id"], path+".id"); err != nil {
			return Manifest{}, err
		}
		if p.File, err = stringField(fields["file"], path+".file"); err != nil {
			return Manifest{}, err
		}
		if p.SHA256, err = stringField(fields["sha256"], path+".sha256"); err != nil {
			return Manifest{}, err
		}
		if p.Upstream, err = stringField(fields["upstream"], path+".upstream"); err != nil {
			return Manifest{}, err
		}
		if cves, ok := fields["cves"]; ok {
			if cves.Kind != yaml.SequenceNode || cves.Tag != "!!seq" || cves.Anchor != "" {
				return invalid()
			}
			p.CVEs = make([]string, 0, len(cves.Content))
			for j, node := range cves.Content {
				value, err := stringField(node, fmt.Sprintf("%s.cves[%d]", path, j))
				if err != nil {
					return Manifest{}, err
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

func isString(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Anchor == ""
}

func stringField(node *yaml.Node, path string) (string, error) {
	if !isString(node) {
		return "", invalidYAML(node, path+" must be an unanchored YAML string")
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

func invalidYAML(at *yaml.Node, message string) error {
	if at != nil {
		message = fmt.Sprintf("line %d, column %d: %s", at.Line, at.Column, message)
	}
	return &RunError{Stage: StageManifest, Reason: ReasonInvalidManifest, Err: errors.New(message)}
}

func checkMapping(node *yaml.Node, required, optional []string) error {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || node.Anchor != "" || len(node.Content)%2 != 0 {
		return invalidYAML(node, "expected an unanchored mapping")
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
		at := node.Content[i]
		if !isString(at) {
			return invalidYAML(at, "expected an unanchored string field name")
		}
		key := at.Value
		if !allowed[key] {
			return invalidYAML(at, "unknown field")
		}
		if seen[key] {
			return invalidYAML(at, "duplicate field "+key)
		}
		seen[key] = true
	}
	for _, name := range required {
		if !seen[name] {
			return invalidYAML(node, "missing required field "+name)
		}
	}
	return nil
}
