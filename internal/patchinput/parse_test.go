package patchinput

import (
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/patchstack-audit/internal/contracts"
)

const modifyPatch = "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n"
const addPatch = "--- /dev/null\n+++ b/added\n@@ -0,0 +1,2 @@\n+one\n+two\n"
const deletePatch = "--- a/deleted\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n"

func TestParseErrorLocation(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"second file index", modifyPatch + "diff --git a/file b/file\nindex unfinished\n", "line 7: unsupported Git index"},
		{"new header", "--- a/file\n+++ b/file\tnot a date\n", "line 2: unsupported header timestamp"},
		{"second hunk", modifyPatch + "@@ -two +2 @@\n", "line 6: malformed unified hunk header"},
		{"body", modifyPatch + "@@ -2 +2 @@\n-old\nunfinished edit\n", "line 8: unsupported unified hunk line"},
		{"truncated", strings.TrimSuffix(modifyPatch, "+new\n"), "end of patch after line 4: truncated unified hunk"},
		{"unterminated line", strings.TrimSuffix(modifyPatch, "\n"), "line 5:"},
		{"CR in later section", modifyPatch + "--- a/other\r\n", "line 6:"},
		{"empty", "", "end of patch:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parse([]byte(tc.data))
			if got != nil || err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("targets=%v, error=%v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestParseSupportedUnified(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []contracts.PatchTarget
	}{
		{"modify", modifyPatch, []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"git modify", "diff --git a/file b/file\nindex 1111111..2222222 100644\n" + modifyPatch, []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"git executable context", "diff --git a/file b/file\nindex 1111111..2222222 100755\n" + modifyPatch, []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"git optional index mode", "diff --git a/file b/file\nindex 1111111..2222222\n" + modifyPatch, []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"git add", "diff --git a/added b/added\nnew file mode 100644\nindex 0000000..2222222\n" + addPatch, []contracts.PatchTarget{{NewPath: "added", Operation: contracts.OperationAdd}}},
		{"git executable add uses v1 mode", "diff --git a/added b/added\nnew file mode 100755\nindex 0000000..2222222\n" + addPatch, []contracts.PatchTarget{{NewPath: "added", Operation: contracts.OperationAdd}}},
		{"git delete", "diff --git a/deleted b/deleted\ndeleted file mode 100755\nindex 1111111..0000000\n" + deletePatch, []contracts.PatchTarget{{OldPath: "deleted", Operation: contracts.OperationDelete}}},
		{"mixed git and plain", "diff --git a/file b/file\nindex 1111111..2222222 100644\n" + modifyPatch + addPatch, []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}, {NewPath: "added", Operation: contracts.OperationAdd}}},
		{"add", addPatch, []contracts.PatchTarget{{NewPath: "added", Operation: contracts.OperationAdd}}},
		{"delete", deletePatch, []contracts.PatchTarget{{OldPath: "deleted", Operation: contracts.OperationDelete}}},
		{"multiple files", modifyPatch + addPatch + deletePatch, []contracts.PatchTarget{
			{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify},
			{NewPath: "added", Operation: contracts.OperationAdd},
			{OldPath: "deleted", Operation: contracts.OperationDelete},
		}},
		{"timestamps", "--- a/file\t2026-11-15 10:00:00.123456789 +0100\n+++ b/file\t2026-11-15 10:00:01 +0100\n@@ -1 +1 @@ section name\n-old\n+new\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"unicode and metacharacters", strings.ReplaceAll(modifyPatch, "file", "來源/$(literal);.c"), []contracts.PatchTarget{{OldPath: "來源/$(literal);.c", NewPath: "來源/$(literal);.c", Operation: contracts.OperationModify}}},
		{"header-like content", "--- a/file\n+++ b/file\n@@ -1,2 +1,2 @@\n--- a/../../content\n+++ b/../../content\n unchanged\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"multiple hunks", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n@@ -10,2 +10,3 @@ function\n context\n-tail\n+line\n+tail\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"no newline modify", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"no newline add", "--- /dev/null\n+++ b/added\n@@ -0,0 +1 @@\n+new\n\\ No newline at end of file\n", []contracts.PatchTarget{{NewPath: "added", Operation: contracts.OperationAdd}}},
		{"insert into existing", "--- a/file\n+++ b/file\n@@ -1,0 +2 @@\n+inserted\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
		{"opaque body bytes", "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-\xff\n+\xfe\n", []contracts.PatchTarget{{OldPath: "file", NewPath: "file", Operation: contracts.OperationModify}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parse([]byte(tc.data))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("targets = %#v, error = %v; want %#v", got, err, tc.want)
			}
		})
	}
}

func TestParseRejectsUnsafePathsOnBothSides(t *testing.T) {
	paths := []string{
		"a/../../escape", "a/../escape", "a/x/../../escape", "/outside/file", "a//file", "a/./file",
		"a/file/", "file", "a/", `"a/file"`, "a/'file'", "a/file name", "a/file\u2003name", "a/file\tname",
		"a/file\x1fname", "a/file\x7fname", `a\file`, "C:/file", "a/C:drive", string([]byte{'a', '/', 0xff}),
	}
	for _, path := range paths {
		for _, old := range []bool{true, false} {
			oldPath, newPath := "a/file", "b/file"
			if old {
				oldPath = path
			} else {
				newPath = path
			}
			data := "--- " + oldPath + "\n+++ " + newPath + "\n@@ -1 +1 @@\n-old\n+new\n"
			if targets, err := parse([]byte(data)); err == nil || targets != nil {
				t.Fatalf("accepted old=%v path %q: %#v", old, path, targets)
			}
		}
	}
}

func TestParseGitModeConsistency(t *testing.T) {
	for _, operation := range []struct {
		name, path, metadata, oldHash, newHash, patch string
	}{
		{"add", "added", "new file mode", "0000000", "2222222", addPatch},
		{"delete", "deleted", "deleted file mode", "1111111", "0000000", deletePatch},
	} {
		for _, declaredMode := range []string{"100644", "100755"} {
			for _, indexMode := range []string{"100644", "100755"} {
				t.Run(operation.name+"/"+declaredMode+"/"+indexMode, func(t *testing.T) {
					data := "diff --git a/" + operation.path + " b/" + operation.path + "\n" +
						operation.metadata + " " + declaredMode + "\n" +
						"index " + operation.oldHash + ".." + operation.newHash + " " + indexMode + "\n" + operation.patch
					got, err := parse([]byte(data))
					if declaredMode != indexMode {
						if err == nil || got != nil {
							t.Fatalf("accepted conflicting mode descriptors: targets=%#v, error=%v", got, err)
						}
					} else if err != nil || len(got) != 1 {
						t.Fatalf("rejected equal mode descriptors: targets=%#v, error=%v", got, err)
					}
				})
			}
		}
	}
}

func TestParseRejectsUnsupportedOrMalformedText(t *testing.T) {
	cases := map[string]string{
		"empty":                           "",
		"only header":                     "--- a/file\n+++ b/file\n",
		"missing new header":              "--- a/file\n",
		"wrong header":                    "*** a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n",
		"two nulls":                       "--- /dev/null\n+++ /dev/null\n@@ -1 +1 @@\n-old\n+new\n",
		"rename targets":                  strings.Replace(modifyPatch, "+++ b/file", "+++ b/other", 1),
		"add with old content":            strings.Replace(modifyPatch, "--- a/file", "--- /dev/null", 1),
		"delete with new content":         strings.Replace(modifyPatch, "+++ b/file", "+++ /dev/null", 1),
		"incomplete add":                  "--- /dev/null\n+++ b/file\n@@ -0,0 +2 @@\n+new\n",
		"incomplete delete":               "--- a/file\n+++ /dev/null\n@@ -2 +0,0 @@\n-old\n",
		"multiple add hunks":              "--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+new\n@@ -0,0 +1 @@\n+more\n",
		"git wrapper renamed":             "diff --git a/file b/other\nindex 1111111..2222222 100644\n" + modifyPatch,
		"git wrapper mismatched":          "diff --git a/other b/other\nindex 1111111..2222222 100644\n" + modifyPatch,
		"git wrapper traversal":           "diff --git a/../../file b/file\nindex 1111111..2222222 100644\n" + modifyPatch,
		"git wrapper quoted":              "diff --git \"a/file\" \"b/file\"\nindex 1111111..2222222 100644\n" + modifyPatch,
		"git wrapper null":                "diff --git /dev/null b/file\nindex 0000000..2222222\n" + modifyPatch,
		"git no index":                    "diff --git a/file b/file\n" + modifyPatch,
		"git nonregular index":            "diff --git a/file b/file\nindex 1111111..2222222 120000\n" + modifyPatch,
		"git gitlink index":               "diff --git a/file b/file\nindex 1111111..2222222 160000\n" + modifyPatch,
		"git malformed index":             "diff --git a/file b/file\nindex invalid..metadata 100644\n" + modifyPatch,
		"git inconsistent zero index":     "diff --git a/file b/file\nindex 0000000..2222222 100644\n" + modifyPatch,
		"git mode/header disagreement":    "diff --git a/file b/file\nnew file mode 100644\nindex 1111111..2222222\n" + modifyPatch,
		"git mode with text":              "diff --git a/file b/file\nold mode 100644\nnew mode 100755\n" + modifyPatch,
		"mode only":                       "diff --git a/file b/file\nold mode 100644\nnew mode 100755\n",
		"link mode":                       "diff --git a/file b/file\nnew file mode 120000\n" + addPatch,
		"rename only":                     "diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n",
		"binary":                          "GIT binary patch\nliteral 4\nAbcd\n",
		"binary files":                    "Binary files a/file and b/file differ\n",
		"index prefix":                    "Index: a/other\n" + modifyPatch,
		"mail prefix":                     "From: example\nSubject: demonstration\n\n" + modifyPatch,
		"normal diff":                     "1c1\n< old\n---\n> new\n",
		"context diff":                    "*** a/file\n--- b/file\n***************\n*** 1 ****\n- old\n--- 1 ----\n+ new\n",
		"trailing text":                   modifyPatch + "trailing garbage\n",
		"trailing blank":                  modifyPatch + "\n",
		"malformed hunk":                  strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -one +1 @@", 1),
		"missing hunk delimiter":          strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -1 +1", 1),
		"huge position":                   strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -999999999999999999999999 +1 @@", 1),
		"overflowing end":                 strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -9223372036854775807 +1 @@", 1),
		"huge count":                      strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -1,99999 +1 @@", 1),
		"zero position":                   strings.Replace(modifyPatch, "@@ -1 +1 @@", "@@ -0 +1 @@", 1),
		"zero change":                     "--- a/file\n+++ b/file\n@@ -1,0 +1,0 @@\n",
		"context only":                    "--- a/file\n+++ b/file\n@@ -1 +1 @@\n context\n",
		"truncated body":                  "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n",
		"unprefixed body":                 "--- a/file\n+++ b/file\n@@ -1 +1 @@\nold\n+new\n",
		"blank body":                      "--- a/file\n+++ b/file\n@@ -1 +1 @@\n\n-old\n+new\n",
		"excess old lines":                "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n-extra\n+new\n",
		"excess new lines":                modifyPatch + "+extra\n",
		"overlapping hunks":               modifyPatch + "@@ -1 +1 @@\n-old\n+new\n",
		"missing final LF":                strings.TrimSuffix(modifyPatch, "\n"),
		"CRLF":                            strings.ReplaceAll(modifyPatch, "\n", "\r\n"),
		"NUL body":                        strings.Replace(modifyPatch, "+new", "+new\x00", 1),
		"bad timestamp":                   strings.Replace(modifyPatch, "--- a/file", "--- a/file\tgarbage", 1),
		"space timestamp":                 strings.Replace(modifyPatch, "--- a/file", "--- a/file 2026-11-15 00:00:00 +0000", 1),
		"orphan marker":                   "--- a/file\n+++ b/file\n@@ -1 +1 @@\n\\ No newline at end of file\n-old\n+new\n",
		"duplicate marker":                strings.Replace(modifyPatch, "-old\n", "-old\n\\ No newline at end of file\n\\ No newline at end of file\n", 1),
		"marker before later source line": "--- a/file\n+++ b/file\n@@ -1,2 +1 @@\n-old\n\\ No newline at end of file\n-more\n+new\n",
		"unknown marker":                  modifyPatch + "\\ Unknown marker\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parse([]byte(data)); err == nil || got != nil {
				t.Fatalf("accepted unsupported text: targets=%#v, error=%v", got, err)
			}
		})
	}
}
