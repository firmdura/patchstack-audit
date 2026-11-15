// Package patchinput verifies a complete patch directory and freezes its declared
// bytes into private staging. It never applies a patch or starts a process.
//
// The supported format is unified text: ---/+++ headers followed by one or more
// counted @@ hunks, with LF line endings. A header may have a tab followed
// by a GNU diff timestamp. Multiple file sections and the standard no-newline
// marker are supported. Both header paths are validated after stripping exactly
// one component; modifications must name the same target. /dev/null is accepted
// only for a complete, single-hunk addition or deletion.
//
// A standard Git text envelope is also supported: diff --git, optional regular
// new/deleted file mode, and index metadata. Both wrapper paths must match the
// text headers after strip=1. Only regular modes 100644/100755 are descriptive;
// when both operation and index metadata specify modes, they must agree.
// Existing intended permissions remain unchanged and all new files use 0644.
// Git blob IDs in index lines are descriptive, not authenticated provenance.
//
// Paths containing whitespace, quotes, controls or backslashes are unsupported.
// Mail/Index prologues, binary data, mode changes, links, renames, context/normal
// diffs, unexplained leading/trailing text and malformed hunk counts are rejected
// before an executor can receive the staged series. Plain unified diffs can be
// produced with diff -u --label a/path --label b/path old-file new-file.
package patchinput
