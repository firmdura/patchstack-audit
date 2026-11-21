# PatchStack Audit

Schema version: 1

Outcome: failed

Stage: execution

Reason: timeout

## Source declaration

Archive: demo&#46;tar&#46;gz

SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Archive root: demo&#45;1&#46;0

## Ordered patches

1 applied, 1 failed, 0 not run.

| Position | ID | File | SHA-256 | Application | Reason | Declared provenance | Declared CVEs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | z&#45;first | 0001&#45;first&#46;patch | bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | applied | none | local&#58;demonstration | CVE&#45;2025&#45;0001&#44; CVE&#45;2024&#45;10000 |
| 2 | a&#45;second | 0002&#45;second&#46;patch | cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc | failed | timeout | https&#58;&#47;&#47;example&#46;org&#47;commit&#47;demo |  |

Upstream references and CVE identifiers are declarations, not authenticated provenance or security verdicts.

## Digest definition

SHA&#45;256 of the UTF&#45;8 manifest&#44; sorted by relative path bytes&#59; each regular file contributes path NUL four&#45;digit octal intended mode NUL lowercase content SHA&#45;256 LF&#59; empty directories&#44; uid&#44; gid and timestamps are excluded&#46;

## Evidence limitations

Hashes establish byte identity and clean patch application establishes reproduction of declared inputs&#46; Neither proves trusted provenance&#44; a security repair&#44; CVE applicability&#44; a successful build&#44; or compliance&#46;
