# Two-patch example

This example starts with a tiny C program. The first patch changes its arithmetic
operation; the second changes the label it prints. The source and both patches
are original to this project and use Apache-2.0. Each patch declares
`local:demonstration` as its origin. Neither patch represents a security fix or
makes a claim about a CVE.

Follow the [build instructions](../../README.md#build-and-try-the-example) first,
then run these commands from the repository root on Linux:

```sh
work=$(mktemp -d)
go run ./examples/demo --output "$work/inputs"
./bin/patchstack audit \
  --manifest "$work/inputs/stack.yaml" \
  --input-root "$work/inputs" \
  --output "$work/result"
```

The generator writes `source.tar.gz`, a `patches/` directory and `stack.yaml` with
the exact SHA-256 hashes of those inputs. It uses the fixtures embedded in the
generator, with a fixed archive entry order, permissions, ownership and timestamps.
Running it again produces identical input bytes. These generated files are
disposable; the checked-in fixtures remain the source for the example.

Both generated directories, `inputs` and `result`, must be absent before their
respective commands run. Their parent must already exist; `mktemp -d` creates it
here. On success, `$work/result` contains the patched `source/main.c`,
`report.json` and `report.md`.

The audit does not compile or test the C program, so no C compiler is needed.
Successful application demonstrates reproduction of this patch series; it does
not establish a security repair.
