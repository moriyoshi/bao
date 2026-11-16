# Signature verification

Details of the opt-in consumer verification described under
[consumer-controlled signature verification](../README.md#consumer-controlled-signature-verification),
and of the release envelopes that
[signing library releases](../README.md#signing-library-releases) produces.

## Release metadata and policy

The library developer supplies a signed release envelope covering the complete
module, as described in [signing library releases](../README.md#signing-library-releases).
To use these optional verification commands, obtain a trusted Bao CLI from
[CLI releases](../README.md#cli-releases). Ordinary application builds do not require it.

A consumer pins the **key and exact payload digest**, module, release and target
in a policy received and approved through their independent trusted channel:

```json
{
  "schema": 1,
  "keys": {"PUBLIC_KEY_SHA256": "BASE64_RAW_ED25519_PUBLIC_KEY"},
  "approvals": [{
    "module": "example.org/native",
    "target": "darwin/arm64",
    "release": "v1.2.3",
    "key_id": "PUBLIC_KEY_SHA256",
    "payload_sha256": "EXACT_APPROVED_PAYLOAD_SHA256"
  }]
}
```

Placeholders are deliberately unusable; Bao ships no publisher key or release
authority. Fetching a replacement policy/key or blindly approving the latest
digest from a compromised publisher defeats this trust model. Exact approvals
prevent automatic acceptance of newer or older releases, including another
release signed by the same key. Policy rotation/revocation, freshness and
rollback decisions remain with the consumer. There is no TUF update service,
transparency-log integration, threshold policy or automatic key discovery.

## Scan downloaded dependencies

```sh
bao verify -go /trusted/go1.26.11/bin/go -json
bao verify -C ./consumer -go /trusted/go1.26.11/bin/go \
  -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json -target darwin/arm64 -json
```

The default scope is the current module's dependencies, including downloaded
dependencies it does not import. Bao resolves the module build list offline,
runs `go mod verify`, and scans downloaded source trees for `.syso` files across
all targets and subdirectories. It checks complete trees against independently
approved signatures and rejects unsigned native dependencies. Ordinary Go
dependencies without native inputs need no Bao policy. Repeat `-manifest` for
multiple approved modules; supply policy and manifests together.

The main application module and unrelated entries in the global module cache
are excluded. Local replacements are scanned too, but Go's module-cache
integrity check does not cover them. Missing source downloads are reported as
`not-downloaded`, not fetched or authenticated; an approved native module that
is missing fails. Missing module metadata may prevent offline resolution, so
download dependencies beforehand. Source trees containing symlinks are refused.

Scanning compiles and runs no application code. It authenticates downloaded
sources at scan time and does not certify a later build or shared build cache.
Use `verified-build` to check actual linker inputs. JSON reports are also
printed on scan rejection, with a nonzero exit status.

## Go build flow and cache boundary

Download ordinary Go dependencies before verification, then invoke:

```sh
bao verified-build -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json \
  -go /trusted/go1.26.11/bin/go -target darwin/arm64 -o ./app ./cmd/app
```

Repeat `-manifest` for independently approved native modules. The command:

1. Checks signatures and exact policy approvals on every request.
2. Resolves one executable's dependency closure using stock Go, with cgo,
   workspaces, module networking, toolchain downloads and Go environment files
   disabled. Dependencies must already be available. It never runs `generate`,
   consumer `init`, `main`, or functions inside untrusted native objects.
3. Copies selected module trees into a private temporary directory and checks
   the copied bytes against each approved manifest. It binds every selected
   `.syso` to an approved complete module; unsigned native inputs fail closed.
   Ordinary Go dependencies and consumer application code remain consumer
   trusted unless their modules are also explicitly approved. This does not
   authenticate the entire Go supply chain.
4. Rewrites only dependency resolution in the private main `go.mod` to those
   snapshots, resolves again and rejects packages escaping them. Read-only
   snapshots, scrubbed build environment, internal linking, and a **new empty
   private `GOCACHE` per invocation** prevent reuse of unverified shared build
   results. The initial profile has no verified-cache reuse optimization.
5. Uses a private `-toolexec` hook that keeps Go tool version probes working.
   Immediately before linking it parses the actual input package archives,
   checks native member digests and multiplicities, rejects unknown/substituted
   members, and gives the linker read-only private copies of those exact bytes
   through a rewritten `importcfg` and main archive path. It requires a linker
   verification report before publishing a new executable and reports archive
   and final-executable SHA-256 values. Existing output files are refused.

## Bazel consumer builds

For a local rules_go consumer, select the separate Bazel backend:

```sh
bao verified-build -backend bazel -bazel /trusted/bin/bazel \
  -C ./consumer -module example.org/native=native \
  -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json \
  -target darwin/arm64 -o ./app //cmd/app:app
```

Each `-module importpath=relative/root` binds one approved complete native module
to a directory inside the consumer workspace, containing the library developer's
[prepared and signed package](../README.md#distributing-a-generated-package). Configure
the application's `go_binary` with `pure = "on"` and the requested
`goos`/`goarch`. Pin Bazel 8.4.2
(set the consumer's `.bazelversion` when using Bazelisk),
rules_go 0.65.0 and the downloaded Go 1.26.11 SDK, and generate the consumer's
`MODULE.bazel.lock` before verification. Consumer Bazel/Starlark definitions and
these tools are trusted; native repositories must be local signed roots.

Bao authenticates copied native source trees before Bazel loads their build
definitions, then analyzes a restricted action graph with rc files disabled.
It compiles into new private Bazel/Go caches with disk/remote action-result reuse
disabled, checks the actual link `.a` members, and replays the selected GoLink
action with private copies of those archives, standard-library archives, builder
and linker. rules_go's split export/archive format is checked separately from
stock Go's format. The consumer executable is published only after this checked
link completes; consumer `init` and `main` are never run by verification.

This initial backend accepts one local `//package:target` executable with pure
internal linking. External native repositories, custom build actions, cgo,
plugins, coverage/race modes, arbitrary compiler/linker flags and alternate
rules_go/SDK versions are refused. Repository/SDK downloads may occur in the
fresh private repository cache. This is a bounded rules_go profile, not a
general Bazel action sandbox or a `-toolexec` wrapper for Bazel.

## Limitations

The consumer-controlled host, Bao executable, Go SDK/tools, main application,
unapproved Go dependencies and policy files are trusted. This does not defend
against root, a hostile process with the same user's privileges, memory or
toolchain compromise, or a signer approving malicious code. Private directories
and read-only copies reduce incidental mutation; they are not an OS security
sandbox against that user. The implementation does not claim race-proof checks
against a hostile same-user process. Archive copies bind the checked bytes to
the paths provided to the trusted linker within this host trust assumption.

The stock Go profile builds a single main package without custom flags, overlays,
workspace mode, external linking or shared-library inputs. It rejects native
objects in the standard library, and assembly includes escaping a selected
package. Native target support is inherited from the stock toolchain and Bao's
translator profiles. Verification itself requires no Rust compiler, Apple
linker, native extraction, cgo or execution of the consumer. Mac app codesigning
is a separate later step and does not prove prelink artifact identity.

Input source provenance, reproducibility, builder authorization and code review
are separate from authenticating bytes. Signed Bao provenance files are useful
records, not independent proof of how a producer built its artifacts. Module
checksums and `go mod verify` serve their documented module-cache roles; they
do not establish an independently approved native release signing authority.
See [Go build/tool execution](https://pkg.go.dev/cmd/go@go1.26.11),
[Go module verification](https://go.dev/ref/mod#go-mod-verify) and
[SLSA verification expectations](https://slsa.dev/spec/v1.2/verifying-artifacts).

## Release envelope format

`keygen` prints the public key as base64 plus its key ID (SHA-256 of the raw
Ed25519 public key). `sign` prints that ID and the signed payload's SHA-256.
Its envelope contains base64 `payload` and `signature` and a `key_id`.
The payload is JSON schema 1: `module`, exact `target`, `release`, and sorted
`files` entries containing `path` and `sha256`. Ed25519 signs the bytes
`bao.module-release.v1\0` followed by the exact payload bytes. Verification
does not reserialize or canonicalize untrusted JSON before checking a signature.

## Implementation notes

The [verified-build flow](#go-build-flow-and-cache-boundary) addresses Go's cache
caveat by construction. A standalone link hook can
be skipped entirely when Go reuses a cached build result. `packInternal` also
places `.syso` bytes into Go package archives inside `cmd/go`; there is no
external `pack` invocation to intercept. Checking original source paths at link
time would not authenticate a substituted cached archive.

The private `_verified-tool` command is an implementation detail, not a
supported mandatory verification hook for arbitrary `go build -toolexec` use.
The outer command's fresh cache and required linker report are essential.
These rules intentionally trade cache performance for a small trust model.

## Tests

```sh
bazel test //verify:verify_test
bazel run //:verify -- -suite signatures
bazel run //:verify -- -suite bazel -bazel /path/to/bazel
```

The integration fixture uses a freshly generated **local test key** and a Rust
leaf object produced once. Verification/build uses cgo disabled and unavailable
C/C++/Rust compiler paths. It tests an approved build and repeat request,
warm-shared-cache native substitution, altered generated Go/assembly, an extra
selected native object, wrong target/release, an invalid signature, and native
substitution inside a real cached package archive while its source stays
unchanged. Consumer initialization is checked absent until the approved binary
is deliberately run separately. The fixture currently runs on macOS/arm64.

The suite also authenticates and builds a complete generated static-binding
module, including its bundled runtime bootstrap, without a PureGo dependency.
Assembly archive names truncated to the same 16-byte prefix are verified with
their expected multiplicities; extra and missing members remain rejected.
The signature suite also scans an actual downloaded module cache offline,
rejects an unused unsigned native dependency and a modified cache entry, and
reports a dependency whose sources have not been downloaded.

The Bazel suite builds an independent local consumer on macOS arm64. It poisons
an ordinary shared native archive, verifies and links from fresh private state,
and rejects changed signed sources and a reachable custom action. The approved
executable is run separately. Linux arm64's Bazel consumer has also been checked
in native Docker execution; other Bazel target combinations need separate
validation. Test signing keys are local fixtures, not release authority.
