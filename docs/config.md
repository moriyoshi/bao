# Config files and diagnostics

## Config files

`bao build` and `bao translate` can read their options from a JSON file instead
of the command line:

```sh
bao build -config bao.json -target windows/amd64 -o ./native native.lib
```

```json
{
  "schema": 1,
  "package": "native",
  "symbols": ["native_add"],
  "bindings": {
    "schema": 1,
    "abi": "c",
    "functions": [
      {"name": "Add", "symbol": "native_add", "params": ["int64", "int64"], "result": "int64"}
    ]
  },
  "linux": {
    "sysroot": "${SYSROOT}",
    "system_libraries": ["libxcb.so.1"]
  },
  "windows": {
    "cxx_runtime": "libc++",
    "max_data_alignment": 32,
    "link_archives": ["${MINGW}/lib/libunwind.a"],
    "import_libraries": ["${MINGW}/lib/libuser32.a"]
  }
}
```

| Key | Value |
| --- | --- |
| `schema` | `1` |
| `target`, `input`, `package`, `symbols` | As `-target`, the positional input, `-package` and repeated `-symbol` |
| `bindings` | An inline manifest, a manifest path, or `dwarf` |
| `strip_debug`, `strip_bitcode` | As `-strip-debug` and `-strip-bitcode` |
| `link_archives`, `link_notices`, `require_static_runtime` | As `-link-archive`, `-link-notice` and `-require-static-runtime` |
| `wrap`, `redefine_symbols`, `redefine_symbol_files`, `wildcard` | The [symbol edits](symbol-edits.md); `redefine_symbols` holds `OLD=NEW` strings |
| `prefix_symbols` | An object from input path to prefix |
| `symbol_visibility` | An object from input path to `localize_symbols`, `localize_symbol_files`, `localize_hidden`, `keep_global_symbols`, `keep_global_symbol_files`, `globalize_symbols`, `weaken_symbols`, `strip_symbols`, `strip_unneeded`, `remove_sections`, `only_sections` and `add_symbols` |
| `cargo` | `manifest_path`, `package`, `offline`, `locked` |
| `darwin` | `sdk`, `min_os`, `ld` |
| `linux` | `sysroot`, `ld`, `system_libraries`, `max_symbol_versions`, `max_text_alignment`, `shared_object`, `static_tls` |
| `windows` | `imports`, `import_libraries`, `cxx_runtime`, `crt`, `max_data_alignment` |

Every platform section also accepts `link_archives`, `link_notices` and
`require_static_runtime`.

Only the section for the build's target applies, and its link inputs follow the
common ones. Paths are relative to the config file and may use `${VAR}`; an
unset variable is an error. `${BAO_GOOS}`, `${BAO_GOARCH}` and `${BAO_CPU}` name
the build target, with `${BAO_CPU}` being `x86_64`, `aarch64` and so on, so
`${LLVM_MINGW}/${BAO_CPU}-w64-mingw32/lib/libuser32.a` serves both architectures.
They are not available in `input`, which can decide the target. A flag given on the command line replaces that whole
setting, including every entry of a repeatable flag. Unknown or duplicate keys
are errors, as is a setting the command cannot use. `-o` and the diagnostics
flags stay on the command line.

Without `-config`, Bao uses `.bao.config.json` from the working directory if it
exists and notes this on stderr. Parent directories are not searched. Use
`-config ''` to run without it. The file can name a linker through `ld`, so
review it before building in a checkout you do not trust.

## Diagnostics

`build`, `translate` and `inspect` accept these flags; `doctor` accepts them for
its toolchain checks. They collect errors rather than only logging more: `-v`
keeps going within a stage and reports everything found there.

| Flag | Effect |
| --- | --- |
| `-v` | One line per stage with limits and headroom |
| `-vv` | Adds the symbols behind each number |
| `-trace SYMBOL` | SYMBOL's state at each stage; repeatable |
| `-report FILE` | Findings as JSON, for CI artifacts |
| `-assume-consumer net,crypto/x509` | Counts libraries those dependencies add |

```text
limits OK sections 25 / 65,279 (headroom 65,254)
imports FAIL 43 unresolved: xkb 29, xcb 14
imports HINT -linux-system-library libxcb.so.1 would satisfy 14
functions SKIPPED generation failed; no objects to measure
stopped: 1 failures; no package written
```

Diagnostics go only to stderr or the report file, and they do not change the exit
code or generated objects. Unresolved imports are listed together on every
platform, with or without `-v`. A stage that did not run prints `SKIPPED` with
the reason. A clean report means no known limit was exceeded; it does not verify
execution. The findfunc density is a prediction from object layout.

Findings have stable IDs: `BAO-ELF-SECTIONS`, `BAO-MACHO-SECTIONS`,
`BAO-COFF-SECTIONS`, `BAO-GO-FINDFUNC`, `BAO-MACHO-ORDINAL`,
`BAO-MACHO-FLAT-BIND`, `BAO-IMPORT-MISSING`, `BAO-ELF-TEXT-ALIGNMENT-CAPPED`,
`BAO-COFF-ALIGNMENT-CAPPED` and `BAO-GENERATE`.

`bao inspect -v -manifest bao-manifest.json ./program` reads a built Mach-O
executable, reports flat-namespace binds, and compares each bind's dylib with
the manifest. It exits non-zero on a failure. Library hints on Linux are advice:
binding still requires `-linux-system-library`. `-trace` reads each stage's
artifacts, so the translator stage it names is labeled as an inference.
