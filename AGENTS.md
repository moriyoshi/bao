# Documents for humans and coding agents

* [README.md](README.md): public APIs, build commands, examples, supported behavior, and trust boundaries.
* [JOURNAL.md](JOURNAL.md): durable findings, decisions, and verification history.

# Documentation and journaling

* Keep user workflows and supported behavior in `README.md`. Record operational findings, implementation decisions, investigations, and verification outcomes in `JOURNAL.md`.
* Read the relevant journal entries before revisiting an investigation. Verify historical claims against the current implementation before relying on them.
* Append dated entries to the end of `JOURNAL.md`. Do not rewrite, reorder, or remove earlier entries during ordinary work. Record corrections and superseding results in a new entry that identifies the earlier finding.
* Journal entries should explain the concrete problem or decision, what changed, the result, and any remaining limitations. Include the reproduction commands, toolchain versions, target, and execution environment needed to assess a verification claim.
* Distinguish compilation, successful linkage, native execution, emulated execution, and signing checks. Record what actually ran; do not label skipped checks as passed or cite a cached executable as evidence for changed native inputs. Include meaningful negative controls when used.
* Keep scratch scripts, raw logs, inventories, generated artifacts, and investigation checkouts in ignored `.work/`. Summarize durable evidence in the journal instead of creating per-session Markdown reports or a repository-level `evidence/` tree. Maintained tests, fixtures, and tools belong in their existing source directories.
* Reorganize or consolidate earlier journal entries only as explicitly requested maintenance, after verifying that durable findings and verification context are preserved. A recorded next step or backlog item is not authorization to implement it.
* Preserve unrelated edits and user files. Use ASCII parentheses and colons in authored prose; preserve exact code, URLs, Unicode examples, and fixture data.
