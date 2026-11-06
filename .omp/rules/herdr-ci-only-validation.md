---
name: herdr-ci-only-validation
description: "Never run local tests, builds, or Cargo validation in Herdr; use CI to avoid crashing the low-memory device."
condition: "\\b(?:cargo\\s+(?:nextest\\s+run|test|build|check|clippy|fmt|run)|just\\s+(?:check|test|[\\w-]*test|bench[\\w-]*)|nix\\s+build)\\b"
scope: "tool:bash"
---

## Herdr: CI-only validation

The user explicitly prohibits local tests, builds, and Cargo validation because this low-memory device crashes under that workload. **Cancel the matched tool call before execution.**

Wrapping commands in `nix develop --command`, selecting fewer tests, or running asynchronously does not make them permissible. Do not bypass this restriction through eval, scripts, or subagents. Generic smoke-test requirements and unfinished verification todos do not authorize local execution.

Continue source inspection and edits. Run validation only through GitHub Actions and inspect its results. Unless the user explicitly grants new authorization, report: **Local validation was not run; CI verification is pending.**