---
title: "Source Code Parsing"
description: "Available language parser backends and the scan-time context verification gate for eligible HTML and CSS files."
---

# Kingfisher Source Code Parsing

Kingfisher uses a parser-based context verifier as a second pass on supported source files. After its initial regex scan (powered by Vectorscan/Hyperscan), it extracts assignment-style snippets from code and configuration files to confirm that generic keyword+token matches appear in plausible contexts.

The implementation favors lightweight extractors over full AST parsing:

- **Handwritten lexers** for common programming and config languages — comment-aware stripping followed by regex-based `key = value` extraction
- **`tl`** for HTML — attribute values, element text, and embedded `<script>` / `<style>` delegation
- **`cssparser`** for CSS — declaration parsing via Mozilla’s CSS tokenizer

> **History:** Earlier parser implementations relied on 17 statically-linked
> grammar crates. This added ~20 MB to the binary and required building a
> full syntax tree just to extract assignment pairs. The current lexer-based
> approach achieves the same extraction quality with near-zero binary overhead
> and no external grammar dependencies.

## How It’s Called

In the scanning phase (in the Matcher’s implementation), Kingfisher does the following:

- **Primary Regex Pass:** Kingfisher always scans the full blob with Vectorscan/Hyperscan first.
- **Candidate Selection:** Findings from rules classified as context-dependent become parser-verification candidates.
- **Language Detection:** If a language string is provided (for example from metadata or extension), the code maps it to a supported parser backend.
- **Parsing and Querying:** The parser streams normalized snippets such as `key = value` without materializing a full syntax tree.
- **Verification Decision:** Strict contextual candidates are kept only if parser-extracted context verifies the matched secret. More explicit assignment-style rules can still survive on raw regex evidence when parser verification is unavailable.

## Supported Languages

The design supports many common source code languages. The Language enum (defined in the parser module) includes variants for:

- **Scripting:** Bash, Python, Ruby, PHP
- **Compiled languages:** C, C++, C#, Rust, Java
- **Web-related languages:** CSS, HTML, JavaScript, TypeScript, YAML, TOML
- **Others:** Go

These are available parser backends. The scanner currently invokes its context
verification gate only for HTML and CSS; other source languages, including Python,
do not receive comment/docstring filtering from that gate.

## When Context Verification Is Not Called

Context verification is skipped in certain cases:

- **No Language Identified:** If the file isn’t recognized as belonging to one of the supported languages or no language hint is provided, the context verifier isn’t even constructed.
- **Non-source Files:** Binary files or files that aren’t expected to contain code (or aren’t extracted from archives) bypass parser-based context verification.
- **Large Blobs:** Files larger than 2 MiB skip context verification to avoid spending time on generated or minified content.
- **Verification Errors:** If extraction fails, rules whose match profile strictly requires parser confirmation are suppressed. Assignment-style contextual rules can still fall back to their raw regex hit.

## Summary

Parser-based context verification is conditional and complementary. The scan-time gate is called only for eligible HTML or CSS blobs, and its role is to reduce noisy strict-context findings by checking them against extracted code/config structure without unnecessarily dropping clear assignment-style secrets from raw text inputs.

This layered approach helps improve the accuracy of secret detection while maintaining high performance.
