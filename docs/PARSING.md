# Kingfisher Source Code Parsing
Kingfisher leverages tree‐sitter as an extra layer of analysis when scanning source files written in supported programming languages. In practice, after its initial regex‐based scan (powered by Vectorscan), Kingfisher checks if the file’s language is known.

If so, it creates a Checker (see below) that uses tree‐sitter to parse the file and run language‐specific queries. This additional pass refines the detection by capturing more structured patterns—such as secret-like tokens—that might be obscured or spread over code constructs.

### How It’s Called

In the scanning phase (in the Matcher’s implementation), Kingfisher does the following:
- **Language Detection:** When processing a blob, if a language string is provided (e.g. inferred from file metadata or extension), the code calls a helper (via a function like `get_language_and_queries`) to retrieve the corresponding tree‐sitter language and a set of queries.
- **Checker Creation:** With these values, a `Checker` struct is instantiated. This struct holds both the target language (as defined in its `Language` enum) and a map of tree‐sitter queries to run.
- **Parsing and Querying:** The Checker’s key method (e.g. `check` or indirectly via `modify_regex`) retrieves a thread‐local tree‐sitter parser (to avoid recreating the parser on every call), sets the appropriate language, and parses the source code into a syntax tree. It then executes the queries over that tree, extracting ranges and texts of interest that might represent secrets.  
  *(See the implementation details in the parser module – for example, the `modify_regex` function in the Checker, and the conditional tree‐sitter call in Matcher::scan_blob)*

### Supported Languages

The design supports many common source code languages. The Language enum (defined in the parser module) includes variants for:
- **Scripting:** Bash, Python, Ruby, PHP  
- **Compiled languages:** C, C++, C#, Rust, Java  
- **Web-related languages:** CSS, HTML, JavaScript, TypeScript, YAML, Toml  
- **Others:** Go, and even a generic “Regex” mode  

Each variant maps to its corresponding tree‐sitter language through the `get_ts_language()` method.

### When Tree‐sitter Is Not Called

Tree‐sitter won’t be invoked in certain cases:
- **No Language Identified:** If the file isn’t recognized as belonging to one of the supported languages or no language hint is provided, the Checker isn’t even constructed.
- **Non-source Files:** Binary files or files that aren’t expected to contain code (or aren’t extracted from archives) bypass tree‐sitter parsing.
- **Fallback on Errors:** If tree‐sitter parsing fails (e.g. due to malformed code or other errors), Kingfisher will fall back on its regex/Vectorscan matches without the additional tree‐sitter insights.

### Summary

In essence, Kingfisher’s use of tree‐sitter is conditional and complementary. It is called only when the scanned file is a source code file written in a supported language, and its role is to enrich the scanning results by leveraging the syntax tree and language-specific queries. When files are non-source, binary, or if no language is provided, tree‐sitter is not invoked, and Kingfisher relies solely on its regex-based detection.

This layered approach helps improve the accuracy of secret detection while maintaining high performance.
