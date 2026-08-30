---
title: "Multi-Step Revocation"
description: "Configure lookup-then-delete HTTP revocation workflows for credentials that require multiple API requests."
---

# Multi-Step Revocation Implementation

## Overview

This document describes the implementation of 2-step revocation support in Kingfisher. Some services require a two-step revocation process:

1. **Step 1 (Lookup)**: Query the API to retrieve an internal ID, token identifier, or other metadata
2. **Step 2 (Delete)**: Use the extracted value(s) to perform the actual revocation/deletion

## Architecture

### New Types

#### `HttpMultiStepRevocation`
```rust
pub struct HttpMultiStepRevocation {
    /// Sequential steps to execute (minimum 1, maximum 2).
    pub steps: Vec<RevocationStep>,
}
```

#### `RevocationStep`
```rust
pub struct RevocationStep {
    /// Human-readable name for this step (e.g., "lookup_id", "delete").
    pub name: Option<String>,
    
    /// HTTP request configuration for this step.
    pub request: HttpRequest,
    
    /// Optional multipart configuration for this step.
    pub multipart: Option<MultipartConfig>,
    
    /// Variables to extract from the response for use in subsequent steps.
    pub extract: Option<BTreeMap<String, ResponseExtractor>>,
}
```

#### `ResponseExtractor`
```rust
pub enum ResponseExtractor {
    /// Extract from JSON response using JSONPath syntax
    JsonPath { path: String },
    
    /// Extract using regex with a capture group
    Regex { pattern: String },
    
    /// Extract an HTTP response header value
    Header { name: String },
    
    /// Use the entire response body as-is
    Body,
    
    /// Extract the HTTP status code as a string
    StatusCode,
}
```

### Revocation Enum

The `Revocation` enum has been extended with:

```rust
pub enum Revocation {
    AWS,
    GCP,
    Http(HttpValidation),
    HttpMultiStep(HttpMultiStepRevocation),  // New variant
}
```

## Implementation Details

### Execution Flow

1. **Validation**: Checks that 1-2 steps are defined
2. **Sequential Execution**: Each step executes in order
3. **Variable Extraction**: After each step completes, extract variables from response
4. **Variable Injection**: Extracted variables are available as Liquid templates in subsequent steps
5. **Response Validation**: Final step's `response_matcher` determines success/failure

### Key Functions

#### `extract_value_from_response()`
Extracts a value from an HTTP response based on the specified extractor type.

**Supported Extractors:**
- **JsonPath**: Basic JSONPath implementation supporting:
  - Nested fields: `$.data.user.id`
  - Array indexing: `$.items[0].id`
  - Combined: `$.data.sessions[0].session_id`
- **Regex**: Uses first capture group from pattern match
- **Header**: Extracts value from response header by name
- **Body**: Returns entire response body
- **StatusCode**: Returns HTTP status code as string

#### `execute_revocation_step()`
Executes a single revocation step:
1. Renders URL and request templates with current variables
2. Builds and sends HTTP request
3. Extracts variables from response if configured
4. Adds extracted variables to globals for next step

#### `execute_multi_step_revocation()`
Orchestrates the multi-step revocation process:
1. Validates step count (1-2 steps)
2. Iterates through steps sequentially
3. Tracks intermediate results
4. Returns final result from last step

### Backwards Compatibility

All existing single-step revocations continue to work unchanged:
- `Revocation::AWS`
- `Revocation::GCP`
- `Revocation::Http(_)`

## Usage Examples

### Basic 2-Step Revocation

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      # Step 1: Get the token ID
      - name: lookup_token_id
        request:
          method: GET
          url: https://api.example.com/v1/tokens/current
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:
          TOKEN_ID:
            type: JsonPath
            path: "$.data.token_id"
      
      # Step 2: Delete the token
      - name: delete_token
        request:
          method: DELETE
          url: https://api.example.com/v1/tokens/{{ TOKEN_ID }}
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [204]
```

### Multiple Extractions

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      - name: get_metadata
        request:
          method: GET
          url: https://api.service.com/tokens/info
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:
          TOKEN_ID:
            type: JsonPath
            path: "$.id"
          ACCOUNT_ID:
            type: Header
            name: X-Account-ID
          TOKEN_TYPE:
            type: Regex
            pattern: '"type":\s*"([^"]+)"'
      
      - name: revoke_token
        request:
          method: POST
          url: https://api.service.com/accounts/{{ ACCOUNT_ID }}/tokens/{{ TOKEN_ID }}/revoke
          headers:
            Authorization: "Bearer {{ TOKEN }}"
            Content-Type: application/json
          body: '{"token_type":"{{ TOKEN_TYPE }}"}'
          response_matcher:
            - type: StatusMatch
              status: [200, 204]
```

## Testing

Test your multi-step revocation using:

```bash
# Revoke a token using multi-step revocation
kingfisher revoke --rule <rule_id> <token>

# With additional variables if needed
kingfisher revoke --rule <rule_id> --var EXTRA_VAR=value <token>
```

## Files Modified

### Core Implementation
- `crates/kingfisher-rules/src/rule.rs`: Added new types and enum variants
- `crates/kingfisher-rules/src/lib.rs`: Exported new types
- `src/direct_revoke.rs`: Added multi-step execution logic

### Documentation
- `docs/RULES.md`: Added comprehensive multi-step revocation documentation
- `docs/MULTI_STEP_REVOCATION.md`: This file

### Examples
- [RULES.md](../rules/overview.md): Kingfisher 1.x custom-rule examples and schema guidance

### Supporting Changes
- `src/reporter.rs`: Added pattern match for `HttpMultiStep` variant

## Constraints

1. **Maximum 2 steps**: The implementation supports 1-2 steps only
2. **Sequential execution**: Steps execute in order; no parallel execution
3. **Final step validation**: The last step must include `response_matcher`
4. **Variable naming**: Extracted variable names should be uppercase (convention)
5. **JSONPath limitations**: Basic implementation supporting common patterns only

## Error Handling

The implementation provides clear error messages for:
- Empty steps array
- More than 2 steps
- Missing response_matcher on final step
- Failed variable extraction
- Invalid JSONPath syntax
- Missing required headers or fields
- HTTP request failures

All errors are propagated with context about which step failed and why.

## Debug Logging

Enable debug logging to see multi-step execution details:

```bash
RUST_LOG=debug kingfisher revoke --rule <rule_id> <token>
```

Debug logs include:
- Step execution start/completion
- URLs being called
- Variables extracted and their values
- Response status codes
- Intermediate step results
