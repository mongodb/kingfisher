---
title: "Writing Custom Rules"
description: "Write custom YAML-based detection rules with regex patterns, entropy thresholds, validation, revocation, and checksum intelligence."
---

# Writing Custom Rules for Kingfisher

A _rule_ in Kingfisher is a YAML document that describes how to detect and (optionally) validate or revoke secrets in your codebase. With custom rules you can:

- **Extend** Kingfisher without touching Rust code  
- **Tune** sensitivity via entropy and confidence  
- **Plug in** live checks against external services  

This document explains how to write custom rules for Kingfisher using a YAML-based rule system. The rules define regular expressions to detect secrets in source code and other textual data, and they can include validation or revocation steps to confirm or invalidate the secret. By using a rules-based system, Kingfisher is highly extensible—new rules can be added or existing ones modified without changing the core code.

## 1. Rule Schema

Each rule file defines one or more entries under a top‑level `rules:` list. Every entry supports the following fields:

```yaml
rules:
  - name:           # (string) Human-friendly rule name
    id:             # (string) Unique identifier (e.g. kingfisher.aws.1)

    pattern: |      # (multi-line regex) Detection pattern
      (?x)(?i)
      aws
      (?:.|[\n\r]){0,32}?
      \b([A-Za-z0-9/+=]{40})\b

    min_entropy: 3.5                # (float) Minimum Shannon entropy
    confidence:  medium             # (enum: low | medium | high)

    examples:                       # (list) strings that must match
      - AWS_SECRET="AKIA…"

    references:                     # (optional list) context URLs
      - https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html

    visible: true                   # (bool) hide helper matches when false

    depends_on_rule:                # (optional) capture chaining
      - rule_id: kingfisher.aws.id
        variable: AKID              # referenced as {{ AKID }}

    pattern_requirements:         # (optional) character/word requirements
      min_digits: 1                 # require at least 1 digit
      min_uppercase: 1              # require at least 1 uppercase letter
      min_lowercase: 1              # require at least 1 lowercase letter
      min_special_chars: 1          # require at least 1 special character
      special_chars: "!@#$%^&*()"   # optional: custom special character set
      ignore_if_contains:                # optional: drop matches containing these words
        - test

    validation:                     # (optional) live validation
      type: Http
      content:
        request:
          method: GET
          url: https://api.example.com/v1/check
          headers:
            X-Secret: "{{ TOKEN }}"
            X-Id:     "{{ AKID }}"
          response_is_html: true # by default, validation responses containing HTML or considered invalid. Set to `true` if you expect HTML returned from a validation response
          response_matcher:
            - report_response: true   # always include raw payload
            - type: StatusMatch
              status: [200]           # positive check
            - type: StatusMatch
              status: [401,403]
              negative: true          # negative check → must NOT match
            - type: HeaderMatch
              header: content-type
              expected: ["application/json"]
            - type: JsonValid

    # NOTE: Some providers are gRPC-only (no REST endpoint). For those, use Grpc validation.
    validation:
      type: Grpc
      content:
        request:
          url: https://api.example.com/<package>.<Service>/<Method>
          headers:
            content-type: application/grpc
            te: trailers
            Authorization: "Bearer {{ TOKEN }}"
          # Raw bytes are allowed (YAML \\u0000 escapes become NUL bytes).
          body: "\\u0000\\u0000\\u0000\\u0000\\u0000"
          response_matcher:
            - report_response: true
            - type: HeaderMatch
              header: grpc-status
              expected: ["0"]

    revocation:                     # (optional) revoke a secret
      type: Http
      content:
        request:
          method: POST
          url: https://api.example.com/v1/revoke
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [200, 202]

```

AWS access key revocation can use:

```yaml
revocation:
  type: AWS
```

GCP service account key revocation can use:

```yaml
revocation:
  type: GCP
```

### Multi-Step Revocation

Some services require a 2-step revocation process:
1. **Lookup Step**: Make a request to retrieve an ID or token
2. **Delete Step**: Use that ID to perform the actual revocation

For these cases, use `HttpMultiStep`:

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      - name: lookup_token_id                    # Step 1: Get the token ID
        request:
          method: GET
          url: https://api.example.com/v1/tokens/current
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:                                  # Extract values from response
          TOKEN_ID:                               # Variable name (uppercase)
            type: JsonPath                        # Extraction method
            path: "$.data.id"                     # JSONPath to the value
      
      - name: revoke_token                        # Step 2: Delete using the ID
        request:
          method: DELETE
          url: https://api.example.com/v1/tokens/{{ TOKEN_ID }}
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [204]
```

| Field                   | What it does                                                         |
| ----------------------- | -------------------------------------------------------------------- |
| name                    | Friendly name shown in reports                                       |
| id                      | Unique text ID (namespace.v#) used internally                        |
| pattern                 | Regex used to spot secrets (free‑spacing & flags allowed)            |
| min_entropy             | Threshold to guard against low‑complexity false positives            |
| confidence              | Suggests severity: low → high                                        |
| examples                | Good matches; used for testing                                       |
| visible                 | false to hide non‑secret captures (e.g. IDs)                         |
| depends_on_rule         | Chain rules: use captures from one rule in another's validation      |
| pattern_requirements  | Require character types and/or exclude placeholder words from matches |
| validation              | Configure `Http`, `Grpc`, typed validators (`AWS`, `GCP`, etc.), or `Raw` exception-path checks to verify live validity |
| revocation              | Configure HTTP, AWS, or multi-step revocation for a detected secret  |

## Validation Types

Kingfisher supports three validation buckets:

1. `Http` and `Grpc`: YAML-native validation flows. Prefer these first.
2. Typed validators: schema-level validation families already modeled in the rule schema, such as `AWS`, `AzureStorage`, `Coinbase`, `GCP`, `MongoDB`, `MySQL`, `Postgres`, `Jdbc`, and `JWT`.
3. Raw validators: provider-specific or protocol-specific exception paths dispatched through `validation: type: Raw`.

Raw validation looks like this:

```yaml
validation:
  type: Raw
  content: kraken
```

Use `Raw` only when the provider check cannot be expressed reliably with `Http` or `Grpc` and does not justify a new reusable validator family. Raw validator implementations live in `crates/kingfisher-scanner/src/validation/raw.rs`.

Typed validators are safer and more reusable because the validator kind is part of the schema. `Raw` validators are string-dispatched and fail at runtime if the `content` name is unknown. If you need a Rust-backed exception path for one provider, prefer `Raw`; reserve new typed validators for stable validation families that can be reused across rules.

## gRPC Validation (Grpc)

Some services (notably CLI/SDK control planes) are **gRPC-only**. For these, `validation: type: Http`
is not sufficient because gRPC status is typically returned via HTTP/2 trailers (`grpc-status`,
`grpc-message`). Kingfisher’s `Grpc` validator performs an HTTP/2 request and evaluates matchers
against the merged headers+trailers.

`Grpc` is currently intended for unary requests and expects you to provide a fully-qualified method URL:

```yaml
validation:
  type: Grpc
  content:
    request:
      url: https://api.modal.com/modal.client.ModalClient/ClientHello
      headers:
        content-type: application/grpc
        te: trailers
        x-modal-token-id: "{{ TOKEN_ID }}"
        x-modal-token-secret: "{{ TOKEN }}"
        x-modal-client-type: "1"
        x-modal-client-version: "1.0.0"
      body: "\u0000\u0000\u0000\u0000\u0000"  # Empty protobuf frame
      response_matcher:
        - report_response: true
        - type: HeaderMatch
          header: grpc-status
          expected: ["0"]
```


*responser_matcher* variants. Multiple can be used

| Variant         | Required keys                                                                                              | Behavior                                                                |
|-----------------|-------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **StatusMatch** | `status` (list\<int>)<br>`negative` (bool, default `false`)                                                 | Pass when codes match (or don’t match if `negative`).                     |
| **WordMatch**   | `words` (list\<string>)<br>`match_all_words` (bool)<br>`negative` (bool)                                    | Word/substring checks in body.                                            |
| **HeaderMatch** | `header` (string)<br>`expected` (list\<string>)<br>`match_all_values` (bool)                                | Header value assertions.                                                  |
| **JsonValid**   | –                                                                                                           | Pass only if body parses as JSON. Use when response is expected as JSON data                                       |
| **XmlValid**    | –                                                                                                           | Pass only if body parses as well-formed XML. Use when response is expected as XML data                             |
| **ReportResponse** | `report_response` (bool)                                                                                | Include raw payload in finding for debugging.                             |

## 2. Multi-Step Revocation

Some APIs require a two-step revocation process:

1. **Step 1 (Lookup)**: Query the API to retrieve an internal ID, token identifier, or other metadata
2. **Step 2 (Delete)**: Use the extracted value(s) to perform the actual revocation/deletion

Kingfisher supports up to 2 sequential steps in a revocation workflow. Each step can extract values from its response, making them available as variables in subsequent steps.

### Response Extractors

Values can be extracted from HTTP responses using the following methods:

| Extractor Type | Description | Example |
|----------------|-------------|---------|
| **JsonPath** | Extract from JSON response using JSONPath syntax | `$.data.id`, `$.items[0].token_id` |
| **Regex** | Extract using regex with a capture group | `"token_id":\s*"([^"]+)"` |
| **Header** | Extract an HTTP response header value | `X-Token-ID` |
| **Body** | Use the entire response body as-is | - |
| **StatusCode** | Extract the HTTP status code as a string | - |

### Multi-Step Revocation Schema

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      - name: <step_name>              # Optional: human-readable step name
        request:                       # Standard HTTP request configuration
          method: GET|POST|DELETE|...
          url: https://api.example.com/...
          headers:
            Header-Name: "value"
          body: "optional request body"
          response_matcher:            # Required for final step only
            - type: StatusMatch
              status: [200]
        extract:                       # Optional: extract variables from response
          VARIABLE_NAME:               # Variable name (uppercase recommended)
            type: JsonPath|Regex|Header|Body|StatusCode
            path: "$.path.to.value"    # For JsonPath
            pattern: "regex pattern"   # For Regex (use first capture group)
            name: "header-name"        # For Header
      
      - name: <next_step>              # Subsequent steps can use extracted variables
        request:
          method: DELETE
          url: https://api.example.com/tokens/{{ VARIABLE_NAME }}
          response_matcher:
            - type: StatusMatch
              status: [204]
```

### Multi-Step Revocation Requirements

- **Minimum 1, Maximum 2 steps**: You must define at least 1 step and no more than 2 steps
- **Final step requires response_matcher**: The last step must include a `response_matcher` to determine success/failure
- **Intermediate steps are optional**: Earlier steps don't require response matchers but can have them for validation
- **Variables flow forward**: Variables extracted in step 1 are available in step 2 via Liquid templates (e.g., `{{ TOKEN_ID }}`)
- **All standard Liquid filters apply**: You can use filters on extracted variables just like with `{{ TOKEN }}`

### Example 1: Basic Two-Step Revocation

This example shows a service that requires looking up a token's ID before deletion:

```yaml
rules:
  - name: Example Service Token
    id: kingfisher.example.1
    pattern: |
      (?xi)
      example_token_
      [A-Za-z0-9]{32}
    min_entropy: 3.5
    examples:
      - example_token_abc123def456ghi789jkl012mno345
    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://api.example.com/v1/auth/verify
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
    revocation:
      type: HttpMultiStep
      content:
        steps:
          # Step 1: Look up the token ID
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
          
          # Step 2: Delete the token using the ID
          - name: delete_token
            request:
              method: DELETE
              url: https://api.example.com/v1/tokens/{{ TOKEN_ID }}
              headers:
                Authorization: "Bearer {{ TOKEN }}"
              response_matcher:
                - report_response: true
                - type: StatusMatch
                  status: [204]
```

### Example 2: Using Multiple Extraction Methods

This example demonstrates extracting values using different methods:

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      # Step 1: Get metadata from multiple sources
      - name: get_token_metadata
        request:
          method: GET
          url: https://api.service.com/tokens/info
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:
          # Extract from JSON body
          TOKEN_ID:
            type: JsonPath
            path: "$.id"
          
          # Extract from response header
          ACCOUNT_ID:
            type: Header
            name: X-Account-ID
          
          # Extract using regex
          TOKEN_TYPE:
            type: Regex
            pattern: '"type":\s*"([^"]+)"'
      
      # Step 2: Use all extracted values
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

### Example 3: Complex JSONPath Extraction

JSONPath supports nested objects and array indexing:

```yaml
extract:
  # Extract from nested object
  USER_ID:
    type: JsonPath
    path: "$.data.user.id"
  
  # Extract from array (first element)
  FIRST_TOKEN_ID:
    type: JsonPath
    path: "$.tokens[0].id"
  
  # Extract from nested array
  SESSION_ID:
    type: JsonPath
    path: "$.data.sessions[0].session_id"
```

### Example 4: Single-Step Migration Path

Existing single-step revocations remain unchanged and continue to work:

```yaml
# This continues to work as before
revocation:
  type: Http
  content:
    request:
      method: DELETE
      url: https://api.service.com/tokens/revoke
      headers:
        Authorization: "Bearer {{ TOKEN }}"
      response_matcher:
        - type: StatusMatch
          status: [204]
```

### When to Use Multi-Step Revocation

Use multi-step revocation when:

- **The API requires looking up an ID first**: Some services don't accept the token directly for revocation
- **You need metadata from the token**: The revocation endpoint requires additional information only available via a separate API call
- **The service uses indirect revocation**: The token must be associated with another resource (session, key, credential) that needs to be identified first

Do NOT use multi-step revocation when:

- **The API accepts the token directly**: Use the simpler single-step `Http` revocation
- **You need more than 2 steps**: Kingfisher supports a maximum of 2 steps
- **The service provides a native revocation method**: Use `AWS` or `GCP` types when applicable

## 3. Templating with Liquid
Kingfisher leverages the Liquid template engine for dynamic parts of HTTP request bodies, headers, query parameters, and multipart payloads. The engine supports both built-in and custom filters to manipulate the captured secret (TOKEN) or other named captures ({{ NAME }}).

### Using Liquid Filters in Validation and Revocation
- **Capture Injection**: The unnamed capture from your regex becomes {{ TOKEN }}. Named captures are made available as uppercase variables (e.g. {{ RDMVAL }}).
- **Filter Pipeline**: You can chain filters using the pipe (|) syntax:

```liquid
{{ TOKEN | b64enc | url_encode }}
```
Arguments: Some filters accept parameters, provided after a colon:

```liquid
{{ TOKEN | hmac_sha256: "my-secret-key" }}
```

### Built-in & Custom Liquid Filters

Below is the complete list of Liquid filters available in Kingfisher, along with their usage patterns and examples.

| Filter                | Parameters                                   | Description                                                                                                    | Example                                                             |
| --------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `b64enc`              | –                                            | Base64-encodes the input using the standard alphabet.                                                          | `{{ TOKEN \| b64enc }}`                                              |
| `b64url_enc`          | –                                            | URL-safe Base64 (no padding). Useful for JWT headers & payloads.                                               | `{{ TOKEN \| b64url_enc }}`                                          |
| `b64dec`              | –                                            | Decodes a Base64 string.                                                                                        | `{{ "aGVsbG8=" \| b64dec }}`                                         |
| `b64url_dec`          | –                                            | Decodes a URL-safe Base64 string (with or without padding).                                                     | `{{ "Kys_Pw" \| b64url_dec }}`                                       |
| `sha256`              | –                                            | Computes the SHA-256 hex digest of the input.                                                                  | `{{ TOKEN \| sha256 }}`                                              |
| `crc32`               | –                                            | Computes the CRC32 checksum of the input and returns a decimal value. | `{{ TOKEN \| crc32 }}` |
| `crc32_dec`           | `digits` (integer, optional)                 | Computes the CRC32 checksum and returns the last `digits` decimal characters (zero-padded). Defaults to the full value when omitted. | `{{ TOKEN \| crc32_dec: 6 }}` |
| `crc32_hex`           | `digits` (integer, optional)                 | Computes the CRC32 checksum and returns the last `digits` hexadecimal characters (zero-padded). Defaults to the full value when omitted. | `{{ TOKEN \| crc32_hex: 8 }}` |
| `crc32_le_b64`        | `len` (integer, optional)                    | Computes the CRC32 checksum, encodes the little-endian bytes using Base64, and optionally truncates to the first `len` characters. | `{{ TOKEN \| crc32_le_b64: 6 }}` |
| `hmac_sha1`           | `key` (string)                               | Computes HMAC-SHA1 over the input, returns Base64-encoded result.                                              | `{{ TOKEN \| hmac_sha1: "secret-key" }}`                             |
| `hmac_sha256`         | `key` (string)                               | Computes HMAC-SHA256 over the input, returns Base64-encoded result.                                            | `{{ TOKEN \| hmac_sha256: "secret-key" }}`                           |
| `hmac_sha384`         | `key` (string)                               | Computes HMAC-SHA384 over the input, returns Base64-encoded result.                                            | `{{ TOKEN \| hmac_sha384: "secret-key" }}`                           |
| `hmac_sha384_hex`     | `key` (string)                               | Computes HMAC-SHA384 over the input, returns lowercase hexadecimal output.                                     | `{{ TOKEN \| hmac_sha384_hex: "secret-key" }}`                       |
| `hmac_sha256_b64key`  | `key` (string, base64-encoded)               | Decodes the key from Base64 to raw bytes, then computes HMAC-SHA256. Returns Base64. Use for Azure SAS and other protocols where the signing key is base64-encoded. | `{{ to_sign \| hmac_sha256_b64key: TOKEN }}`                         |
| `random_string`       | `len` (integer, optional)                    | Generates a cryptographically-secure random alphanumeric string of the specified length (default: 32).        | `{{ "" \| random_string: 16 }}`                                      |
| `prefix`              | `len` (integer, optional)                    | Returns the first `len` characters from the string (default: full).                                            | `{{ TOKEN \| prefix: 6 }}`                                           |
| `suffix`              | `len` (integer, optional)                    | Returns the last `len` characters from the string (default: full).                                             | `{{ TOKEN \| suffix: 6 }}`                                           |
| `base62`              | `width` (integer, optional)                  | Encodes the input number as Base62, left-padding with zeros as needed.                                         | `{{ TOKEN \| crc32 \| base62: 6 }}`                                  |
| `url_encode`          | –                                            | Percent-encodes the input according to RFC 3986.                                                                | `{{ TOKEN \| url_encode }}`                                          |
| `json_escape`         | –                                            | Escapes special characters so a string can be safely injected into JSON contexts.                              | `{{ TOKEN \| json_escape }}`                                         |
| `unix_timestamp`      | –                                            | Returns the current Unix epoch time in seconds (UTC).                                                          | `{{ "" \| unix_timestamp }}`                                         |
| `unix_timestamp_ms`   | –                                            | Returns the current Unix epoch time in milliseconds (UTC).                                                     | `{{ "" \| unix_timestamp_ms }}`                                      |
| `iso_timestamp`       | –                                            | Returns the current UTC timestamp in full ISO-8601 format (may include fractional seconds).                    | `{{ "" \| iso_timestamp }}`                                          |
| `iso_timestamp_no_frac` | –                                          | Current ISO-8601 timestamp (UTC) **without** fractional seconds.                                               | `{{ "" \| iso_timestamp_no_frac }}`                                  |
| `rfc1123_date`        | –                                            | Returns the current RFC-1123 timestamp in GMT.                                                                 | `{{ "" \| rfc1123_date }}`                                           |
| `uuid`                | –                                            | Generates a random UUIDv4 string.                                                                              | `{{ "" \| uuid }}`                                                   |
| `jwt_header`          | –                                            | Builds a minimal JWT header JSON (`{"typ":"JWT","alg":…}`) and Base64URL-encodes it.                           | `{{ "HS256" \| jwt_header }}`                                        |
| `replace`             | `from` (string), `to` (string)               | Replaces every occurrence of `from` with `to` in the input string.                                             | `{{ "hello world" \| replace: "world", "mars" }}`                    |
| `newline`             | –                                            | Returns a single newline character (`\n`). Useful inside YAML block scalars where a literal newline would break indentation. | `{{ "" \| newline }}`                                                |
| `base36`              | `width` (integer, optional)                  | Encodes the input number as Base36, left-padding with zeros as needed.                                         | `{{ TOKEN \| crc32 \| base36: 6 }}`                                  |


**Chaining & Composition:** Filters can be stacked; e.g.:

```liquid
Authorization: Basic {{ "api:" | append: TOKEN | b64enc }}
```

**Runtime Values:** Filters like unix_timestamp and uuid are evaluated at runtime, enabling nonces, timestamps, and unique IDs in your requests.

**Stable Request Values:** HTTP and gRPC validation requests also expose stable per-request template variables. Use these when the same generated value must appear in multiple places within one request. Currently:
- `REQUEST_RFC1123_DATE`
- `REQUEST_UNIX_MILLIS`

### How depends_on_rule Works

- **Dependency Declaration:**  
  In your YAML rule definition, you add a `depends_on_rule` section. Here you specify:
  - **rule_id:** The identifier of the rule whose output is required.
  - **variable:** The name (typically in uppercase) that will be used to reference the captured value from the dependency rule.

- **Chaining Captures:**  
  When Kingfisher scans a file, it processes rules in a specific order. If a rule has a dependency, the engine first checks whether the dependent rule has already matched on the same input (or blob). If it did, the captured value (for example, an access key ID) is made available to the dependent rule.

- **Using the Captured Value:**  
  This captured value can then be used during the validation phase. For instance, if you have a rule for an Algolia Admin API Key that depends on an Algolia Application ID (captured as `APPID`), the validation logic can incorporate the `APPID` value to confirm that the secret matches the expected pattern or format for that specific account.

- **Detection vs validation:**  
  `depends_on_rule` is for capture chaining and validation context. It does not automatically hide the main secret finding, and it does not by itself mean the rule must be parser-verified before it can be reported from raw text.

### Use depends_on_rule to require one rule before another runs:

```yaml
depends_on_rule:
  - rule_id: kingfisher.algolia.app_id   # must match first
    variable: APPID                     # captured as {{ APPID }}
```

- **Capture flow**: First rule captures `APPID` → second rule injects `{{ APPID }}` into validation HTTP request or pattern
- **Visible control:** set `visible: false` on the supporting rule so it doesn’t clutter your report for non-secret matches
- **Primary secret rule:** leave the secret rule visible unless it is also only a helper; helper rules should usually be the ones marked `visible: false`
## Algolia Example

Consider this example rule for an Algolia Application ID and Admin Key combination. To validate that this is an active credential, both must be matched:

```yaml
rules:
  - name: Algolia Admin API Key
    id: kingfisher.algolia.1
    pattern: |
      (?xi)
      algolia
      (?:.|[\n\r]){0,32}?
      \b
      (
        [a-z0-9]{32}
      )
      \b
    min_entropy: 3.5
    confidence: medium
    examples:
      - algolia_api_key = "ij1mut5oe606wlrf5z4u8u31264z3gag"
    validation:
      type: Http
      content:
        request:
          headers:
            X-Algolia-API-Key: '{{ TOKEN }}'
            X-Algolia-Application-Id: '{{ APPID }}'
          method: GET
          response_matcher:
            - report_response: true
            - status:
                - 200
              type: StatusMatch
          url: https://{{ APPID }}-dsn.algolia.net/1/keys
    depends_on_rule:
      - rule_id: "kingfisher.algolia.2"
        variable: APPID
  
  - name: Algolia Application ID
    id: kingfisher.algolia.2
    pattern: |
      (?xi)
      algolia
      (?:.|[\n\r]){0,16}?
      \b
      (
        [A-Z0-9]{10}
      )
      \b               
    min_entropy: 3.5
    visible: false
    confidence: medium
    examples:
      - algolia_app_id = "WRB8YLFW7Y"

```

### How It Works:

* Algolia Application ID Rule (kingfisher.algolia.2):

  This rule scans for an Algolia Application ID—a 10-character alphanumeric string. It is marked with visible: false so that even if it matches, the finding is not directly reported. Its primary role is to provide a supporting value for other rules rather than to be flagged as a secret by itself.

* Algolia Admin API Key Rule (kingfisher.algolia.1):
  This rule detects the Algolia Admin API Key using a regex pattern. It includes a depends_on_rule property that specifies a dependency on the Algolia Application ID rule.

  * The dependency declares that the rule requires the output of the Algolia Application ID rule, and the captured value is assigned to the variable APPID.
  * In the validation section, this captured `APPID` is used dynamically in the HTTP request (for example, in the header `X-Algolia-Application-Id` and in the URL).

The dependency mechanism (depends_on_rule) ensures that:

* Non-secret data (like an application ID) is captured without cluttering the scan report (thanks to visible: false).
* The secret (the API key) is validated in context, with the necessary supporting information automatically injected.
* Rules remain modular and extensible; you can update the dependent rule or its pattern independently, and the change will automatically be reflected where the value is used.

## The `visible: false` Property

The `visible: false` property tells Kingfisher to hide the finding from the final scan report. This is particularly useful for rules that capture data not meant to be reported as a secret, but rather to serve as supporting context for another rule.

For example, a rule might match a username, an email address, an AWS Access Key ID, or an Application ID. While these pieces of information are captured during scanning, they are not secrets on their own. Instead, they are used by other rules—via the `depends_on_rule` mechanism—to validate an associated secret. By marking such rules as `visible: false`, you prevent these non-secret findings from cluttering your report, yet their values remain available for dependent rules.

`visible: false` helps keep the scan output focused on actual secrets while still capturing important contextual data needed for comprehensive validation.

## Character Requirements

The `pattern_requirements` field allows you to specify data type requirements for matched secrets. This is particularly useful when:

- Your regex pattern must be permissive (due to Hyperscan limitations)
- You want to enforce password complexity requirements
- You need to filter out low-quality matches that lack certain character types

Kingfisher's regex engine (Hyperscan) does not support lookahead assertions like `(?=.*\d)` to require specific character types. Instead, use the `pattern_requirements` field to filter matches post-detection.

### Available Requirements

```yaml
pattern_requirements:
  min_digits: 1              # Require at least 1 digit (0-9)
  min_uppercase: 1           # Require at least 1 uppercase letter (A-Z)
  min_lowercase: 1           # Require at least 1 lowercase letter (a-z)
  min_special_chars: 1       # Require at least 1 special character
  special_chars: "!@#$%^&*"  # Optional: define which characters are "special"
  ignore_if_contains:             # Optional: reject matches containing any of these (case-insensitive)
    - test
    - demo
  checksum:                      # Optional: compare rendered values to drop mismatched formats
    actual:
      template: "{{ MATCH | suffix: 6 }}"   # Liquid template for the observed checksum
      requires_capture: checksum            # (optional) skip unless this capture is present
    expected: "{{ BODY | crc32 | base62: 6 }}"  # Liquid template to render the expected checksum
    skip_if_missing: true                   # (optional) treat missing captures as legacy tokens
```

All fields are optional. If `special_chars` is not specified, the default set includes: `!@#$%^&*()_+-=[]{}|;:'",.<>?/\`~`

`ignore_if_contains` performs a case-insensitive substring check. If any entry (after trimming whitespace) appears within the match, the match is discarded. This is helpful for dropping known dummy tokens such as "test" or "demo" that otherwise satisfy the regex.

The optional `checksum` block renders Liquid templates against the match to determine whether the captured checksum matches your expectation. Both templates gain access to `{{ MATCH }}`, `{{ FULL_MATCH }}`, and every named capture in two forms: the original capture name and its uppercase alias (e.g. `{{ body }}` and `{{ BODY }}`). Use helper filters like `suffix`, `crc32`, and `base62` to mirror provider-specific checksum pipelines. If a required capture is missing or the rendered values differ, Kingfisher skips the finding—logging the reason, including checksum lengths, at the `DEBUG` level. Set `skip_if_missing` to `true` to treat absent captures as legacy matches.

When any of these filters remove a match it is logged at the `DEBUG` level so you can see exactly why the skip occurred. If you need to keep every match even when one of these substrings appears, pass `--no-ignore-if-contains` to `kingfisher scan`. The flag disables this post-processing step without changing the rule definitions.

### Are `requires_capture` and `skip_if_missing` equivalent?

`requires_capture`
 - Optional field that names a specific regex capture that must be present before the checksum templates are evaluated.
 - In the engine, Kingfisher checks whether that capture exists in the match context. If it’s missing, the behavior falls back to whatever `skip_if_missing` dictates (fail or treat as a legacy match).

`skip_if_missing`
 - Boolean switch that controls what happens when Kingfisher can’t render the checksum—because there’s no match context or a required capture is absent.
  - `true`: silently skip (pass) the match so legacy, non-checksum tokens are still accepted.
  -  `false`: treat the situation as a validation failure.

In short, `requires_capture` identifies which capture must exist, while `skip_if_missing` determines whether missing data is a hard failure or an allowed legacy case.

### Example: Secure API Key

```yaml
rules:
  - name: Secure API Key
    id: custom.secure_api.1
    pattern: |
      (?xi)
      api[_-]?key
      (?:.|[\n\r]){0,32}?
      \b
      ([A-Za-z0-9!@#$%^&*]{20,})
      \b
    min_entropy: 4.0
    confidence: high
    pattern_requirements:
      min_digits: 1           # Must contain at least 1 digit
      min_uppercase: 1        # Must contain at least 1 uppercase letter
      min_lowercase: 1        # Must contain at least 1 lowercase letter
      min_special_chars: 1    # Must contain at least 1 special character
      ignore_if_contains:
        - test
    examples:
      - api_key = "MyS3cur3K3y!2024"
      - 'api-key: "Abc123!@#Token"'
```

In this example:
- The regex pattern is permissive: `[A-Za-z0-9!@#$%^&*]{20,}` matches any combination of those characters
- The `pattern_requirements` filters out matches that don't have at least one of each required type
- A match like `"abcdefghijklmnopqrst"` would be rejected (no uppercase, no digit, no special)
- A match like `"Abc123!SecureToken"` would be accepted (has all required types)
- A match like `"Test123!SecureToken"` would be rejected because it contains the `ignore_if_contains` term `test`

### Example: Excluding Dummy Values

```yaml
rules:
  - name: Token without placeholders
    id: custom.token.2
    pattern: |-
      (?i)token[:=]\s*([A-Za-z0-9]{12,})
    pattern_requirements:
      ignore_if_contains:
        - placeholder
        - sample
    examples:
      - token: "REALVALUE1234"
```

### Example: Custom Special Characters

```yaml
rules:
  - name: Token with Custom Special Chars
    id: custom.token.1
    pattern: |
      (?xi)
      token
      (?:.|[\n\r]){0,16}?
      \b([A-Za-z0-9$%^]{16,})\b
    min_entropy: 3.5
    confidence: medium
    pattern_requirements:
      min_special_chars: 2
      special_chars: "$%^"    # Only these characters count as "special"
    examples:
      - token = "abc$%defgh123456"
```

### How It Works

1. Hyperscan regex matches a pattern in the input
2. Entropy check filters low-complexity matches (if `min_entropy` is set)
3. **Character requirements check filters matches that don't meet the criteria**
4. Validation checks verify the secret is live (if `validation` is configured)

Matches that fail the character requirements check are silently dropped with a debug log message.


## Writing Custom Rules

When writing custom rules, consider the following best practices:

1. **Multi-line Regex:** Write your regex patterns over multiple lines for clarity. Use the `(?x)` flag to enable free-spacing mode.
2. **Optimize for Performance:** Structure your regex to minimize backtracking. Use non-capturing groups where possible and keep the pattern as concise as possible.
3. **Validation Integration:** Define a `validation` section if you want to verify the detected secret. Prefer `Http` or `Grpc`; use an existing typed validator when the rule matches a supported validator family; use `Raw` only for rare provider-specific exception paths. You can use Liquid templating to insert dynamic values where supported. Use the unnamed capture as `TOKEN` and any named captures in uppercase.
4. **Revocation Integration:** Define a `revocation` section if you want to revoke a detected secret. It uses the same HTTP request format and template variables as `validation`.
5. **Test with Examples:** Always include examples that should match and, optionally, negative examples to ensure your rule behaves as expected.

## Examples

Below are some examples to guide you in writing custom rules

### Anthropic API Key

```yaml
rules:
  - name: Anthropic API Key
    id: kingfisher.anthropic.1
    pattern: |
      (?xi)                    
      \b                       
      (                        
        sk-ant-api
        \d{2,4}
        -
        [\w\-]{93}
        AA
      )                        
      \b                       
    min_entropy: 3.3
    confidence: medium
    examples:
      - sk-ant-api668-Clm512odot9WDD7itfUU9R880nefA1EtYZDbpE-C9b0XQEWpqFKf9DQUo03vOfXl16oSmyar1CLF1SzV3YzpZJ6bahcpLAA
    categories:
      - api
      - secret
    references:
      - https://docs.anthropic.com/claude/reference/authentication
    validation:
      type: Http
      content:
        request:
          body: |
            {
              "model": "claude-3-haiku-20240307",
              "max_tokens": 1024,
              "messages": [
                {"role": "user", "content": "respond only with 'success'"}
              ]
            }
          headers:
            Content-Type: application/json
            anthropic-version: "2023-06-01"
            x-api-key: '{{ TOKEN }}'
          method: POST
          response_matcher:
            - report_response: true
            - status:
                - 200
              type: StatusMatch
            - report_response: true
            - type: WordMatch
              words:
                - '"type":"invalid_request_error"'
          url: https://api.anthropic.com/v1/messages
```

### FileIO Secret Key
```yaml
rules:
  - name: FileIO Secret Key
    id: kingfisher.fileio.1
    pattern: |
      (?xi)
      \b
      fileio
      (?:.|[\n\r]){0,32}?
      (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)
      (?:.|[\n\r]){0,16}?
      \b
      (
        [A-Z0-9]{16}
        (?:\.[A-Z0-9]{7}){2}
        \.[A-Z0-9]{8}
      )
      \b
    min_entropy: 3.3
    confidence: medium
    examples:
      - fileio SECRETKEY = Z9Y8X7W6V5U4T3S2R1Q0.P9O8N7M6L5K4J3H2G1F
      - fileio.PRIVATE.TOKEN = F0E1D2C3B4A596877869.5E4D3C2B1A0Z9Y8X7W6V
      - fileio_key = M8N6B4V2C0X9Z7L5K3J1.H2G4F6D8S0A9P7O5I3U1
    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://file.io/api/v2/account
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [200]
            - type: HeaderMatch
              header: content-type
              expected: ["application/json"]
            - type: JsonValid

```

## Advanced Example

This advanced example uses the liquid-rs filters included with Kingfisher to sign requests that validate Alibaba Cloud long-lived and STS temporary credential pairs:

```yaml
rules:
  - name: Alibaba Access Key ID
    id: kingfisher.alibabacloud.1
    pattern: |
      (?x)
      \b
      (
        LTAI[A-Za-z0-9]{17,21}
      )
      \b
    pattern_requirements:
      min_digits: 2
      min_uppercase: 1
      min_lowercase: 1
    min_entropy: 4.0
    confidence: medium
    visible: false
    examples:
      - LTAI8x2NiGqfyJGx7eLDhp12
      - LTAI5GqyJGhp12ad31L5hpix
  - name: Alibaba Access Key Secret
    id: kingfisher.alibabacloud.2
    pattern: |
      (?x)
      \b
      (?:
        (?i:alibaba|alibaba[\s_-]*cloud|aliyun)
        |
        LTAI[A-Za-z0-9]{17,21}
      )
      (?:.|[\n\r]){0,80}?
      (?i:access[\s_-]*key[\s_-]*secret|access[\s_-]*secret|secret|token|key)
      (?:.|[\n\r]){0,16}?
      (?:
        [=:]
        |
        ["']\s*:\s*["']
      )
      \s*
      ["']?
      (
        [A-Za-z0-9]{30}
      )
      \b
      ["']?
    min_entropy: 4.2
    confidence: medium
    examples:
      - alibaba_secret = 7jkWdTjKLnSlGddwPR5gBn65PHcZG6
      - alibaba-token = aJHKLnSlGddwPR5g7jkWdTBn65PHc5
      - AccessKeyId=LTAI8x2NiGqfyJGx7eLDhp12 AccessKeySecret=7jkWdTjKLnSlGddwPR5gBn65PHcZG6
    validation:
      type: Http
      content:
        request:
          method: GET
          url: >
            {%- assign nonce = "" | uuid | upcase -%}
            {%- assign raw_timestamp = "" | iso_timestamp_no_frac -%}
            {%- assign timestamp = raw_timestamp | replace: ":", "%3A" -%}

            {%- capture params -%}
            AccessKeyId={{ AKID | url_encode }}&Action=GetCallerIdentity&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce={{ nonce }}&SignatureVersion=1.0&Timestamp={{ timestamp }}&Version=2015-04-01
            {%- endcapture -%}
            {%- assign encoded_params = params | replace: "+", "%20" | replace: "*", "%2A" | replace: "%7E", "~" -%}
            {%- assign query_string = encoded_params | url_encode | replace: "%2D", "-" | replace: "%2E", "." -%}
            
            {%- assign signature_base_string = "GET&%2F&" | append: query_string -%}
            {%- assign token_amp = TOKEN | append: "&" -%}

            {%- assign hmacsignature = signature_base_string | hmac_sha1: token_amp | url_encode -%}

            https://sts.aliyuncs.com/?{{ params }}&Signature={{ hmacsignature }}
          headers:
            Accept: application/json
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: ['"Arn"']
    depends_on_rule:
      - rule_id: kingfisher.alibabacloud.1
        variable: AKID
  - name: Alibaba STS Access Key ID
    id: kingfisher.alibabacloud.3
    pattern: |
      (?x)
      \b
      (
        STS\.[A-Za-z0-9]{16,64}
      )
      \b
    min_entropy: 3.0
    confidence: medium
    visible: false
    examples:
      - STS.NTKaenSkmLhG4HpM576UV
      - STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE
  - name: Alibaba STS Security Token
    id: kingfisher.alibabacloud.4
    pattern: |
      (?xi)
      \b
      (?:security[\s_-]*token|sts[\s_-]*token|x[\s_-]*oss[\s_-]*security[\s_-]*token|alibaba[\s_-]*cloud[\s_-]*security[\s_-]*token|aliyun[\s_-]*security[\s_-]*token)
      (?:.|[\n\r]){0,16}?
      (?:
        [=:]
        |
        ["']\s*:\s*["']
      )
      \s*
      ["']?
      (
        CAIS[A-Za-z0-9+/_=-]{20,1024}
      )
      (?:["'\s,;}&\]]|$)
    min_entropy: 4.0
    confidence: medium
    visible: false
    examples:
      - securityToken = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"
      - ALIBABA_CLOUD_SECURITY_TOKEN=CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA
  - name: Alibaba STS Access Key Secret
    id: kingfisher.alibabacloud.5
    pattern: |
      (?x)
      \b
      (?:
        (?i:alibaba|alibaba[\s_-]*cloud|aliyun|sts)
        |
        STS\.[A-Za-z0-9]{16,64}
      )
      (?:.|[\n\r]){0,120}?
      (?i:access[\s_-]*key[\s_-]*secret|access[\s_-]*secret)
      (?:.|[\n\r]){0,16}?
      (?:
        [=:]
        |
        ["']\s*:\s*["']
      )
      \s*
      ["']?
      (
        [A-Za-z0-9]{30,64}
      )
      \b
      ["']?
    min_entropy: 4.2
    confidence: medium
    examples:
      - STS.NTKaenSkmLhG4HpM576UV AccessKeySecret=wyLTSmsyPGP1ohvvw8xYgB29dlGI8KMiH2pK
      - "aliyun sts access_key_secret: 6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62"
    validation:
      type: Http
      content:
        request:
          method: GET
          url: >
            {%- assign nonce = "" | uuid | upcase -%}
            {%- assign raw_timestamp = "" | iso_timestamp_no_frac -%}
            {%- assign timestamp = raw_timestamp | replace: ":", "%3A" -%}

            {%- capture params -%}
            AccessKeyId={{ STS_AKID | url_encode }}&Action=GetCallerIdentity&Format=JSON&SecurityToken={{ SECURITY_TOKEN | url_encode }}&SignatureMethod=HMAC-SHA1&SignatureNonce={{ nonce }}&SignatureVersion=1.0&Timestamp={{ timestamp }}&Version=2015-04-01
            {%- endcapture -%}
            {%- assign encoded_params = params | replace: "+", "%20" | replace: "*", "%2A" | replace: "%7E", "~" -%}
            {%- assign query_string = encoded_params | url_encode | replace: "%2D", "-" | replace: "%2E", "." -%}

            {%- assign signature_base_string = "GET&%2F&" | append: query_string -%}
            {%- assign token_amp = TOKEN | append: "&" -%}

            {%- assign hmacsignature = signature_base_string | hmac_sha1: token_amp | url_encode -%}

            https://sts.aliyuncs.com/?{{ params }}&Signature={{ hmacsignature }}
          headers:
            Accept: application/json
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: ['"Arn"']
    depends_on_rule:
      - rule_id: kingfisher.alibabacloud.3
        variable: STS_AKID
      - rule_id: kingfisher.alibabacloud.4
        variable: SECURITY_TOKEN
```
