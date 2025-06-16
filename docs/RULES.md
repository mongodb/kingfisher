# Writing Custom Rules for Kingfisher

A _rule_ in Kingfisher is a YAML document that describes how to detect and (optionally) validate secrets in your codebase. With custom rules you can:

- **Extend** Kingfisher without touching Rust code  
- **Tune** sensitivity via entropy and confidence  
- **Plug in** live checks against external services  

This document explains how to write custom rules for Kingfisher using a YAML-based rule system. The rules define regular expressions to detect secrets in source code and other textual data, and they can include validation steps to confirm the secret's authenticity. By using a rules-based system, Kingfisher is highly extensible—new rules can be added or existing ones modified without changing the core code. This approach also makes it possible to leverage Large Language Models (LLMs) to generate or refine rules based on sample inputs.

## Use an LLM (ChatGPT, Gemini, Claude, etc) to Write a Kingfisher Rule

You can use an LLM (eg ChatGPT, Gemini, Claude, etc) to help generate Kingfisher rules.

See [docs/LLM_PROMPT_RULES.md](LLM_PROMPT_RULES.md) for full detail.
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

    validation:                     # (optional) live validation
      type: Http
      content:
        request:
          method: GET
          url: https://api.example.com/v1/check
          headers:
            X-Secret: "{{ TOKEN }}"
            X-Id:     "{{ AKID }}"
          response_is_html: true # be default, validation responses containing HTML or considered invalid. Set to `true` if you expect HTML returned from a validation response
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
```

| Field             | What it does                                                         |
| ----------------- | -------------------------------------------------------------------- |
| name              | Friendly name shown in reports                                       |
| id                | Unique text ID (namespace.v#) used internally                        |
| pattern           | Regex used to spot secrets (free‑spacing & flags allowed)            |
| min_entropy       | Threshold to guard against low‑complexity false positives            |
| confidence        | Suggests severity: low → high                                        |
| examples          | Good matches; used for testing                                       |
| visible           | false to hide non‑secret captures (e.g. IDs)                         |
| depends_on_rule   | Chain rules: use captures from one rule in another’s validation      |
| validation        | Configure HTTP, AWS, GCP, etc. checks to verify live validity        |


*responser_matcher* variants. Multiple can be used
| Variant         | Required keys                                                                                              | Behavior                                                                |
|-----------------|-------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **StatusMatch** | `status` (list\<int>)<br>`negative` (bool, default `false`)                                                 | Pass when codes match (or don’t match if `negative`).                     |
| **WordMatch**   | `words` (list\<string>)<br>`match_all_words` (bool)<br>`negative` (bool)                                    | Word/substring checks in body.                                            |
| **HeaderMatch** | `header` (string)<br>`expected` (list\<string>)<br>`match_all_values` (bool)                                | Header value assertions.                                                  |
| **JsonValid**   | –                                                                                                           | Pass only if body parses as JSON. Use when response is expected as JSON data                                       |
| **XmlValid**    | –                                                                                                           | Pass only if body parses as well-formed XML. Use when response is expected as XML data                             |
| **ReportResponse** | `report_response` (bool)                                                                                | Include raw payload in finding for debugging.                             |


### How depends_on_rule Works

- **Dependency Declaration:**  
  In your YAML rule definition, you add a `depends_on_rule` section. Here you specify:
  - **rule_id:** The identifier of the rule whose output is required.
  - **variable:** The name (typically in uppercase) that will be used to reference the captured value from the dependency rule.

- **Chaining Captures:**  
  When Kingfisher scans a file, it processes rules in a specific order. If a rule has a dependency, the engine first checks whether the dependent rule has already matched on the same input (or blob). If it did, the captured value (for example, an access key ID) is made available to the dependent rule.

- **Using the Captured Value:**  
  This captured value can then be used during the validation phase. For instance, if you have a rule for an Algolia Admin API Key that depends on an Algolia Application ID (captured as `APPID`), the validation logic can incorporate the `APPID` value to confirm that the secret matches the expected pattern or format for that specific account.

### Use depends_on_rule to require one rule before another runs:

```yaml
depends_on_rule:
  - rule_id: kingfisher.algolia.app_id   # must match first
    variable: APPID                     # captured as {{ APPID }}
```

- **Capture flow**: First rule captures `APPID` → second rule injects `{{ APPID }}` into validation HTTP request or pattern
- **Visible control:** set `visible: false` on the supporting rule so it doesn’t clutter your report for non-secret matches
## Algolia Example

Consider this example rule for an Algolia Application ID and Admin Key combination. To validate that this is an active credential, both must be matched:

```yaml
rules:
  - name: Algolia Admin API Key
    id: kingfisher.algolia.1
    pattern: |
      (?x)
      (?i)
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
      (?x)                    
      (?i)
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


## Writing Custom Rules

When writing custom rules, consider the following best practices:

1. **Multi-line Regex:** Write your regex patterns over multiple lines for clarity. Use the `(?x)` flag to enable free-spacing mode.
2. **Optimize for Performance:** Structure your regex to minimize backtracking. Use non-capturing groups where possible and keep the pattern as concise as possible.
3. **Validation Integration:** Define a `validation` section if you want to verify the detected secret. You can use Liquid templating to insert dynamic values—use the unnamed capture as `TOKEN` and any named captures in uppercase.
4. **Leverage LLMs:** Use Large Language Models to help generate or refine regex patterns based on sample inputs. LLMs can suggest efficient patterns that balance detection accuracy with performance. See ([docs/LLM_PROMPT_RULES.md](LLM_PROMPT_RULES.md))
5. **Test with Examples:** Always include examples that should match and, optionally, negative examples to ensure your rule behaves as expected.

## Examples

Below are some examples to guide you in writing custom rules

### Anthropic API Key

```yaml
rules:
  - name: Anthropic API Key
    id: kingfisher.anthropic.1
    pattern: |
      (?x)
      (?i)
      \b
      (
        sk-ant-api
        \d{2,4}
        -
        [\w\-]{93}
        AA
      )
      \b
    min_entropy: 4
    confidence: medium
    examples:
      - sk-ant-api668-Clm512odot9WDD7itfUU9R880nefA1EtYZDbpE-C9b0XQEWpqFKf9DQUo03vOfXl16oSmyar1CLF1SzV3YzpZJ6bahcpLAA
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

### Snyk API Key

```yaml
rules:
  - name: Snyk API Key
    id: kingfisher.snyk.1
    pattern: |
      (?x)
      (?i)
      \b
      snyk
      (?:.|[\\n\r]){0,32}?
      (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)
      (?:.|[\n\r]){0,32}?
      \b
      (
        [0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}
      )
    min_entropy: 3.0
    examples:
      - snyk=123e4567-e89b-12d3-a456-426614174000
      - snyk=123e4567-e89b-12d3-a456-426614174abc
    validation:
      type: Http
      content:
        request:
          headers:
            Authorization: token {{ TOKEN }}
          method: GET
          response_matcher:
            - report_response: true
            - match_all_words: true
              type: WordMatch
              words:
                - '"username":'
                - '"date":'
          url: https://snyk.io/api/v1/user/me
```
### FileIO Secret Key
```rules:
  - name: FileIO Secret Key
    id: kingfisher.fileio.1
    pattern: |
      (?xi)
      \b
      fileio
      (?:.|[\n\r]){0,32}?
      (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)
      (?:.|[\n\r]){0,32}?
      \b
      (
        [A-Z0-9.-]{39}
      )
    min_entropy: 3.3
    confidence: medium
    examples:
      - fileioSECRETKEY-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890
      - fileio.PRIVATE.TOKEN-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890
      - fileio_ACCESS-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890
    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://file.io/
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