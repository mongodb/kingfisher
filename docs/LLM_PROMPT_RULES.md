I'm using the vectorscan-rs crate for Rust, v0.0.5. I have a YAML based "rule" system which contains these regex patterns. Here are some examples:

```
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

and

```
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

and

```
rules:
  - name: MailGun Primary Key
    id: kingfisher.mailgun.2
    pattern: |
      (?x)
      (?i)
      \b
      mailgun
      (?:.|[\\n\r]){0,32}?
      (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)
      (?:.|[\n\r]){0,32}?
      \b
      (
        key-[a-z0-9]{32}
      )
      \b                  
    min_entropy: 3.5
    confidence: medium
    examples:
      - key-mailgun_token= key-ad13dfc23adf55fa404a91e76d96f472
    validation:
      type: Http
      content:
        request:
          headers:
            Authorization: 'Basic {{ "api:" | append: TOKEN | b64enc }}'
          method: GET
          response_matcher:
            - report_response: true
            - status:
                - 200
              type: StatusMatch
          url: https://api.mailgun.net/v3/domains
```

and

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

and 

```rules:
  - name: ReadMe API Key
    id: kingfisher.readme.1
    pattern: |
        (?x)
        (?i)
        \b
        (
            rdme_(?P<RDMVAL>[a-z0-9]{70})
        )
    min_entropy: 4
    confidence: medium
    examples:
      - rdme_utfzw17gd1g9e2vd2l55uazwhovsepbgtbh73gbhfz7p7ghxkimnc2n6qg4jvojja4wbpy
      - rdme_xn8s9he60fb31e9d290403d2707cce88fa820042d425fc6eb2baed4191dd88a5405987
    validation:
      type: Http
      content:
        request:
          headers:
            Authorization: "{{ TOKEN | b64enc }}"
            Content-Type: "application/json; charset=utf-8"
            Accept: application/json
          method: GET
          response_matcher:
            - report_response: true
            - status:
                - 200
              type: StatusMatch
          url: https://dash.readme.com/api/v1
```

and

```
rules:
  - name: AWS Access Key ID
    id: kingfisher.aws.1
    pattern: |
      (?x)                
      (?i)                
      \b                  
      (   
        (?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
        [0-9A-Z]{16}
      )
      \b                  
    min_entropy: 3.2
    confidence: medium
    visible: false
    examples:
      - ASIAOZW6VBVAZFJHJLQA
  - name: AWS Secret Access Key
    id: kingfisher.aws.2
    pattern: |
      (?x)
      (?i)
      \b
      (?:AWS|AMAZON|AMZN|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
      (?:.|[\n\r]){0,32}?
      (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)
      (?:.|[\n\r]){0,32}?
      \b
      (
        [A-Za-z0-9/+=]{40}
      )
      \b
    min_entropy: 3.0
    confidence: medium
    examples:
      - foo.backup.archive.aws.secretkey=sBmHlDFrNcsz35N+LRjwlUxF8/wypT4tiJCQ0wP4
      - '"awsSecretKey":"3lyTWqHMt5UySny2drdPYheRTEzrNux8Cn5JWFHL"'
      - '"\"awsSecretKey\":\"3lyTWqHMt5UySny2drdPYheRTEzrNux8Cn5JWFHL\"," +'
      - | 		
        "Whiteboard" : {
          "type" : "aws-s3",
          "config" : {
            "accessKeyId" : "AKIAIVOURJN3SXRRLZFQ",
            "region" : "us-east-1",
            "secretAccessKey" : "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"
          },
    validation:
      type: AWS
    depends_on_rule:
      - rule_id: kingfisher.aws.1
        variable: AKID
```

and

```rules:
  - name: PyPI Upload Token
    id: kingfisher.pypi.1
    pattern: |
      (?x)
      \b
      (
        pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}
      )
      (?:[^a-zA-Z0-9_-]|$)
    min_entropy: 4.0
    confidence: medium
    examples:
      - '# password = pypi-AgEIcHlwaS5vcmcCJDkwNzYwNzU1LW'
    validation:
      type: Http
      content:
        request:
          method: POST
          url: https://upload.pypi.org/legacy/
          response_matcher:
            - report_response: true
            - type: WordMatch
              words: 
                - "isn't allowed to upload to project"
          headers:
            Authorization: 'Basic {{ "__token__:" | append: TOKEN | b64enc }}'
          multipart:
            parts:
              - name: name
                type: text
                content: "my-package"
              - name: version
                type: text
                content: "0.0.1"
              - name: filetype
                type: text
                content: "sdist"
              - name: metadata_version
                type: text
                content: "2.1"
              - name: summary
                type: text
                content: "A simple example package"
              - name: home_page
                type: text
                content: "https://github.com/yourusername/my_package"
              - name: sha256_digest
                type: text
                content: "0447379dd46c4ca8b8992bda56d07b358d015efb9300e6e16f224f4536e71d64"
              - name: md5_digest
                type: text
                content: "9b4036ab91a71124ab9f1d32a518e2bb"
              - name: :action
                type: text
                content: "file_upload"
              - name: protocol_version
                type: text
                content: "1"
              - name: content
                type: file
                content: "path/to/my_package-0.0.1.tar.gz"
                content_type: "application/octet-stream"
```

Note that the captured value in the regular expression defined in `pattern` can be used in the validation. The unnamed capture should be used (case sensitive) as `TOKEN`. Any named captures can be used as well and they must also be uppercase.

Note the `validation` section. It is defined in Rust code as follows:

```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Validation {
    AWS,
    GCP,
    MongoDB,
    Postgres,
    PyPi,
    Raw(String),
    Http(HttpValidation),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct DependsOnRule {
    pub rule_id: String,
    pub variable: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct MultipartConfig {
    pub parts: Vec<MultipartPart>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct MultipartPart {
    pub name: String,
    #[serde(rename = "type")]
    pub part_type: String,
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
}


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpValidation {
    pub request: HttpRequest,
    pub multipart: Option<MultipartConfig>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub response_matcher: Vec<ResponseMatcher>,
    #[serde(default)]
    pub multipart: Option<MultipartConfig>,
    // allow HTML only when explicitly set true
    #[serde(default = "default_false")]
    pub response_is_html: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReportResponseData {
    #[serde(default = "default_true")]
    report_response: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(untagged)]
pub enum ResponseMatcher {
    WordMatch {
        r#type: String,
        words: Vec<String>,
        #[serde(default = "default_false")]
        match_all_words: bool,
        #[serde(default = "default_false")]
        negative: bool, // true = “fail if the pattern *does* appear”
    },
    StatusMatch {
        r#type: String,
        status: Vec<u16>,
        #[serde(default = "default_false")]
        match_all_status: bool,
        #[serde(default = "default_false")]
        negative: bool, // true = “fail if the status *does* match”
    },
    HeaderMatch {
        r#type: String,        // "HeaderMatch"
        header: String,        // e.g. "content-type"
        expected: Vec<String>, // one or more acceptable tokens
        #[serde(default = "default_false")]
        match_all_values: bool,
    },
    JsonValid {
        // "JsonValid"
        r#type: String,
    },
    XmlValid {
        // "XmlValid"
        r#type: String,
    },
    ReportResponse(ReportResponseData),
}

/// The syntactic representation of a rule.
#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
pub struct RuleSyntax {
    /// Human-readable name of the rule.
    pub name: String,
    /// Globally unique identifier for the rule.
    pub id: String,
    /// The regex pattern used by the rule.
    pub pattern: String,
    /// Minimum Shannon entropy required.
    #[serde(default)]
    pub min_entropy: f32,
    /// Confidence level of the rule.
    #[serde(default)]
    pub confidence: Confidence,
    /// Whether the rule is visible to end-users.
    #[serde(default = "default_true")]
    pub visible: bool,
    /// Example inputs that should match.
    #[serde(default)]
    pub examples: Vec<String>,
    /// Example inputs that should not match.
    #[serde(default)]
    pub negative_examples: Vec<String>,
    /// References (e.g., URLs) for further context.
    #[serde(default)]
    pub references: Vec<String>,
    /// Optional validation configuration.
    #[serde(default)]
    pub validation: Option<Validation>,
    /// Optional dependencies on other rules.
    #[serde(default)]
    pub depends_on_rule: Vec<Option<DependsOnRule>>,
    /// Whether matches should always be considered validated.
    #[serde(default)]
    pub prevalidated: bool,
}
```

I’m creating new Kingfisher rules and need to follow these guidelines:

1. **Regex Patterns**
   - Write patterns as multi‑line, free‑spacing regex (`(?x)`) for readability.
   - Ensure compatibility with **vectorscan‑rs** for high‑performance scanning.
   - Minimize backtracking:
     - Use non‑capturing groups (`(?:…)`) and atomic or possessive quantifiers where supported.
     - Favor simple character classes over complex alternations.
     - Anchor your pattern (`\b…\b`) whenever possible.
   - **Do not** include inline comments inside the regex itself.

2. **Templating with Liquid**
   - Use the `liquid`, `liquid-core`, and `liquid-derive` crates for dynamic validation or request templates.
   - You have several custom Liquid filters, listed below

## Custom Liquid Filters

| Filter | Parameters | Description | Example |
|--------|------------|-------------|---------|
| **`b64enc`** | – | Base64-encodes the input with the standard alphabet . | `{{ TOKEN \| b64enc }}` |
| **`b64url_enc`** | – | URL-safe Base64 _without_ padding – handy for JWT parts. | `{{ TOKEN \| b64url_enc }}` |
| **`sha256`** | – | Hex-encoded SHA-256 digest of the input . | `{{ TOKEN \| sha256 }}` |
| **`hmac_sha256`** | `key` (str) | Base64 of an HMAC-SHA256 over the input . | `{{ TOKEN \| hmac_sha256: secret }}` |
| **`hmac_sha384`** | `key` (str) | Same as above, but with SHA-384 . | `{{ TOKEN \| hmac_sha384: secret }}` |
| **`random_string`** | `len` (int, optional, default `32`) | Cryptographically-secure random ASCII string . | `{{ "" \| random_string: 10 }}` |
| **`url_encode`** | – | Percent-encodes the input per RFC 3986 . | `{{ TOKEN \| url_encode }}` |
| **`json_escape`** | – | Escapes a string so it can be safely injected into JSON. | `{{ TOKEN \| json_escape }}` |
| **`unix_timestamp`** | – | Current Unix epoch seconds (UTC) . | `{{ "" \| unix_timestamp }}` |
| **`iso_timestamp`** | – | Current ISO-8601 timestamp (UTC) . | `{{ "" \| iso_timestamp }}` |
| **`uuid`** | – | Generates a random UUID-v4 . | `{{ "" \| uuid }}` |
| **`jwt_header`** | `alg` (str) | Builds `{"typ":"JWT","alg":…}` and Base64URL-encodes it. | `{{ "HS256" \| jwt_header }}` |

