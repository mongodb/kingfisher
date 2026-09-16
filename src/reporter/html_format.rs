use super::*;

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_timestamp(input: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(input)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_else(|_| input.to_string())
}

fn summary_line(label: &str, value: &str) -> String {
    format!(
        "<div class=\"summary-line\"><span class=\"label\">{}</span><span class=\"dots\"></span><span class=\"value\">{}</span></div>",
        escape_html(label),
        escape_html(value)
    )
}

fn render_metadata(metadata: &ScanReportMetadata) -> String {
    let mut lines = Vec::new();
    lines.push(summary_line("Findings", &metadata.summary.findings.to_string()));
    if let Some(successful) = metadata.summary.successful_validations {
        lines.push(summary_line(" |__Successful Validations", &successful.to_string()));
    }
    if let Some(failed) = metadata.summary.failed_validations {
        lines.push(summary_line(" |__Failed Validations", &failed.to_string()));
    }
    if let Some(skipped) = metadata.summary.skipped_validations {
        lines.push(summary_line(" |__Skipped Validations", &skipped.to_string()));
    }
    if let Some(rules_applied) = metadata.summary.rules_applied {
        lines.push(summary_line("Rules Applied", &rules_applied.to_string()));
    }
    if let Some(blobs) = metadata.summary.blobs_scanned {
        lines.push(summary_line(" |__Blobs Scanned", &blobs.to_string()));
    }
    if let Some(bytes) = metadata.summary.bytes_scanned {
        lines.push(summary_line("Bytes Scanned", &bytes.to_string()));
    }
    if let Some(duration) = metadata.summary.scan_duration_seconds {
        lines.push(summary_line("Scan Duration", &format!("{duration:.3}s")));
    }
    lines.push(summary_line("Scan Date", &format_timestamp(&metadata.scan_timestamp)));
    lines.push(summary_line("Report Generated", &format_timestamp(&metadata.generated_at)));
    lines.push(summary_line("Kingfisher Version", &metadata.kingfisher_version));
    if let Some(latest) = &metadata.latest_version_available {
        lines.push(summary_line(" |__Latest Version", latest));
    }
    if let Some(target) = &metadata.target {
        lines.push(summary_line("Target", target));
    }
    lines.push(summary_line(
        "Confidence Level",
        &metadata.summary.confidence_level.to_ascii_lowercase(),
    ));
    lines.push(summary_line(
        "Custom Rules Used",
        if metadata.summary.custom_rules_used { "yes" } else { "no" },
    ));
    lines.push(summary_line(
        "Validation Split",
        &format!(
            "Active {} | Local {} | Inactive {} | Invalid material {} | Unknown {}",
            metadata.summary.active_findings,
            metadata.summary.locally_derived_findings,
            metadata.summary.inactive_findings,
            metadata.summary.invalid_material_findings,
            metadata.summary.unknown_validation_findings
        ),
    ));
    lines.push(summary_line(
        "Blast Radius Identities",
        &metadata.summary.access_map_identities.to_string(),
    ));

    let cli_cmdline =
        metadata.command_line_args.iter().map(|arg| escape_html(arg)).collect::<Vec<_>>().join(" ");

    format!(
        "<section class=\"panel\">
          <h2>Scan Summary</h2>
          <div class=\"meta summary\">{}</div>
          <h3>Sanitized command-line arguments</h3>
          <pre class=\"cmdline\"><code>{}</code></pre>
        </section>",
        lines.join(""),
        cli_cmdline
    )
}

fn render_repository_audit(audit: Option<&crate::scan_audit::ScanAuditManifest>) -> String {
    let Some(audit) = audit else {
        return String::new();
    };
    let mut rows = String::new();
    for repository in &audit.repositories {
        let git = repository.git.as_ref();
        let tip = git.and_then(|value| value.tip_sha.as_deref()).unwrap_or("—");
        let scope = git.map(|value| value.scope.as_str()).unwrap_or("—");
        let boundary = git
            .and_then(|value| {
                value
                    .base_sha
                    .as_deref()
                    .map(|sha| format!("base {}", sha.chars().take(12).collect::<String>()))
                    .or_else(|| {
                        value
                            .inclusive_root_sha
                            .as_deref()
                            .map(|sha| format!("root {}", sha.chars().take(12).collect::<String>()))
                    })
            })
            .unwrap_or_else(|| "—".to_string());
        let duration = repository
            .scan
            .duration_seconds
            .map(|value| format!("{value:.3}s"))
            .unwrap_or_else(|| "—".to_string());
        let started = repository
            .scan
            .started_at
            .as_deref()
            .map(format_timestamp)
            .unwrap_or_else(|| "—".to_string());
        let scanned = repository
            .stats
            .as_ref()
            .map(|stats| {
                format!(
                    "{} blobs / {} bytes / {} findings",
                    stats.blobs_scanned, stats.bytes_scanned, stats.findings
                )
            })
            .unwrap_or_else(|| "—".to_string());
        let error =
            repository.scan.error.as_deref().or(repository.fetch.error.as_deref()).unwrap_or("");
        let status = if repository.fetch.status == "failed" {
            "fetch_failed"
        } else {
            repository.scan.status.as_str()
        };
        let duration_sort =
            repository.scan.duration_seconds.map(|value| value.to_string()).unwrap_or_default();
        let started_sort = repository.scan.started_at.as_deref().unwrap_or("");
        let scanned_sort = repository
            .stats
            .as_ref()
            .map(|stats| stats.blobs_scanned.to_string())
            .unwrap_or_default();
        rows.push_str(&format!(
            "<tr><td>{}</td><td data-filter-value=\"{}\"><span class=\"audit-status audit-status--{}\">{}</span></td><td data-sort-value=\"{}\">{}</td><td data-sort-value=\"{}\">{}</td><td><code title=\"{}\">{}</code></td><td><code>{}</code><br><span class=\"muted\">{}</span></td><td data-sort-value=\"{}\">{}</td><td>{}</td></tr>",
            escape_html(&repository.repository),
            escape_html(status),
            escape_html(status),
            escape_html(&status.replace('_', " ")),
            escape_html(started_sort),
            escape_html(&started),
            escape_html(&duration_sort),
            escape_html(&duration),
            escape_html(tip),
            escape_html(&tip.chars().take(12).collect::<String>()),
            escape_html(scope),
            escape_html(&boundary),
            escape_html(&scanned_sort),
            escape_html(&scanned),
            escape_html(error),
        ));
    }
    format!(
        "<section class=\"panel\"><h2>Repository Coverage</h2>
         <p class=\"section-note\"><strong>How to read this:</strong> Git history is not one straight line—branches and merges make a single “last commit scanned” ambiguous. <strong>Tip SHA</strong> is the exact commit Kingfisher pinned when this scan started (a version bookmark). An optional boundary is the older end of a diff, and <strong>Scope</strong> tells you what was eligible. <code>all_fetched_git_objects</code> means every file-content object (Git blob) available in the fetched repository—including history objects, not only the latest files.</p>
         <div class=\"audit-metrics\">
           <div><strong>{}</strong><span>Discovered</span></div>
           <div><strong>{}</strong><span>Completed</span></div>
           <div><strong>{}</strong><span>Fetch failed</span></div>
           <div><strong>{}</strong><span>Scan failed</span></div>
         </div>
         <div class=\"table-toolbar\" data-table-controls=\"repository-coverage-table\">
           <label class=\"search-control\"><span>Filter repositories</span><input type=\"search\" data-table-search=\"repository-coverage-table\" aria-controls=\"repository-coverage-table\" placeholder=\"Repository, SHA, scope, status…\"></label>
           <label class=\"select-control\"><span>Status</span><select data-table-column-filter=\"repository-coverage-table\" data-column=\"1\"><option value=\"\">All statuses</option><option value=\"completed\">Completed</option><option value=\"fetch_failed\">Fetch failed</option><option value=\"failed\">Scan failed</option><option value=\"pending\">Pending</option></select></label>
           <button type=\"button\" class=\"secondary-button\" data-table-reset=\"repository-coverage-table\">Clear</button>
           <span class=\"table-count\" data-table-count=\"repository-coverage-table\" aria-live=\"polite\"></span>
         </div>
         <div class=\"table-scroll\"><table id=\"repository-coverage-table\" class=\"interactive-table audit-table\" data-table-label=\"repositories\"><colgroup><col><col><col><col><col><col><col><col></colgroup><thead><tr><th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Repository<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Status<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"date\"><button type=\"button\" class=\"sort-button\">Started<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"number\"><button type=\"button\" class=\"sort-button\">Duration<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\" title=\"The exact commit Kingfisher pinned when this scan started.\">Tip SHA<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\" title=\"The files or history that were eligible for scanning, plus an optional diff boundary.\">Scope / boundary<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"number\"><button type=\"button\" class=\"sort-button\">Scanned<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th><th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Error<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th></tr></thead><tbody>{rows}<tr class=\"empty-filter-row\" data-table-empty hidden><td colspan=\"8\">No repositories match the current filters.</td></tr></tbody></table></div>
         </section>",
        audit.summary.discovered,
        audit.summary.scan_succeeded,
        audit.summary.fetch_failed,
        audit.summary.scan_failed,
    )
}

fn validation_rank(status: &str) -> usize {
    if status.eq_ignore_ascii_case("Active Credential") {
        0
    } else if status.eq_ignore_ascii_case("Assumed Valid (Not Live-Validated)") {
        1
    } else if status.eq_ignore_ascii_case("Locally Derived") {
        2
    } else if status.eq_ignore_ascii_case("Invalid Cryptographic Material") {
        4
    } else if status.eq_ignore_ascii_case("Inconclusive Validation") {
        3
    } else if status.eq_ignore_ascii_case("Inactive Credential") {
        4
    } else if status.eq_ignore_ascii_case("Canary Token (Skipped)")
        || status.eq_ignore_ascii_case("Validation Skipped")
    {
        5
    } else if status.eq_ignore_ascii_case("Not Attempted") {
        6
    } else {
        7
    }
}

fn validation_status_class(outcome: kingfisher_core::ValidationOutcome) -> &'static str {
    match outcome {
        kingfisher_core::ValidationOutcome::VerifiedActive => "status-active",
        kingfisher_core::ValidationOutcome::Assumed => "status-assumed",
        kingfisher_core::ValidationOutcome::LocallyDerived => "status-local",
        kingfisher_core::ValidationOutcome::InvalidMaterial => "status-invalid-material",
        kingfisher_core::ValidationOutcome::VerifiedInactive => "status-inactive",
        kingfisher_core::ValidationOutcome::Unavailable => "status-unavailable",
        kingfisher_core::ValidationOutcome::Skipped => "status-canary",
        kingfisher_core::ValidationOutcome::NotAttempted => "status-unknown",
    }
}

fn finding_git_url(record: &FindingReporterRecord) -> Option<String> {
    record
        .finding
        .git_metadata
        .as_ref()
        .and_then(|meta| {
            meta.get("file").and_then(|file| file.get("url")).or_else(|| meta.get("repository_url"))
        })
        .and_then(|url| url.as_str())
        .map(|url| url.to_string())
}

fn render_findings_table(findings: &[FindingReporterRecord]) -> String {
    if findings.is_empty() {
        return "<p>No findings detected.</p>".to_string();
    }

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        validation_rank(&a.finding.validation.status)
            .cmp(&validation_rank(&b.finding.validation.status))
            .then_with(|| a.finding.path.cmp(&b.finding.path))
            .then_with(|| a.finding.line.cmp(&b.finding.line))
    });

    let mut rows = String::new();
    for record in &sorted {
        let status_class = validation_status_class(record.finding.validation.outcome);
        let git_url_html = finding_git_url(record)
            .map(|url| {
                format!(
                    "<a class=\"source-link\" href=\"{}\" title=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">View source <span aria-hidden=\"true\">↗</span></a>",
                    escape_html(&url),
                    escape_html(&url)
                )
            })
            .unwrap_or_default();
        let commands = [
            record.finding.validate_command.as_deref().map(|command| {
                format!("<div><strong>Validate</strong><code>{}</code></div>", escape_html(command))
            }),
            record.finding.revoke_command.as_deref().map(|command| {
                format!("<div><strong>Revoke</strong><code>{}</code></div>", escape_html(command))
            }),
            record.finding.blast_radius_command.as_deref().map(|command| {
                format!(
                    "<div><strong>Blast radius</strong><code>{}</code></div>",
                    escape_html(command)
                )
            }),
        ];
        let command_count = commands.iter().flatten().count();
        let command_html = if command_count == 0 {
            String::new()
        } else {
            format!(
                "<details class=\"commands\"><summary>{command_count} command{}</summary>{}</details>",
                if command_count == 1 { "" } else { "s" },
                commands.into_iter().flatten().collect::<String>()
            )
        };
        let confidence_sort = match record.finding.confidence.to_ascii_lowercase().as_str() {
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };

        rows.push_str(&format!(
            "<tr>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td><code>{}</code></td>\
                <td>{}</td>\
                <td><span class=\"status {}\">{}</span></td>\
                <td data-sort-value=\"{}\">{}</td>\
                <td data-sort-value=\"{}\">{}</td>\
                <td>{}</td>\
             </tr>",
            escape_html(&record.rule.title),
            escape_html(&record.rule.id),
            escape_html(&record.rule.description),
            escape_html(&record.finding.path),
            git_url_html,
            status_class,
            escape_html(&record.finding.validation.status),
            confidence_sort,
            escape_html(&record.finding.confidence),
            record.finding.line,
            record.finding.line,
            command_html
        ));
    }

    format!(
        "<div class=\"table-toolbar\" data-table-controls=\"detailed-findings-table\">
          <label class=\"search-control\"><span>Filter findings</span><input type=\"search\" data-table-search=\"detailed-findings-table\" aria-controls=\"detailed-findings-table\" placeholder=\"Rule, path, repository, command…\"></label>
          <label class=\"select-control\"><span>Validation</span><select data-table-column-filter=\"detailed-findings-table\" data-column=\"5\"><option value=\"\">All validation states</option><option value=\"active credential\">Active</option><option value=\"assumed valid\">Assumed valid</option><option value=\"locally derived\">Locally derived</option><option value=\"inactive credential\">Inactive</option><option value=\"inconclusive validation\">Inconclusive</option><option value=\"validation skipped\">Skipped</option><option value=\"not attempted\">Not attempted</option></select></label>
          <label class=\"select-control\"><span>Confidence</span><select data-table-column-filter=\"detailed-findings-table\" data-column=\"6\"><option value=\"\">All confidence levels</option><option value=\"high\">High</option><option value=\"medium\">Medium</option><option value=\"low\">Low</option></select></label>
          <button type=\"button\" class=\"secondary-button\" data-table-reset=\"detailed-findings-table\">Clear</button>
          <span class=\"table-count\" data-table-count=\"detailed-findings-table\" aria-live=\"polite\"></span>
        </div>
        <div class=\"table-scroll\"><table id=\"detailed-findings-table\" class=\"interactive-table findings-table\" data-table-label=\"findings\">
          <colgroup><col><col><col><col><col><col><col><col><col></colgroup>
          <thead>
            <tr>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Rule<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Rule ID<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Description<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Path<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Source<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Validation<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"number\"><button type=\"button\" class=\"sort-button\">Confidence<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"number\"><button type=\"button\" class=\"sort-button\">Line<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
              <th data-sort-type=\"text\"><button type=\"button\" class=\"sort-button\">Commands<span class=\"sort-indicator\" aria-hidden=\"true\"></span></button></th>
            </tr>
          </thead>
          <tbody>{rows}<tr class=\"empty-filter-row\" data-table-empty hidden><td colspan=\"9\">No findings match the current filters.</td></tr></tbody>
        </table></div>"
    )
}

fn render_access_map(access_map: Option<&Vec<AccessMapEntry>>) -> String {
    let Some(entries) = access_map else {
        return String::new();
    };
    if entries.is_empty() {
        return String::new();
    }

    let mut items = String::new();
    for entry in entries {
        let resources = entry
            .groups
            .iter()
            .flat_map(|g| &g.resources)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let permissions = entry
            .groups
            .iter()
            .flat_map(|g| &g.permissions)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let mut paths = String::new();
        for group in &entry.groups {
            let grants = if group.permissions.is_empty() {
                "<li>Not recorded</li>".into()
            } else {
                group
                    .permissions
                    .iter()
                    .map(|p| format!("<li><code>{}</code></li>", escape_html(p)))
                    .collect::<String>()
            };
            let targets = if group.resources.is_empty() {
                "<li>Scope not recorded</li>".into()
            } else {
                group
                    .resources
                    .iter()
                    .map(|r| format!("<li><code>{}</code></li>", escape_html(r)))
                    .collect::<String>()
            };
            paths.push_str(&format!(
                "<li class=\"access-path\"><div><h4>Permissions</h4><ul>{grants}</ul></div><span aria-label=\"apply to\">→</span><div><h4>Resources</h4><details {}><summary>{} recorded resources</summary><ul>{targets}</ul></details></div></li>",
                if group.resources.len() <= 6 { "open" } else { "" }, group.resources.len()
            ));
        }
        let evidence_counts = entry
            .provider_metadata
            .as_ref()
            .and_then(|m| m.authorization_evidence.as_ref())
            .map(|e| {
                format!(
                    "<p>{} policies · {} identity paths · {} reachable roles · {} API probes</p>",
                    e.policies.len(),
                    e.paths.len(),
                    e.role_impacts.len(),
                    e.probes.len()
                )
            })
            .unwrap_or_default();
        let limitations = entry
            .provider_metadata
            .as_ref()
            .and_then(|m| m.authorization_evidence.as_ref())
            .map(|e| {
                e.limitations
                    .iter()
                    .map(|note| format!("<li>{}</li>", escape_html(note)))
                    .collect::<String>()
            })
            .filter(|notes| !notes.is_empty())
            .map(|notes| format!("<h4>Coverage limitations</h4><ul>{notes}</ul>"))
            .unwrap_or_default();
        items.push_str(&format!(
            "<article class=\"access-identity\"><h3>{} · {}</h3><p>{resources} recorded resources · {permissions} unique permissions</p><ol class=\"access-paths\">{paths}</ol>{evidence_counts}{limitations}</article>",
            escape_html(&entry.provider.to_uppercase()),
            escape_html(entry.account.as_deref().unwrap_or("Identity")),
        ));
    }
    format!(
        "<section class=\"panel\"><h2>Blast Radius Summary</h2><p>Snapshot of recorded access. Unlisted resources are not proof of no access.</p>{items}</section>"
    )
}

const FINDING_FILTER_SCRIPT: &str = include_str!("finding-filters.js");

const INTERACTIVE_TABLE_SCRIPT: &str = r#"<script>
(() => {
  const valueFor = (cell, type) => {
    const raw = (cell?.dataset.sortValue ?? cell?.textContent ?? "").trim();
    if (type === "number") {
      const value = Number(raw);
      return Number.isFinite(value) ? value : Number.NEGATIVE_INFINITY;
    }
    if (type === "date") {
      const value = Date.parse(raw);
      return Number.isFinite(value) ? value : Number.NEGATIVE_INFINITY;
    }
    return raw.toLocaleLowerCase();
  };

  const searchValueFor = (row) => {
    const attributes = Array.from(row.querySelectorAll("[href], [title]"))
      .flatMap((element) => [element.getAttribute("href"), element.getAttribute("title")])
      .filter(Boolean)
      .join(" ");
    return (row.textContent + " " + attributes).toLocaleLowerCase();
  };

  document.querySelectorAll("table.interactive-table").forEach((table) => {
    const body = table.tBodies[0];
    const emptyRow = body.querySelector("[data-table-empty]");
    const rows = Array.from(body.rows).filter((row) => row !== emptyRow);
    const label = table.dataset.tableLabel || "rows";
    const search = document.querySelector('[data-table-search="' + table.id + '"]');
    const filters = Array.from(
      document.querySelectorAll('[data-table-column-filter="' + table.id + '"]'),
    );
    const count = document.querySelector('[data-table-count="' + table.id + '"]');
    const reset = document.querySelector('[data-table-reset="' + table.id + '"]');

    rows.forEach((row, index) => {
      row.dataset.originalIndex = String(index);
      row.dataset.searchValue = searchValueFor(row);
    });

    let advancedFilters;
    const refresh = () => {
      const query = (search?.value ?? "").trim().toLocaleLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const matchesSearch = !query || row.dataset.searchValue.includes(query);
        const matchesColumns = filters.every((filter) => {
          if (!filter.value) return true;
          const cell = row.cells[Number(filter.dataset.column)];
          const explicitValue = cell?.dataset.filterValue;
          const actual = (explicitValue ?? cell?.textContent ?? "").trim().toLocaleLowerCase();
          const expected = filter.value.toLocaleLowerCase();
          return explicitValue === undefined ? actual.includes(expected) : actual === expected;
        });
        row.hidden = !(matchesSearch && matchesColumns && (!advancedFilters || advancedFilters.matches(row)));
        if (!row.hidden) visible += 1;
      });
      emptyRow.hidden = visible !== 0;
      count.textContent =
        "Showing " + visible.toLocaleString() + " of " + rows.length.toLocaleString() + " " + label;
    };

    table.querySelectorAll("thead th[data-sort-type]").forEach((header, column) => {
      header.setAttribute("aria-sort", "none");
      header.querySelector("button")?.addEventListener("click", () => {
        const direction = header.getAttribute("aria-sort") === "ascending"
          ? "descending"
          : "ascending";
        table.querySelectorAll("thead th[aria-sort]").forEach((other) => {
          other.setAttribute("aria-sort", other === header ? direction : "none");
        });
        const type = header.dataset.sortType;
        rows.sort((left, right) => {
          const a = valueFor(left.cells[column], type);
          const b = valueFor(right.cells[column], type);
          let result = typeof a === "number"
            ? a - b
            : a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
          if (result === 0) {
            result = Number(left.dataset.originalIndex) - Number(right.dataset.originalIndex);
          }
          return direction === "ascending" ? result : -result;
        });
        rows.forEach((row) => body.insertBefore(row, emptyRow));
        refresh();
      });
    });

    if (table.id === "detailed-findings-table") {
      const container = document.createElement("section");
      container.className = "finding-filter-builder";
      container.setAttribute("aria-label", "Finding filters");
      table.closest(".table-scroll").before(container);
      const fields = {};
      Array.from(table.tHead.rows[0].cells).slice(0, -1).forEach((header, index) => {
        const values = (row) => [row.cells[index]?.dataset.filterValue ?? row.cells[index]?.textContent?.trim()];
        fields[String(index)] = { label: header.textContent.trim(), values,
          options: () => [...new Set(rows.flatMap(values).filter(Boolean))].sort().slice(0, 200) };
      });
      const urlKey = "finding-filters";
      advancedFilters = createFindingFilters(container, fields, () => {
        const url = new URL(window.location.href);
        if (advancedFilters.serialize() === "[]") url.searchParams.delete(urlKey);
        else url.searchParams.set(urlKey, advancedFilters.serialize());
        window.history.replaceState(window.history.state, "", url);
        refresh();
      }, () => {
        if (search) search.value = "";
        filters.forEach((filter) => { filter.value = ""; });
      });
      advancedFilters.restore(new URLSearchParams(window.location.search).get(urlKey));
      window.addEventListener("popstate", () => {
        advancedFilters.restore(new URLSearchParams(window.location.search).get(urlKey));
        refresh();
      });
    }
    search?.addEventListener("input", refresh);
    filters.forEach((filter) => filter.addEventListener("change", refresh));
    reset?.addEventListener("click", () => {
      if (search) search.value = "";
      filters.forEach((filter) => { filter.value = ""; });
      if (advancedFilters) {
        advancedFilters.restore();
        const url = new URL(window.location.href);
        url.searchParams.delete("finding-filters");
        window.history.replaceState(window.history.state, "", url);
      }
      refresh();
      search?.focus();
    });
    refresh();
  });

  window.addEventListener("beforeprint", () => {
    document.querySelectorAll("details.commands").forEach((details) => {
      details.dataset.wasOpen = details.open ? "true" : "false";
      details.open = true;
    });
  });
  window.addEventListener("afterprint", () => {
    document.querySelectorAll("details.commands").forEach((details) => {
      details.open = details.dataset.wasOpen === "true";
      delete details.dataset.wasOpen;
    });
  });
})();
</script>"#;

fn build_html(envelope: &ReportEnvelope) -> String {
    let metadata_html = envelope.metadata.as_ref().map(render_metadata).unwrap_or_default();
    let repository_audit_html = render_repository_audit(envelope.audit.as_ref());
    let findings_html = render_findings_table(&envelope.findings);
    let access_map_html = render_access_map(envelope.access_map.as_ref());

    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Kingfisher Audit Report — Local report snapshot</title>
  <style>
    /* MongoDB brand / LeafyGreen palette: https://www.mongodb.design/foundations/palette
   Keep semantic colors aligned with the local viewer and standalone reports. */
    :root {{
      --brand: #00684a;
      --brand-dark: #00684a;
      --bg: #f9fbfa;
      --surface: #ffffff;
      --surface-muted: #f9fbfa;
      --surface-strong: #e8edeb;
      --text: #001e2b;
      --muted: #5c6c75;
      --border: #c1c7c6;
      --border-strong: #889397;
      --hover: #e8edeb;
      --danger: #970606;
      --warning: #944f01;
      --info: #1254b7;
      --success: #00684a;
      --purple: #5e0c9e;
      --brand-soft: #e3fcf7;
      --danger-soft: #ffeae5;
      --warning-soft: #fef7db;
      --info-soft: #e1f7ff;
      --purple-soft: #f9ebff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; margin: 0; padding: 24px; color: var(--text); background: var(--bg); }}
    body {{ color: var(--text); background: var(--bg); border-top: 4px solid var(--brand); }}
    .report-shell {{ width: 100%; max-width: 1600px; margin: 0 auto; }}
    h1 {{ margin: 0 0 6px; color: var(--text); }}
    .workspace-mode {{ color: var(--info); font-size: 11px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }}
    .workspace-context {{ padding: 12px 16px; margin: 16px 0; border: 1px solid var(--border); border-radius: 7px; background: var(--surface-muted); color: var(--muted); font-size: 13px; }}
    h2 {{ margin: 0 0 10px; }}
    h3 {{ margin: 16px 0 8px; font-size: 14px; }}
    .subtitle {{ color: var(--muted); margin-bottom: 18px; line-height: 1.45; }}
    .subtitle a {{ color: var(--brand); text-decoration: none; font-weight: 600; }}
    .subtitle a:hover {{ text-decoration: underline; }}
    .panel {{ background: #ffffff; border: 1px solid var(--border); border-radius: 7px; padding: 16px; margin-bottom: 16px; }}
    .summary {{ display: grid; gap: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", monospace; }}
    .summary-line {{ display: flex; align-items: baseline; gap: 8px; color: var(--text); }}
    .summary-line .label {{ color: var(--brand); white-space: nowrap; }}
    .summary-line .dots {{ flex: 1; border-bottom: 1px dotted var(--border); transform: translateY(-3px); }}
    .summary-line .value {{ color: var(--text); }}
    .cmdline {{ margin: 0; padding: 12px; background: #f1f5f9; border-radius: 8px; overflow-x: auto; }}
    .cmdline code {{ color: var(--text); white-space: pre-wrap; word-break: break-word; }}
    .section-note {{ color: var(--muted); font-family: ui-sans-serif, system-ui, sans-serif; font-size: 13px; line-height: 1.5; }}
    .audit-metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin: 14px 0; }}
    .audit-metrics div {{ border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: var(--bg); }}
    .audit-metrics strong {{ display: block; color: var(--brand); font-size: 22px; }}
    .audit-metrics span {{ color: var(--muted); font-family: ui-sans-serif, system-ui, sans-serif; font-size: 12px; }}
    .table-toolbar {{ display: flex; align-items: end; flex-wrap: wrap; gap: 10px; margin: 14px 0 10px; }}
    .table-toolbar label {{ display: grid; gap: 5px; color: var(--text); font-size: 12px; font-weight: 700; }}
    .search-control {{ flex: 1 1 320px; }}
    .select-control {{ flex: 0 1 210px; }}
    .table-toolbar input, .table-toolbar select {{ width: 100%; min-height: 38px; border: 1px solid var(--border-strong); border-radius: 7px; padding: 8px 10px; color: var(--text); background: #fff; font: inherit; font-weight: 400; }}
    .table-toolbar input:focus, .table-toolbar select:focus, .sort-button:focus-visible, .secondary-button:focus-visible {{ outline: 3px solid var(--brand); outline-offset: 1px; border-color: var(--brand); }}
    .secondary-button {{ min-height: 38px; border: 1px solid var(--border-strong); border-radius: 7px; padding: 8px 14px; color: var(--text); background: var(--bg); font-weight: 700; cursor: pointer; }}
    .secondary-button:hover {{ background: var(--surface-strong); }}
    .table-count {{ margin-left: auto; padding: 0 2px 10px; color: var(--muted); font-size: 12px; white-space: nowrap; }}
    .table-scroll {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }}
    .audit-status {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--surface-strong); font-weight: 700; }}
    .audit-status--completed {{ background: #dcfce7; color: #166534; }}
    .audit-status--failed, .audit-status--fetch_failed {{ background: #fee2e2; color: #991b1b; }}
    .muted {{ color: var(--muted); font-size: 11px; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
    .interactive-table {{ table-layout: fixed; }}
    .interactive-table th, .interactive-table td {{ border: 0; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); padding: 10px; font-size: 13px; line-height: 1.4; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
    .interactive-table th:last-child, .interactive-table td:last-child {{ border-right: 0; }}
    .interactive-table tbody tr:last-child td {{ border-bottom: 0; }}
    .interactive-table th {{ position: sticky; top: 0; z-index: 2; padding: 0; background: var(--surface-strong); color: var(--text); box-shadow: inset 0 -1px var(--border-strong); }}
    .interactive-table tbody tr:nth-child(even) {{ background: var(--bg); }}
    .interactive-table tbody tr:hover {{ background: #ecfeff; }}
    .findings-table {{ min-width: 1560px; }}
    .findings-table col:nth-child(1) {{ width: 160px; }}
    .findings-table col:nth-child(2) {{ width: 185px; }}
    .findings-table col:nth-child(3) {{ width: 240px; }}
    .findings-table col:nth-child(4) {{ width: 260px; }}
    .findings-table col:nth-child(5) {{ width: 105px; }}
    .findings-table col:nth-child(6) {{ width: 170px; }}
    .findings-table col:nth-child(7) {{ width: 105px; }}
    .findings-table col:nth-child(8) {{ width: 70px; }}
    .findings-table col:nth-child(9) {{ width: 265px; }}
    .audit-table {{ min-width: 1450px; }}
    .audit-table col:nth-child(1) {{ width: 245px; }}
    .audit-table col:nth-child(2) {{ width: 120px; }}
    .audit-table col:nth-child(3) {{ width: 190px; }}
    .audit-table col:nth-child(4) {{ width: 100px; }}
    .audit-table col:nth-child(5) {{ width: 125px; }}
    .audit-table col:nth-child(6) {{ width: 220px; }}
    .audit-table col:nth-child(7) {{ width: 200px; }}
    .audit-table col:nth-child(8) {{ width: 250px; }}
    .sort-button {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; width: 100%; min-height: 44px; border: 0; padding: 9px 10px; color: inherit; background: transparent; font: inherit; font-weight: 800; text-align: left; cursor: pointer; }}
    .sort-button:hover {{ background: var(--border); }}
    .sort-indicator::before {{ content: \"↕\"; color: var(--muted); font-size: 12px; }}
    th[aria-sort=\"ascending\"] .sort-indicator::before {{ content: \"↑\"; color: var(--brand); }}
    th[aria-sort=\"descending\"] .sort-indicator::before {{ content: \"↓\"; color: var(--brand); }}
    .source-link {{ display: inline-flex; gap: 3px; color: var(--info); font-weight: 700; text-decoration: none; }}
    .source-link:hover {{ text-decoration: underline; }}
    .access-identity {{ margin-top: 20px; overflow-wrap: anywhere; }}
    .access-paths {{ list-style: none; padding: 0; display: grid; gap: 12px; }}
    .access-path {{ display: grid; grid-template-columns: minmax(0, 1fr) 24px minmax(0, 1.2fr); gap: 12px; padding: 16px; border: 1px solid var(--border); border-radius: 8px; }}
    .access-path h4 {{ margin: 0 0 10px; }}
    .access-path > div {{ min-width: 0; }}
    .access-path > span {{ align-self: center; }}
    .access-path summary {{ cursor: pointer; min-height: 24px; }}
    .access-path ul {{ padding-left: 18px; }}
    .access-path li + li {{ margin-top: 8px; }}
    @media (max-width: 600px) {{ .access-path {{ grid-template-columns: minmax(0, 1fr); }} .access-path > span {{ transform: rotate(90deg); justify-self: center; }} }}
    .commands summary {{ color: var(--brand); font-weight: 800; cursor: pointer; }}
    .commands div {{ margin-top: 9px; }}
    .commands strong {{ display: block; margin-bottom: 3px; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; }}
    .commands code {{ display: block; padding: 7px; border-radius: 5px; background: #f1f5f9; white-space: pre-wrap; overflow-wrap: anywhere; }}
    .empty-filter-row td {{ padding: 28px; color: var(--muted); text-align: center; font-style: italic; }}
    .status {{ display: inline-block; max-width: 100%; padding: 3px 8px; border-radius: 999px; font-weight: 700; }}
    .status-active {{ background: var(--danger-soft); color: var(--danger); }}
    .status-assumed {{ background: var(--info-soft); color: var(--info); }}
    .status-local {{ background: var(--info-soft); color: var(--info); }}
    .status-invalid-material {{ background: var(--danger-soft); color: var(--danger); }}
    .status-inactive {{ background: var(--brand-soft); color: var(--success); }}
    .status-canary {{ background: var(--purple-soft); color: var(--purple); }}
    .status-unavailable {{ background: var(--warning-soft); color: var(--warning); }}
    .status-unknown {{ background: var(--warning-soft); color: var(--warning); }}
    @media (max-width: 720px) {{
      body {{ padding: 12px; }}
      .panel {{ padding: 12px; }}
      .table-count {{ width: 100%; margin-left: 0; padding: 0; }}
    }}

.finding-filter-builder {{ margin: 12px 0; padding: 16px; border: 1px solid var(--border-strong); border-radius: 12px; }}
.finding-filter-form, .finding-filter-chips {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: end; }}
.finding-filter-form label {{ display: grid; gap: 6px; flex: 1 1 160px; min-width: 0; }}
.finding-filter-form input, .finding-filter-form select, .finding-filter-builder button {{ min-height: 36px; max-width: 100%; padding: 8px 12px; border: 1px solid var(--border-strong); border-radius: 8px; background: #fff; color: var(--text); font: inherit; }}
.finding-filter-builder button {{ cursor: pointer; overflow-wrap: anywhere; text-align: left; }}
.finding-filter-builder p, .finding-filter-builder [role=status] {{ font-size: 12px; color: var(--muted); }}
.finding-filter-chips {{ margin-bottom: 8px; }}
.finding-filter-builder :focus-visible {{ outline: 2px solid var(--accent, #0e9f6e); outline-offset: 2px; }}
@media (max-width: 600px) {{ .finding-filter-builder input, .finding-filter-builder select {{ font-size: 16px; }} .finding-filter-builder button, .finding-filter-builder select, .finding-filter-builder input {{ min-height: 44px; }} }}

    @media print {{
      @page {{ size: landscape; margin: 0.4in; }}
      body {{ padding: 0; background: #fff; }}
      .report-shell {{ max-width: none; }}
      .table-toolbar, .finding-filter-builder {{ display: none; }}
      .table-scroll {{ display: contents; overflow: visible; border: 0; }}
      .interactive-table {{ width: 100%; min-width: 0; table-layout: auto; }}
      .interactive-table thead {{ display: table-header-group; }}
      .interactive-table tbody {{ display: table-row-group; }}
      .interactive-table tr {{ break-inside: avoid; page-break-inside: avoid; }}
      .interactive-table th {{ position: static; }}
      .interactive-table .sort-indicator {{ display: none; }}
      .interactive-table .empty-filter-row {{ display: none !important; }}
      .interactive-table th, .interactive-table td {{ padding: 5px; font-size: 9px; }}
      .commands {{ display: block; }}
      .access-identity {{ margin-top: 20px; overflow-wrap: anywhere; }}
    .access-paths {{ list-style: none; padding: 0; display: grid; gap: 12px; }}
    .access-path {{ display: grid; grid-template-columns: minmax(0, 1fr) 24px minmax(0, 1.2fr); gap: 12px; padding: 16px; border: 1px solid var(--border); border-radius: 8px; }}
    .access-path h4 {{ margin: 0 0 10px; }}
    .access-path > div {{ min-width: 0; }}
    .access-path > span {{ align-self: center; }}
    .access-path summary {{ cursor: pointer; min-height: 24px; }}
    .access-path ul {{ padding-left: 18px; }}
    .access-path li + li {{ margin-top: 8px; }}
    @media (max-width: 600px) {{ .access-path {{ grid-template-columns: minmax(0, 1fr); }} .access-path > span {{ transform: rotate(90deg); justify-self: center; }} }}
    .commands summary {{ display: none; }}
      .commands code {{ font-size: 8px; }}
    }}
  </style>
</head>
<body>
 <main class=\"report-shell\">
   <p class=\"workspace-mode\">Kingfisher · Local reports</p>
   <h1>Kingfisher Audit Report</h1>
   <div class=\"workspace-context\"><strong>Report workspace · Scan snapshot</strong><br>This standalone report describes a scan at a point in time. Use <code>kingfisher view report.json</code> for the interactive Report Viewer &amp; Triager.</div>
  <div class=\"subtitle\">Secret scanning report generated by <a href=\"https://github.com/mongodb/kingfisher\" target=\"_blank\" rel=\"noopener noreferrer\">MongoDB Kingfisher</a>.</div>
  {metadata_html}
  {repository_audit_html}
  <section class=\"panel\">
    <h2>Detailed Findings</h2>
    {findings_html}
  </section>
  {access_map_html}
 </main>
  <script>{FINDING_FILTER_SCRIPT}</script>
  {INTERACTIVE_TABLE_SCRIPT}
</body>
</html>"
    )
}

impl DetailsReporter {
    pub fn html_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        write!(writer, "{}", build_html(&envelope))?;
        writeln!(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> FindingReporterRecord {
        FindingReporterRecord {
            rule: RuleMetadata {
                title: "TEST-RULE => [CUSTOM.TEST]".to_string(),
                name: "test-rule".to_string(),
                id: "custom.test".to_string(),
                description: "Test rule description".to_string(),
            },
            finding: FindingRecordData {
                dependent_captures: Default::default(),
                ambiguous_dependencies: Default::default(),
                snippet: "secret".to_string(),
                fingerprint: "fingerprint".to_string(),
                confidence: "high".to_string(),
                entropy: "4.0".to_string(),
                validation: ValidationInfo {
                    outcome: kingfisher_core::ValidationOutcome::VerifiedActive,
                    status: "Active Credential".to_string(),
                    response: String::new(),
                },
                language: "Rust".to_string(),
                line: 42,
                column_start: 1,
                column_end: 6,
                path: "src/example.rs".to_string(),
                encoding: None,
                git_metadata: Some(serde_json::json!({
                    "file": {"url": "https://example.test/repo/blob/main/src/example.rs#L42"}
                })),
                validate_command: Some(
                    "kingfisher validate --rule custom.test 'example'".to_string(),
                ),
                revoke_command: None,
                blast_radius_command: Some(
                    "kingfisher blast-radius --rule custom.test 'example'".to_string(),
                ),
            },
        }
    }

    #[test]
    fn access_map_preserves_permission_resource_groups_and_escapes_provider_text() {
        let entry = AccessMapEntry {
            provider: "test".into(),
            account: Some("<script>account</script>".into()),
            groups: vec![
                crate::reporter::AccessMapResourceGroup {
                    permissions: vec!["read<all>".into()],
                    resources: vec!["bucket&one".into()],
                },
                crate::reporter::AccessMapResourceGroup {
                    permissions: vec!["read<all>".into()],
                    resources: vec![],
                },
            ],
            roles: vec![],
            token_details: None,
            provider_metadata: None,
            fingerprint: None,
            permissions_by_severity: None,
            context: None,
        };
        let html = render_access_map(Some(&vec![entry]));
        assert!(html.contains("1 recorded resources · 1 unique permissions"));
        assert_eq!(html.matches("class=\"access-path\"").count(), 2);
        assert!(html.contains("&lt;script&gt;account&lt;/script&gt;"));
        assert!(html.contains("bucket&amp;one"));
        assert!(html.contains("Scope not recorded"));
        assert!(!html.contains("<script>account"));
    }

    #[test]
    fn skipped_validations_have_a_stable_rank_and_style() {
        assert_eq!(validation_rank("Canary Token (Skipped)"), 5);
        assert_eq!(validation_rank("Validation Skipped"), 5);
        assert_eq!(validation_rank("future validation state"), 7);
        assert_eq!(
            validation_status_class(kingfisher_core::ValidationOutcome::Skipped),
            "status-canary"
        );
    }

    #[test]
    fn build_html_includes_audit_title_and_cli_args() {
        let mut collector =
            crate::scan_audit::ScanAuditCollector::new("2026-01-01T00:00:00Z".to_string(), None)
                .unwrap();
        collector.discover_local(std::path::Path::new("/tmp/repo"));
        let envelope = ReportEnvelope {
            findings: Vec::new(),
            access_map: None,
            audit: Some(collector.finish().unwrap()),
            metadata: Some(ScanReportMetadata {
                generated_at: "2026-01-01T00:00:00Z".to_string(),
                scan_timestamp: "2026-01-01T00:00:00Z".to_string(),
                target: Some("/tmp/repo".to_string()),
                command_line_args: vec![
                    "kingfisher".to_string(),
                    "scan".to_string(),
                    "--token".to_string(),
                    "***REDACTED***".to_string(),
                ],
                kingfisher_version: "1.2.3".to_string(),
                latest_version_available: Some("1.2.4".to_string()),
                update_check_status: Some("ok".to_string()),
                summary: ScanReportSummary {
                    findings: 0,
                    active_findings: 0,
                    inactive_findings: 0,
                    locally_derived_findings: 0,
                    invalid_material_findings: 0,
                    unknown_validation_findings: 0,
                    access_map_identities: 0,
                    rules_applied: Some(10),
                    confidence_level: "medium".to_string(),
                    custom_rules_used: false,
                    successful_validations: Some(0),
                    failed_validations: Some(0),
                    skipped_validations: Some(0),
                    blobs_scanned: Some(1),
                    bytes_scanned: Some(10),
                    scan_duration_seconds: Some(0.1),
                },
            }),
        };

        let html = build_html(&envelope);
        assert!(html.contains("Kingfisher Audit Report"));
        assert!(html.contains("Sanitized command-line arguments"));
        assert!(html.contains("***REDACTED***"));
        assert!(html.contains("/tmp/repo"));
        assert!(html.contains("Repository Coverage"));
        assert!(html.contains("pending"));
        assert!(html.contains("data-table-search=\"repository-coverage-table\""));
        assert!(!html.contains("INTERACTIVE_TABLE_SCRIPT"));
        assert!(html.contains("document.querySelectorAll(\"table.interactive-table\")"));
        assert!(html.contains("@page { size: landscape;"));
        assert!(html.contains("display: contents; overflow: visible"));
        assert!(html.contains("display: table-header-group"));
        assert!(html.contains("window.addEventListener(\"beforeprint\""));
        assert!(!html.contains("<script src="));
        assert!(!html.contains("<link rel=\"stylesheet\""));
    }

    #[test]
    fn findings_table_is_readable_sortable_and_filterable() {
        let html = render_findings_table(&[sample_finding()]);

        assert!(html.contains("data-table-search=\"detailed-findings-table\""));
        assert!(html.contains("data-table-column-filter=\"detailed-findings-table\""));
        assert!(html.contains("data-sort-type=\"number\""));
        assert!(html.contains("View source"));
        assert!(html.contains("<details class=\"commands\"><summary>2 commands</summary>"));
        assert!(!html.contains(">https://example.test/repo/blob"));
    }
}
