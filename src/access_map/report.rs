use std::path::Path;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use flate2::{Compression, write::GzEncoder};
use std::io::Write;

use super::AccessMapResult;

/// Generate a standalone HTML report with a simple, collapsible tree view (no D3 dependency).
pub fn generate_html_report_multi(results: &[AccessMapResult], path: &Path) -> Result<()> {
    let html = render_html_report_multi(results)?;
    std::fs::write(path, html)?;
    Ok(())
}

/// Render a standalone HTML report for a collection of access-map results.
pub fn render_html_report_multi(results: &[AccessMapResult]) -> Result<String> {
    let json = serde_json::to_string(results)?;
    let compressed = gzip_base64(&json)?;
    Ok(build_html(&json, &compressed))
}

fn gzip_base64(json_str: &str) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json_str.as_bytes())?;
    let compressed = encoder.finish()?;
    Ok(BASE64_STANDARD.encode(compressed))
}

fn build_html(json_str: &str, compressed_json_b64: &str) -> String {
    const TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Kingfisher Access Map</title>
    <style>
    :root {
      --bg: #f5f1eb;
      --panel: #fbf7f1;
      --border: #e2d6c2;
      --text: #1f2a3a;
      --muted: #5b5f66;
      --accent: #0e7c56;
      --accent-soft: #dbeee3;
      --highlight: #fcefdc;
      --shadow: rgba(17, 35, 26, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      background: #0b3a2a;
      color: #f1f5f9;
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 14px;
      position: sticky;
      top: 0;
      z-index: 2;
      box-shadow: 0 10px 32px rgba(0, 0, 0, 0.18);
    }
    header h1 {
      margin: 0;
      font-size: 18px;
      letter-spacing: 0.01em;
    }
    header .hint {
      margin-left: auto;
      font-size: 13px;
      color: #dbe4e9;
    }
    main {
      padding: 20px 16px 32px;
      max-width: 1800px;
      width: min(96vw, 1800px);
      margin: 0 auto;
    }
    #layout {
      display: grid;
      grid-template-columns: minmax(260px, 320px) 1fr;
      gap: 18px;
      align-items: start;
    }
    @media (max-width: 1000px) {
      #layout { grid-template-columns: 1fr; }
      #summary { position: relative; top: auto; }
    }
    a {
      color: #0b5c3d;
      font-weight: 700;
      text-decoration: underline;
      text-decoration-color: #0b5c3d;
      text-decoration-thickness: 2px;
      text-underline-offset: 2px;
    }
    a:hover, a:focus-visible {
      color: #09452f;
      text-decoration-color: #09452f;
      outline: none;
    }
    #cards {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    #summary {
      background: #0d2f23;
      color: #e3f0e8;
      border-radius: 12px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      box-shadow: 0 18px 36px rgba(0, 0, 0, 0.28);
      position: sticky;
      top: 86px;
      align-self: start;
      min-height: 160px;
    }
    #summary h2 {
      margin: 0;
      font-size: 16px;
      font-weight: 750;
      letter-spacing: 0.01em;
      color: #f7fbf9;
    }
    #summary .summary-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      list-style: none;
      margin: 0;
      padding: 0;
    }
    #summary .summary-item {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 10px;
      padding: 9px 10px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
    }
    #summary .summary-title {
      font-weight: 700;
      font-size: 14px;
      color: #f7fbf9;
      word-break: break-word;
    }
    #summary .summary-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      font-size: 12px;
      color: #c9d5ce;
    }
    .card {
      background: linear-gradient(180deg, var(--panel) 0%, #fffefa 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 24px 48px var(--shadow);
    }
    .identity {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      margin-bottom: 12px;
      background: var(--accent-soft);
    }
    .identity-title {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
      color: var(--text);
    }
    .identity-sub {
      color: var(--muted);
      font-size: 13px;
      margin-top: 4px;
    }
    .identity-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 10px 18px;
      margin-top: 12px;
    }
    .identity-field {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .identity-key {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .identity-value {
      font-size: 15px;
      font-weight: 700;
      color: var(--text);
      word-break: break-word;
    }
    .meta {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 10px;
      color: var(--muted);
      font-size: 13px;
    }
    .badge {
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--border);
      background: #f7efe2;
      color: var(--text);
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .badge.accent { background: #0d5c41; color: #f4f7f5; border-color: transparent; }
    .cloud-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 750;
      letter-spacing: 0.01em;
    }
    .cloud-logo {
      width: 22px;
      height: 22px;
      border-radius: 8px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 2px;
      background: #f2f5f3;
      border: 1px solid rgba(0, 0, 0, 0.04);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.7), 0 1px 4px rgba(0,0,0,0.12);
    }
    .cloud-logo svg { width: 18px; height: 18px; display: block; }
    .cloud-logo.aws { background: linear-gradient(135deg, #fff8f1, #ffe3c2); }
    .cloud-logo.aws svg { color: #ec7211; }
    .cloud-logo.gcp { background: linear-gradient(135deg, #f3f8ff, #e5f3ea); }
    .cloud-logo.gcp svg { color: #4285f4; }
    .cloud-logo.unknown { background: linear-gradient(135deg, #ececec, #d9d9d9); }
    .summary-title-row { display: inline-flex; align-items: center; gap: 8px; }
    .content {
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
      gap: 18px;
      align-items: start;
    }
    .tree {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      background: #fffdf8;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }
    .search-box { margin-bottom: 10px; }
    .search-input {
      width: 100%;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-size: 14px;
      background: #fff;
    }
    .detail {
      background: #0d2f23;
      color: #e2ebe5;
      border-radius: 12px;
      padding: 14px 16px;
      position: sticky;
      top: 92px;
      min-height: 160px;
      max-height: 70vh;
      overflow: auto;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.3);
    }
    .detail-title {
      margin: 0 0 8px 0;
      font-size: 16px;
      font-weight: 700;
      color: #f5f9f6;
    }
    .detail-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .detail-field { display: flex; flex-direction: column; gap: 4px; }
    .detail-key {
      color: #9db4a8;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .detail-value { font-size: 14px; color: #f4f7f5; word-break: break-word; }
    .detail-empty { color: #93a29a; font-size: 13px; }
    .node {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 7px 8px;
      border-radius: 8px;
      cursor: default;
      transition: background 0.15s ease;
    }
    .node:hover { background: var(--highlight); }
    .node.selected { outline: 2px solid #0e7c56; background: #eef8f2; }
    .toggle {
      width: 16px;
      text-align: center;
      cursor: pointer;
      user-select: none;
      color: var(--muted);
      font-weight: 700;
    }
    .icon {
      width: 14px;
      height: 14px;
      border-radius: 4px;
      flex-shrink: 0;
    }
    .label { font-size: 14px; overflow-wrap: anywhere; font-weight: 600; }
    .type { color: var(--muted); font-size: 12px; }
    details { margin-left: 18px; }
    summary { list-style: none; }
    summary::-webkit-details-marker { display: none; }
    .match { background: #fff4e0; }
    .empty { color: var(--muted); font-size: 14px; padding: 8px 0; }
  </style>
</head>
  <body>
    <header>
      <h1>Access Map</h1>
      <div class="hint">Unified Access Map Report</div>
    </header>
    <div id="data-error" style="display:none; max-width: 1400px; margin: 12px auto 0;">
      <div class="card" style="border-color: #e56a6a; background: #fff6f6;">
        <div class="identity-title">Unable to load embedded data</div>
        <div class="identity-sub" id="error-details"></div>
        <div class="identity-sub">Data size: <span id="data-size"></span></div>
      </div>
    </div>
  <main>
    <div id="layout">
      <aside id="summary"></aside>
      <div id="cards"></div>
    </div>
  </main>
  <script>
    const compressedDataBase64 = "REPLACE_COMPRESSED_JSON";
    const uncompressedSize = REPLACE_UNCOMPRESSED_LEN;

    async function decodeCompressedData() {
      const binary = atob(compressedDataBase64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      if (typeof DecompressionStream !== 'undefined') {
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
        const decompressed = await new Response(stream).arrayBuffer();
        const decoded = new TextDecoder().decode(decompressed);
        return JSON.parse(decoded);
      }

      throw new Error('This browser does not support gzip decompression for embedded data.');
    }

    function slugify(text, fallback = 'identity') {
      if (!text) return fallback;
      return text
        .toString()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80) || fallback;
    }

    function badge(label, accent = false) {
      const span = document.createElement('span');
      span.className = 'badge' + (accent ? ' accent' : '');
      span.textContent = label;
      return span;
    }

    const CLOUD_LOGOS = {
      aws: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z"/></svg>',
      gcp: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z"/></svg>',
      slack: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52h-2.521zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.522 2.521 2.527 2.527 0 0 1-2.522-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.522 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.522 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.522-2.522v-2.522h2.522zM15.165 17.688a2.527 2.527 0 0 1-2.522-2.521 2.527 2.527 0 0 1 2.522-2.522h6.313A2.527 2.527 0 0 1 24 15.167a2.528 2.528 0 0 1-2.522 2.521h-6.313z"/></svg>',
      unknown: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="10" fill="currentColor" opacity="0.18"/><path fill="currentColor" d="M12 6c1.657 0 3 1.343 3 3 0 1.104-.672 2.052-1.624 2.674C12.518 12.318 12 13.095 12 14v.5a1 1 0 0 1-2 0V14c0-1.61.978-2.645 1.835-3.215C12.574 10.328 13 9.688 13 9c0-.552-.448-1-1-1s-1 .448-1 1a1 1 0 1 1-2 0c0-1.657 1.343-3 3-3zm0 11a1.25 1.25 0 1 1 0 2.5A1.25 1.25 0 0 1 12 17z"/></svg>'
    };

    function cloudLogo(cloud) {
      const span = document.createElement('span');
      const normalized = (cloud || 'unknown').toLowerCase();
      span.className = 'cloud-logo ' + normalized;
      span.setAttribute('aria-hidden', 'true');
      span.innerHTML = CLOUD_LOGOS[normalized] || CLOUD_LOGOS.unknown;
      return span;
    }

    function showDataError(message) {
      const container = document.getElementById('data-error');
      const details = document.getElementById('error-details');
      const size = document.getElementById('data-size');
      if (container && details && size) {
        details.textContent = message || 'Failed to load embedded data';
        if (uncompressedSize) {
          const kb = (uncompressedSize / 1024).toFixed(1);
          size.textContent = `${kb} KB (original JSON)`;
        }
        container.style.display = 'block';
      }
    }

    function cloudChip(cloud) {
      const chip = document.createElement('span');
      chip.className = 'cloud-chip';
      chip.appendChild(cloudLogo(cloud));
      const text = document.createElement('span');
      text.textContent = (cloud || 'unknown').toUpperCase();
      chip.appendChild(text);
      return chip;
    }

    function renderIdentity(model, el) {
      el.innerHTML = '';
      const title = document.createElement('div');
      title.className = 'identity-title';
      const link = resolveIdentityLink(model);
      if (link) {
        const anchor = document.createElement('a');
        anchor.href = link;
        anchor.target = '_blank';
        anchor.rel = 'noreferrer noopener';
        anchor.textContent = model.identity?.id || 'Unknown identity';
        title.appendChild(anchor);
      } else {
        title.textContent = model.identity?.id || 'Unknown identity';
      }
      el.appendChild(title);

      const subtitle = document.createElement('div');
      subtitle.className = 'identity-sub';
      subtitle.textContent = model.identity?.access_type || 'unknown';
      el.appendChild(subtitle);

      const grid = document.createElement('div');
      grid.className = 'identity-grid';
      const fields = [
        ['Cloud', model.cloud || 'unknown'],
        ['Project', model.identity?.project || '—'],
        ['Tenant', model.identity?.tenant || '—'],
        ['Account', model.identity?.account_id || '—'],
        ['Fingerprint', model.fingerprint || '—'],
      ];
      fields.forEach(([label, value]) => {
        const item = document.createElement('div');
        item.className = 'identity-field';
        const key = document.createElement('div');
        key.className = 'identity-key';
        key.textContent = label;
        const val = document.createElement('div');
        val.className = 'identity-value';
        if (label === 'Cloud') {
          val.appendChild(cloudChip(value));
        } else {
          val.textContent = value;
        }
        item.appendChild(key);
        item.appendChild(val);
        grid.appendChild(item);
      });
      el.appendChild(grid);
    }

    function renderMeta(model, el) {
      el.innerHTML = '';
      const cloudBadge = badge('', true);
      cloudBadge.appendChild(cloudChip(model.cloud || 'unknown'));
      el.appendChild(cloudBadge);
      el.appendChild(badge('Severity: ' + (model.severity || 'unknown')));
      el.appendChild(badge('Roles: ' + (model.roles?.length || 0)));
      const permCount = (model.permissions?.admin?.length || 0) +
                        (model.permissions?.privilege_escalation?.length || 0) +
                        (model.permissions?.risky?.length || 0) +
                        (model.permissions?.read_only?.length || 0);
      el.appendChild(badge('Permissions: ' + permCount));
      el.appendChild(badge('Resources: ' + (model.resources?.length || 0)));
    }

    function renderDetail(node, el) {
      el.innerHTML = '';
      const title = document.createElement('div');
      title.className = 'detail-title';
      title.textContent = node ? (node.name || 'Selection') : 'Select a node';
      el.appendChild(title);

      if (!node) {
        const empty = document.createElement('div');
        empty.className = 'detail-empty';
        empty.textContent = 'Choose a permission, role, or resource to view details.';
        el.appendChild(empty);
        return;
      }

      const list = document.createElement('div');
      list.className = 'detail-list';

      const typeField = document.createElement('div');
      typeField.className = 'detail-field';
      const typeKey = document.createElement('div');
      typeKey.className = 'detail-key';
      typeKey.textContent = 'Type';
      const typeVal = document.createElement('div');
      typeVal.className = 'detail-value';
      typeVal.textContent = node.type || 'unknown';
      typeField.appendChild(typeKey);
      typeField.appendChild(typeVal);
      list.appendChild(typeField);

      if (node.resource_type) {
        const rtField = document.createElement('div');
        rtField.className = 'detail-field';
        const rtk = document.createElement('div');
        rtk.className = 'detail-key';
        rtk.textContent = 'Resource type';
        const rtv = document.createElement('div');
        rtv.className = 'detail-value';
        rtv.textContent = node.resource_type;
        rtField.appendChild(rtk);
        rtField.appendChild(rtv);
        list.appendChild(rtField);
      }

      const roleSource = node.source;
      if (roleSource) {
        const sourceField = document.createElement('div');
        sourceField.className = 'detail-field';
        const sk = document.createElement('div');
        sk.className = 'detail-key';
        sk.textContent = 'Source';
        const sv = document.createElement('div');
        sv.className = 'detail-value';
        sv.textContent = roleSource;
        sourceField.appendChild(sk);
        sourceField.appendChild(sv);
        list.appendChild(sourceField);
      }

      const link = node.link;
      if (link) {
        const linkField = document.createElement('div');
        linkField.className = 'detail-field';
        const lk = document.createElement('div');
        lk.className = 'detail-key';
        lk.textContent = 'Console link';
        const lv = document.createElement('div');
        lv.className = 'detail-value';
        const anchor = document.createElement('a');
        anchor.href = link;
        anchor.target = '_blank';
        anchor.rel = 'noreferrer noopener';
        anchor.textContent = link;
        lv.appendChild(anchor);
        linkField.appendChild(lk);
        linkField.appendChild(lv);
        list.appendChild(linkField);
      }

      if (node.permissions && node.permissions.length >= 0) {
        const perms = document.createElement('div');
        perms.className = 'detail-field';
        const pk = document.createElement('div');
        pk.className = 'detail-key';
        pk.textContent = node.type === 'resource' ? 'Access permissions' : 'Permissions';
        const pv = document.createElement('div');
        pv.className = 'detail-value';
        const permissions = node.permissions || [];
        permissions.forEach(p => {
          const pill = document.createElement('span');
          pill.className = 'badge';
          pill.textContent = p;
          pv.appendChild(pill);
        });
        if (!permissions.length) {
          pv.textContent = 'None';
        }
        perms.appendChild(pk);
        perms.appendChild(pv);
        list.appendChild(perms);
      }

      if (node.risk) {
        const riskField = document.createElement('div');
        riskField.className = 'detail-field';
        const rk = document.createElement('div');
        rk.className = 'detail-key';
        rk.textContent = 'Risk';
        const rv = document.createElement('div');
        rv.className = 'detail-value';
        rv.textContent = node.risk;
        riskField.appendChild(rk);
        riskField.appendChild(rv);
        list.appendChild(riskField);
      }

      if (node.reason) {
        const reasonField = document.createElement('div');
        reasonField.className = 'detail-field';
        const rk = document.createElement('div');
        rk.className = 'detail-key';
        rk.textContent = 'Reason';
        const rv = document.createElement('div');
        rv.className = 'detail-value';
        rv.textContent = node.reason;
        reasonField.appendChild(rk);
        reasonField.appendChild(rv);
        list.appendChild(reasonField);
      }

      if (node.notes && node.notes.length) {
        const notesField = document.createElement('div');
        notesField.className = 'detail-field';
        const nk = document.createElement('div');
        nk.className = 'detail-key';
        nk.textContent = 'Notes';
        const nv = document.createElement('div');
        nv.className = 'detail-value';
        nv.textContent = node.notes.join(' | ');
        notesField.appendChild(nk);
        notesField.appendChild(nv);
        list.appendChild(notesField);
      }

      el.appendChild(list);
    }

    function resolveIdentityLink(model) {
      if (model.cloud === 'gcp') return gcpServiceAccountLink(model);
      if (model.cloud === 'aws') return awsIamLink(model);
      return null;
    }

    function gcpServiceAccountLink(model) {
      const project = model.identity?.project;
      const id = model.identity?.id;
      if (!project || !id) return null;
      const encodedId = encodeURIComponent(id);
      return `https://console.cloud.google.com/iam-admin/serviceaccounts/details/${encodedId}?project=${encodeURIComponent(project)}`;
    }

    function awsIamLink(model) {
      const arn = model.identity?.id || '';
      const resource = arn.split(':')[5] || '';
      const parts = resource.split('/');
      const kind = parts[0];
      const name = parts[1];
      if (!kind || !name) return null;
      if (kind === 'assumed-role' || kind === 'role') {
        return `https://console.aws.amazon.com/iam/home?#/roles/${encodeURIComponent(name)}`;
      }
      if (kind === 'user') {
        return `https://console.aws.amazon.com/iam/home?#/users/${encodeURIComponent(name)}`;
      }
      return null;
    }

    function permissionLink(permission, model) {
      if (model.cloud === 'gcp') return gcpPermissionLink(permission);
      return null;
    }

    function gcpPermissionLink(permission) {
      if (!permission) return null;
      return `https://cloud.google.com/iam/docs/permissions-reference?hl=en&permission=${encodeURIComponent(permission)}`;
    }

    function buildTree(model) {
      const roleNodes = (model.roles || []).map(role => ({
        name: role.name || 'role',
        type: 'role',
        source: role.source || 'direct',
        permissions: role.permissions || [],
        children: (role.permissions || []).map(p => ({
          name: p,
          type: 'permission',
          link: permissionLink(p, model)
        }))
      }));

      const permGroups = [
        ['Admin', model.permissions?.admin || []],
        ['Privilege Escalation', model.permissions?.privilege_escalation || []],
        ['Risky', model.permissions?.risky || []],
        ['Read Only', model.permissions?.read_only || []],
      ]
        .filter(([, perms]) => perms.length)
        .map(([label, perms]) => ({
          name: label,
          type: 'permission_group',
          children: perms.map(p => ({ name: p, type: 'permission', link: permissionLink(p, model) }))
        }));

      const resourceNodes = buildResourceNodes(model);

      return {
        name: model.identity?.id || 'Identity',
        type: 'identity',
        fingerprint: model.fingerprint,
        children: [
          { name: 'Resources', type: 'section', children: resourceNodes },
          { name: 'Roles', type: 'section', children: roleNodes },
          { name: 'Permissions', type: 'section', children: permGroups },
          { name: 'Notes', type: 'section', children: (model.risk_notes || []).map(n => ({ name: n, type: 'note', notes: [n] })) },
          { name: 'Recommendations', type: 'section', children: (model.recommendations || []).map(r => ({ name: r, type: 'note', notes: [r] })) },
        ],
      };
    }

    function markMatches(node, query) {
      if (!node) return null;
      const name = (node.name || '').toLowerCase();
      const type = (node.type || '').toLowerCase();
      const fp = (node.fingerprint || '').toLowerCase();
      const matchesSelf = query ? name.includes(query) || type.includes(query) || fp.includes(query) : true;
      if (!node.children || node.children.length === 0) {
        return matchesSelf ? { ...node } : null;
      }
      const filteredChildren = node.children
        .map(child => markMatches(child, query))
        .filter(Boolean);
      if (matchesSelf || filteredChildren.length > 0) {
        return { ...node, children: filteredChildren, matched: matchesSelf };
      }
      return null;
    }

    function defaultOpen(node, depth) {
      if (depth === 0) return true;
      if ((node.name === 'Resources' || node.type === 'resource_section') && depth === 1) return true;
      if (node.type === 'resource_group' || node.type === 'resource') return true;
      return false;
    }

    function renderNode(node, root, depth, query, highlight, detailEl) {
      const detailsEl = document.createElement('details');
      const summary = document.createElement('summary');
      const row = document.createElement('div');
      row.className = 'node' + (node.matched && highlight ? ' match' : '');

      const toggle = document.createElement('div');
      toggle.className = 'toggle';
      const hasChildren = node.children && node.children.length;
      const initiallyOpen = defaultOpen(node, depth);
      toggle.textContent = hasChildren ? (initiallyOpen ? '▾' : '▸') : '';
      toggle.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        detailsEl.open = !detailsEl.open;
        toggle.textContent = detailsEl.open ? '▾' : '▸';
      };
      row.appendChild(toggle);

      const icon = document.createElement('div');
      icon.className = 'icon';
      icon.style.background = iconColor(node.type);
      row.appendChild(icon);

      const label = document.createElement('div');
      label.className = 'label';
      label.textContent = node.name || node.type || 'item';
      row.appendChild(label);

      if (node.type) {
        const t = document.createElement('div');
        t.className = 'type';
        t.textContent = node.type;
        row.appendChild(t);
      }

      row.onclick = () => {
        root.querySelectorAll('.node').forEach(n => n.classList.remove('selected'));
        row.classList.add('selected');
        renderDetail(node, detailEl);
      };

      summary.appendChild(row);
      detailsEl.appendChild(summary);

      detailsEl.open = initiallyOpen;

      if (node.children && node.children.length) {
        node.children.forEach(child => {
          const childNode = renderNode(child, root, depth + 1, query, highlight, detailEl);
          if (childNode) detailsEl.appendChild(childNode);
        });
      }

      return detailsEl;
    }

    function renderTree(model, treeRoot, detailEl, query = '') {
      const lower = (query || '').toLowerCase();
      const treeData = buildTree(model);
      const filtered = markMatches(treeData, lower);
      treeRoot.innerHTML = '';
      renderDetail(null, detailEl);
      if (!filtered) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'No matches';
        treeRoot.appendChild(empty);
        return;
      }
      const node = renderNode(filtered, treeRoot, 0, lower, Boolean(lower), detailEl);
      treeRoot.appendChild(node);
    }

    function renderCard(model, idx) {
      const card = document.createElement('section');
      card.className = 'card';
      const anchorId = slugify(model.identity?.id, `identity-${idx + 1}`);
      card.id = anchorId;
      card.innerHTML = `
        <div class="identity"></div>
        <div class="meta"></div>
        <div class="content">
          <div>
            <div class="search-box">
              <input class="search-input" placeholder="Search permissions, roles, resources" />
            </div>
            <div class="tree"></div>
          </div>
          <div class="detail"></div>
        </div>
      `;
      const identityEl = card.querySelector('.identity');
      const metaEl = card.querySelector('.meta');
      const treeEl = card.querySelector('.tree');
      const detailEl = card.querySelector('.detail');
      const search = card.querySelector('.search-input');

      renderIdentity(model, identityEl);
      renderMeta(model, metaEl);
      renderTree(model, treeEl, detailEl);

      search.oninput = (e) => {
        renderTree(model, treeEl, detailEl, e.target.value || '');
      };

      return card;
    }

    function renderSummary(items) {
      const container = document.getElementById('summary');
      if (!container) return;
      container.innerHTML = '';

      if (!items.length) {
        container.style.display = 'none';
        return;
      }

      container.style.display = 'flex';
      const title = document.createElement('h2');
      title.textContent = 'Identities';
      container.appendChild(title);

      const list = document.createElement('ol');
      list.className = 'summary-list';
      items.forEach((model, idx) => {
        const li = document.createElement('li');
        li.className = 'summary-item';

        const anchorId = slugify(model.identity?.id, `identity-${idx + 1}`);
        const link = document.createElement('a');
        link.href = `#${anchorId}`;
        link.className = 'summary-title';
        const titleRow = document.createElement('span');
        titleRow.className = 'summary-title-row';
        titleRow.appendChild(cloudLogo(model.cloud));
        const titleText = document.createElement('span');
        titleText.textContent = model.identity?.id || `Identity ${idx + 1}`;
        titleRow.appendChild(titleText);
        link.appendChild(titleRow);
        li.appendChild(link);

        const meta = document.createElement('div');
        meta.className = 'summary-meta';
        const cloud = document.createElement('span');
        cloud.appendChild(cloudChip(model.cloud || 'unknown'));
        meta.appendChild(cloud);

        if (model.identity?.account_id) {
          const acct = document.createElement('span');
          acct.textContent = model.identity.account_id;
          meta.appendChild(acct);
        }

        const sev = document.createElement('span');
        sev.textContent = `Severity: ${model.severity || 'unknown'}`;
        meta.appendChild(sev);

        if (model.fingerprint) {
          const fp = document.createElement('div');
          fp.style.width = '100%';
          fp.style.marginTop = '4px';
          fp.style.fontSize = '11px';
          fp.style.color = '#9db4a8';
          fp.textContent = `Fingerprint: ${model.fingerprint}`;
          meta.appendChild(fp);

          const btn = document.createElement('button');
          btn.className = 'badge';
          btn.style.marginTop = '6px';
          btn.style.cursor = 'pointer';
          btn.style.width = '100%';
          btn.style.justifyContent = 'center';
          btn.textContent = 'Go to finding';
          btn.onclick = (e) => {
             e.preventDefault();
             e.stopPropagation();
             const searchInput = document.getElementById('search-input');
             if (searchInput) {
                 if (typeof setActiveView === 'function') setActiveView('view-findings');
                 searchInput.value = model.fingerprint;
                 currentFilter = model.fingerprint;
                 currentPage = 1;
                 renderFindingsTable();
                 setTimeout(() => {
                     const tableContainer = document.querySelector('.table-container');
                     if (tableContainer) {
                         tableContainer.scrollIntoView({behavior: 'smooth', block: 'start'});
                     }
                 }, 50);
             }
          };
          meta.appendChild(btn);
        }

        li.appendChild(meta);
        list.appendChild(li);
      });

      container.appendChild(list);
    }

    function renderAll(items) {
      renderSummary(items);
      const container = document.getElementById('cards');
      container.innerHTML = '';
      if (!items.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'No Access Map results found.';
        container.appendChild(empty);
        return;
      }
      items.forEach((model, idx) => {
        container.appendChild(renderCard(model, idx));
      });
    }

    function iconColor(type) {
      switch ((type || '').toLowerCase()) {
        case 'role':
        case 'permission':
          return '#13aa52';
        case 'resource_group':
          return '#b08968';
        case 'resource':
          return '#f4b740';
        case 'permission_group':
          return '#89a7a7';
        case 'note':
          return '#7f8c8d';
        default:
          return '#7fb089';
      }
    }

    function awsResourceConsoleLink(resource) {
      if (!resource || !resource.startsWith('arn:')) return null;
      const parts = resource.split(':');
      if (parts.length < 6) return null;
      const service = parts[2];
      const region = parts[3] || '';
      const resourcePart = parts[5];
      const resourceName = `${parts[5] || ''}`;

      if (service === 's3') {
        const bucket = (resourcePart || '').split('/')[0];
        if (bucket) {
          return `https://s3.console.aws.amazon.com/s3/buckets/${encodeURIComponent(bucket)}`;
        }
      }

      if (service === 'iam') {
        const res = resourcePart.split('/')[1];
        if (!res) return null;
        const kind = resourcePart.split('/')[0];
        if (kind === 'role' || kind === 'assumed-role') {
          return `https://console.aws.amazon.com/iam/home?#/roles/${encodeURIComponent(res)}`;
        }
        if (kind === 'user') {
          return `https://console.aws.amazon.com/iam/home?#/users/${encodeURIComponent(res)}`;
        }
        return null;
      }

      if (service === 'lambda') {
        const match = resourcePart.match(/^function[:\/](.+)$/);
        if (match && match[1]) {
          const fnName = match[1];
          const regionQuery = region ? `?region=${encodeURIComponent(region)}` : '';
          return `https://console.aws.amazon.com/lambda/home${regionQuery}#/functions/${encodeURIComponent(fnName)}`;
        }
        return null;
      }

      if (service === 'ec2') {
        const match = resourcePart.match(/^instance\/(.+)$/);
        if (match && match[1]) {
          const instanceId = match[1];
          return `https://console.aws.amazon.com/ec2/v2/home?#InstanceDetails:instanceId=${encodeURIComponent(instanceId)}`;
        }
        return null;
      }

      if (service === 'kms') {
        const match = resourcePart.match(/^(?:key|alias)\/(.+)$/);
        if (match && match[1]) {
          return `https://console.aws.amazon.com/kms/home?#/kms/keys/${encodeURIComponent(match[1])}`;
        }
        return null;
      }

      if (service === 'secretsmanager') {
        return `https://console.aws.amazon.com/secretsmanager/home?#/secret?name=${encodeURIComponent(resourceName)}`;
      }

      if (service === 'dynamodb') {
        const match = resourcePart.match(/^(?:table\/(.+)|table:(.+))/);
        const tableRaw = match ? match[1] || match[2] : null;
        const table = tableRaw ? tableRaw.split('/')[0] : null;
        if (table) {
          const regionQuery = region ? `?region=${encodeURIComponent(region)}` : '';
          return `https://console.aws.amazon.com/dynamodbv2/home${regionQuery}#/table/${encodeURIComponent(table)}/items`;
        }
        return null;
      }

      return null;
    }

    function awsServiceFromArn(resource) {
      if (!resource || !resource.startsWith('arn:')) return null;
      const parts = resource.split(':');
      if (parts.length < 3) return null;
      return parts[2] || null;
    }

    function gcpResourceConsoleLink(resource) {
      if (!resource) return null;
      const projectMatch = resource.match(/^projects\/([^/]+)/);
      const project = projectMatch ? projectMatch[1] : null;

      if (resource.includes('/buckets/')) {
        const bucketMatch = resource.match(/\/buckets\/([^/]+)/);
        const bucket = bucketMatch ? bucketMatch[1] : null;
        if (bucket && project) {
          return `https://console.cloud.google.com/storage/browser/${encodeURIComponent(bucket)}?project=${encodeURIComponent(project)}`;
        }
      }

      if (resource.includes('/datasets/')) {
        const datasetMatch = resource.match(/\/datasets\/([^/]+)/);
        const dataset = datasetMatch ? datasetMatch[1] : null;
        if (dataset && project) {
          return `https://console.cloud.google.com/bigquery?project=${encodeURIComponent(project)}&p=${encodeURIComponent(project)}&d=${encodeURIComponent(dataset)}&page=dataset`;
        }
      }

      if (resource.includes('/secrets/')) {
        const secretMatch = resource.match(/\/secrets\/([^/:]+)/);
        const secret = secretMatch ? secretMatch[1] : null;
        if (secret && project) {
          return `https://console.cloud.google.com/security/secret-manager/secret/${encodeURIComponent(secret)}/versions?project=${encodeURIComponent(project)}`;
        }
      }

      if (resource.includes('/functions/')) {
        const fnMatch = resource.match(/\/locations\/([^/]+)\/functions\/([^/]+)/);
        if (fnMatch && project) {
          const region = fnMatch[1];
          const fnName = fnMatch[2];
          return `https://console.cloud.google.com/functions/details/${encodeURIComponent(region)}/${encodeURIComponent(fnName)}?project=${encodeURIComponent(project)}`;
        }
      }

      if (project) {
        return `https://console.cloud.google.com/home/dashboard?project=${encodeURIComponent(project)}`;
      }

      return null;
    }

    function buildResourceNodes(model) {
      const resources = model.resources || [];
      if (model.cloud !== 'aws') {
        const grouped = new Map();
        const ungrouped = [];

        resources.forEach(res => {
          let project = null;
          const name = res.name || '';
          if (res.resource_type === 'project' && name) {
            project = name;
          } else {
            const match = name.match(/^projects\/([^/]+)/);
            if (match && match[1]) project = match[1];
          }

          const permissionNodes = (res.permissions || []).map(p => ({
            name: p,
            type: 'permission',
            link: permissionLink(p, model)
          }));

          const node = {
            name: res.name || 'resource',
            type: 'resource',
            risk: res.risk || 'low',
            reason: res.reason || '',
            resource_type: res.resource_type || null,
            permissions: res.permissions || [],
            link: gcpResourceConsoleLink(res.name || ''),
            children: permissionNodes
          };

          if (project) {
            if (!grouped.has(project)) grouped.set(project, []);
            grouped.get(project).push(node);
          } else {
            ungrouped.push(node);
          }
        });

        const nodes = Array.from(grouped.entries()).map(([project, children]) => ({
          name: project,
          type: 'resource_group',
          children
        }));

        return nodes.concat(ungrouped);
      }

      const grouped = new Map();
      const ungrouped = [];

      resources.forEach(res => {
        const group = res.resource_type || awsServiceFromArn(res.name || '') || null;
        const permissionNodes = (res.permissions || []).map(p => ({
          name: p,
          type: 'permission',
          link: permissionLink(p, model)
        }));

        const node = {
          name: res.name || 'resource',
          type: 'resource',
          risk: res.risk || 'low',
          reason: res.reason || '',
          resource_type: res.resource_type || null,
          permissions: res.permissions || [],
          link: awsResourceConsoleLink(res.name || ''),
          children: permissionNodes
        };

        if (group) {
          if (!grouped.has(group)) grouped.set(group, []);
          grouped.get(group).push(node);
        } else {
          ungrouped.push(node);
        }
      });

      const nodes = Array.from(grouped.entries()).map(([group, children]) => ({
        name: group,
        type: 'resource_group',
        children
      }));

      return nodes.concat(ungrouped);
    }

    document.addEventListener('DOMContentLoaded', () => {
      decodeCompressedData()
        .then(data => {
          const models = Array.isArray(data) ? data : [data];
          renderAll(models);
        })
        .catch(err => {
          console.error('Failed to load embedded Access Map:', err);
          showDataError(err?.message || 'Unable to decode embedded data.');
        });
    });
  </script>
</body>
</html>"#;
    let mut template = TEMPLATE.replace("REPLACE_COMPRESSED_JSON", compressed_json_b64);
    let uncompressed_len = json_str.len().to_string();
    template = template.replace("REPLACE_UNCOMPRESSED_LEN", &uncompressed_len);
    template
}
