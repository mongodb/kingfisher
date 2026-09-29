// Client-side search/filter for the built-in rules table.
// Material's `navigation.instant` feature swaps page bodies without firing
// DOMContentLoaded, so we subscribe to the `document$` observable it exposes
// and re-wire the handler every time a new page is rendered.
function initRulesFilter() {
  const table = document.querySelector(".rules-table");
  if (!table) return;

  const input = document.querySelector(".rules-search");
  const countEl = document.querySelector(".rules-count");
  const tbody = table.querySelector("tbody");

  if (table.dataset.rulesFilterBound === "1") return;
  table.dataset.rulesFilterBound = "1";

  const rows = Array.from(tbody.querySelectorAll("tr"));
  const total = rows.length;
  const toolbar = document.createElement("div");
  toolbar.className = "rules-toolbar";
  toolbar.setAttribute("aria-label", "Filter detection rules");
  const filters = [
    { key: "confidence", name: "Confidence", index: 1, options: ["High", "Medium", "Low"] },
    { key: "validation", name: "Live validation", index: 2, options: ["Yes", "None"] },
    { key: "revocation", name: "Direct revocation", index: 3, options: ["Yes", "None"] },
  ];
  const params = new URLSearchParams(window.location.search);
  filters.forEach(function (filter) {
    const label = document.createElement("label");
    label.textContent = filter.name;
    const select = document.createElement("select");
    select.name = filter.key;
    select.add(new Option("All", ""));
    filter.options.forEach(function (value) { select.add(new Option(value, value)); });
    select.value = params.get(filter.key) || "";
    if (select.selectedIndex < 0) select.value = "";
    filter.select = select;
    select.addEventListener("change", applyFilter);
    label.appendChild(select);
    toolbar.appendChild(label);
  });
  const reset = document.createElement("button");
  reset.type = "button";
  reset.textContent = "Clear filters";
  reset.addEventListener("click", function () {
    if (input) input.value = "";
    filters.forEach(function (filter) { filter.select.value = ""; });
    applyFilter();
  });
  toolbar.appendChild(reset);
  if (input) {
    input.setAttribute("aria-label", "Search detection rules");
    input.placeholder = "Search by provider or rule ID…";
    input.value = params.get("rule-query") || "";
    input.insertAdjacentElement("afterend", toolbar);
  } else {
    table.before(toolbar);
  }
  if (countEl) {
    countEl.setAttribute("role", "status");
    countEl.setAttribute("aria-live", "polite");
  }
  const empty = document.createElement("p");
  empty.className = "rules-empty";
  empty.textContent = "No matching rules. Try a different provider or clear your filters.";
  empty.hidden = true;
  table.after(empty);

  function updateCount(visible) {
    if (countEl) {
      countEl.textContent = "Showing " + visible + " of " + total + " rules";
    }
  }

  function applyFilter() {
    const query = input ? input.value.toLowerCase().trim() : "";
    let visible = 0;
    rows.forEach(function (row) {
      const text = row.textContent.toLowerCase();
      const match = (!query || text.includes(query)) && filters.every(function (filter) {
        return !filter.select.value || row.children[filter.index].textContent.trim() === filter.select.value;
      });
      row.hidden = !match;
      if (match) visible++;
    });
    empty.hidden = visible !== 0;
    table.hidden = visible === 0;
    updateCount(visible);
    const url = new URL(window.location.href);
    if (query) url.searchParams.set("rule-query", query);
    else url.searchParams.delete("rule-query");
    filters.forEach(function (filter) {
      if (filter.select.value) url.searchParams.set(filter.key, filter.select.value);
      else url.searchParams.delete(filter.key);
    });
    window.history.replaceState(window.history.state, "", url);
  }

  if (input) {
    let debounceTimer;
    input.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(applyFilter, 80);
    });
  }

  // --- Sortable columns ---
  const headers = Array.from(table.querySelectorAll("thead th"));
  const confidenceOrder = { "high": 3, "medium": 2, "low": 1 };
  let sortState = { index: -1, dir: 1 };

  function cellKey(row, index) {
    const cell = row.children[index];
    if (!cell) return "";
    return cell.textContent.trim().toLowerCase();
  }

  function compare(a, b, index) {
    const av = cellKey(a, index);
    const bv = cellKey(b, index);
    // Confidence column — ordered by severity
    if (headers[index] && headers[index].textContent.trim().toLowerCase() === "confidence") {
      return (confidenceOrder[av] || 0) - (confidenceOrder[bv] || 0);
    }
    // Capability columns — supported rules first.
    const aYes = av === "yes" ? 1 : 0;
    const bYes = bv === "yes" ? 1 : 0;
    if (aYes !== bYes) return bYes - aYes;
    return av.localeCompare(bv, undefined, { numeric: true, sensitivity: "base" });
  }

  function sortBy(index) {
    if (sortState.index === index) {
      sortState.dir = -sortState.dir;
    } else {
      sortState.index = index;
      sortState.dir = 1;
    }
    const dir = sortState.dir;
    const sorted = rows.slice().sort(function (a, b) {
      return dir * compare(a, b, index);
    });
    const frag = document.createDocumentFragment();
    sorted.forEach(function (row) { frag.appendChild(row); });
    tbody.appendChild(frag);

    headers.forEach(function (h, i) {
      h.classList.remove("is-sorted-asc", "is-sorted-desc");
      h.setAttribute("aria-sort", i === index ? (dir === 1 ? "ascending" : "descending") : "none");
      if (i === index) {
        h.classList.add(dir === 1 ? "is-sorted-asc" : "is-sorted-desc");
      }
    });
  }

  headers.forEach(function (th, i) {
    th.classList.add("is-sortable");
    th.setAttribute("aria-sort", "none");
    th.setAttribute("tabindex", "0");
    th.addEventListener("click", function () { sortBy(i); });
    th.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        sortBy(i);
      }
    });
  });

  applyFilter();
}

if (typeof document$ !== "undefined" && document$.subscribe) {
  document$.subscribe(initRulesFilter);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initRulesFilter);
} else {
  initRulesFilter();
}
