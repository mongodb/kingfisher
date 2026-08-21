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

  function updateCount(visible) {
    if (countEl) {
      countEl.textContent = "Showing " + visible + " of " + total + " rules";
    }
  }

  function applyFilter() {
    if (!input) {
      updateCount(total);
      return;
    }
    const query = input.value.toLowerCase().trim();
    let visible = 0;
    rows.forEach(function (row) {
      const text = row.textContent.toLowerCase();
      const match = !query || text.indexOf(query) !== -1;
      row.style.display = match ? "" : "none";
      if (match) visible++;
    });
    updateCount(visible);
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
      if (i === index) {
        h.classList.add(dir === 1 ? "is-sorted-asc" : "is-sorted-desc");
      }
    });
  }

  headers.forEach(function (th, i) {
    th.classList.add("is-sortable");
    th.setAttribute("role", "button");
    th.setAttribute("tabindex", "0");
    th.addEventListener("click", function () { sortBy(i); });
    th.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        sortBy(i);
      }
    });
  });

  updateCount(total);
}

if (typeof document$ !== "undefined" && document$.subscribe) {
  document$.subscribe(initRulesFilter);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initRulesFilter);
} else {
  initRulesFilter();
}
