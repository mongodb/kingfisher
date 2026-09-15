// BEGIN finding filter builder (inline copy in docs/viewer/index.html for offline use).
function createFindingFilters(container, fields, onChange, onClear) {
  const operators = { equals: "is", contains: "contains", not_equals: "is not", not_contains: "does not contain", missing: "is empty", present: "is not empty" };
  let filters = [];
  const form = document.createElement("form");
  form.className = "finding-filter-form";
  const control = (label, tag) => {
    const wrapper = document.createElement("label");
    const title = document.createElement("span");
    title.textContent = label;
    const input = document.createElement(tag);
    input.name = `finding-filter-${label.toLowerCase()}`;
    wrapper.append(title, input);
    form.append(wrapper);
    return input;
  };
  const field = control("Field", "select");
  Object.entries(fields).forEach(([key, config]) => field.add(new Option(config.label, key)));
  const operator = control("Match", "select");
  Object.entries(operators).forEach(([key, label]) => operator.add(new Option(label, key)));
  const value = control("Value", "input");
  value.autocomplete = "off";
  value.placeholder = "Select or type a value…";
  const suggestions = document.createElement("datalist");
  suggestions.id = "finding-filter-values";
  value.setAttribute("list", suggestions.id);
  const add = document.createElement("button");
  add.type = "submit";
  add.textContent = "Add filter";
  const clear = document.createElement("button");
  clear.type = "button";
  clear.textContent = "Clear all filters";
  form.append(add, clear, suggestions);
  const help = document.createElement("p");
  help.textContent = "Include values in the same field match ANY; different fields and exclusions must ALL match. Filters also combine with the search and dropdowns above. Matching ignores case.";
  const chips = document.createElement("div");
  chips.className = "finding-filter-chips";
  chips.setAttribute("aria-label", "Applied finding filters");
  const status = document.createElement("span");
  status.setAttribute("role", "status");
  container.append(form, help, chips, status);
  function render() {
    chips.replaceChildren();
    filters.forEach((filter, index) => {
      const chip = document.createElement("button");
      chip.type = "button";
      const label = `${fields[filter.field].label} ${operators[filter.op]}${filter.value ? `: ${filter.value}` : ""}`;
      chip.textContent = `${label} ×`;
      chip.setAttribute("aria-label", `Remove filter: ${label}`);
      chip.addEventListener("click", () => {
        filters.splice(index, 1);
        render();
        onChange();
        (chips.children[index] || chips.lastElementChild || add).focus();
      });
      chips.append(chip);
    });
    status.textContent = filters.length ? `${filters.length} additional filters applied` : "No additional filters";
  }
  function suggest() {
    suggestions.replaceChildren();
    (fields[field.value].options?.() || []).forEach((text) => {
      const option = document.createElement("option");
      option.value = text;
      suggestions.append(option);
    });
  }
  field.addEventListener("change", () => { value.value = ""; suggest(); });
  value.addEventListener("focus", suggest);
  operator.addEventListener("change", () => {
    value.disabled = ["missing", "present"].includes(operator.value);
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = value.disabled ? "" : value.value.trim();
    if (!value.disabled && !text) { status.textContent = "Enter a filter value."; value.focus(); return; }
    const filter = { field: field.value, op: operator.value, value: text };
    if (!filters.some((entry) => entry.field === filter.field && entry.op === filter.op && entry.value.toLowerCase() === text.toLowerCase())) filters.push(filter);
    value.value = "";
    render();
    onChange();
    (value.disabled ? add : value).focus();
  });
  clear.addEventListener("click", () => { filters = []; render(); onClear(); onChange(); });
  render();
  return {
    serialize: () => JSON.stringify(filters),
    restore(raw) {
      try {
        const parsed = JSON.parse(raw || "[]");
        filters = Array.isArray(parsed) ? parsed.filter((f) => f && Object.hasOwn(fields, f.field) && Object.hasOwn(operators, f.op) && typeof f.value === "string" && (["missing", "present"].includes(f.op) || f.value.trim())) : [];
      } catch (_) { filters = []; }
      render();
    },
    matches(record) {
      const groups = new Map();
      for (const filter of filters) {
        if (!groups.has(filter.field)) groups.set(filter.field, []);
        groups.get(filter.field).push(filter);
      }
      return [...groups].every(([key, group]) => {
        const values = fields[key].values(record).filter((v) => v != null && String(v) !== "").map((v) => String(v).toLowerCase());
        const matches = (f) => {
          if (f.op === "missing") return values.length === 0;
          if (f.op === "present") return values.length > 0;
          const match = values.some((v) => f.op.endsWith("equals") ? v === f.value.toLowerCase() : v.includes(f.value.toLowerCase()));
          return f.op.startsWith("not_") ? !match : match;
        };
        const includes = group.filter((f) => !f.op.startsWith("not_") && f.op !== "present");
        const excludes = group.filter((f) => f.op.startsWith("not_") || f.op === "present");
        return (!includes.length || includes.some(matches)) && excludes.every(matches);
      });
    },
  };
}
// END finding filter builder.
