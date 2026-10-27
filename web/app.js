/*
 * local-redact browser app. All processing happens here, in this tab.
 * The page's Content-Security-Policy blocks network requests and HTML
 * injection sinks, so everything is built with textContent and createElement.
 */
(function () {
  "use strict";

  var E = window.LocalRedact;
  var SAMPLES = window.LOCAL_REDACT_SAMPLES || [];
  var FAMILY = {
    EMAIL: "contact", PHONE: "contact",
    IBAN: "money", CARD: "money",
    EMIRATES_ID: "identity", SAUDI_ID: "identity", AADHAAR: "identity", IN_PAN: "identity",
    IP_ADDRESS: "tech", SECRET: "tech",
  };
  var STORAGE_KEY = "local-redact:settings:v1";
  var PLACEHOLDER = /<([A-Z][A-Z0-9_]*)_[0-9]+>/g;
  var MAX_FILE_BYTES = 10 * 1024 * 1024;

  var state = {
    disabled: [], // type names switched off (built-in or custom)
    allowlist: [],
    custom: [], // [{type, regex}]
    result: null, // last redact() result
    loadedMapping: null, // mapping read from a file, used for restore
  };

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function familyClass(type) {
    return "fam-" + (FAMILY[type] || "custom");
  }

  function typeOfPlaceholder(ph) {
    var inner = ph.slice(1, -1);
    return inner.slice(0, inner.lastIndexOf("_"));
  }

  // ---------------------------------------------------------- settings

  function loadSettings() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      var saved = JSON.parse(raw);
      if (Array.isArray(saved.disabled)) state.disabled = saved.disabled.filter(isString);
      if (Array.isArray(saved.allowlist)) state.allowlist = saved.allowlist.filter(isString);
      if (Array.isArray(saved.custom)) {
        state.custom = saved.custom.filter(function (c) {
          return c && isString(c.type) && isString(c.regex);
        });
        try {
          E.compileCustom(state.custom);
        } catch (e) {
          state.custom = [];
        }
      }
    } catch (e) {
      /* storage unavailable or corrupt: start with defaults */
    }
  }

  function saveSettings() {
    try {
      window.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ disabled: state.disabled, allowlist: state.allowlist, custom: state.custom })
      );
    } catch (e) {
      /* private mode or blocked storage: settings last for this visit only */
    }
  }

  function isString(x) {
    return typeof x === "string";
  }

  function isOn(type) {
    return state.disabled.indexOf(type) === -1;
  }

  function options(withAllowlist) {
    return {
      types: E.detectorIds().filter(isOn),
      custom: state.custom.filter(function (c) {
        return isOn(c.type);
      }),
      allowlist: withAllowlist ? state.allowlist : [],
    };
  }

  // ------------------------------------------------------------ render

  function render() {
    var text = $("input").value;
    var result;
    var review;
    try {
      result = E.redact(text, options(true));
      review = E.detect(text, options(false));
      $("custom-error").textContent = "";
    } catch (err) {
      $("custom-error").textContent = err.message;
      return;
    }
    state.result = result;
    renderReview(text, review);
    renderOutput(text, result);
    renderChips(result.detections);
    renderSummary(text, result.detections);
    renderMapping();
    renderRestore();
  }

  function renderReview(text, detections) {
    var box = $("review");
    var allowed = {};
    state.allowlist.forEach(function (a) {
      allowed[a.trim().toLowerCase()] = true;
    });
    var frag = document.createDocumentFragment();
    var last = 0;
    detections.forEach(function (d) {
      frag.appendChild(document.createTextNode(text.slice(last, d.start)));
      var kept = Object.prototype.hasOwnProperty.call(allowed, d.text.trim().toLowerCase());
      var mark = el("mark", "hl " + familyClass(d.type) + (kept ? " kept" : ""));
      mark.tabIndex = 0;
      mark.setAttribute("role", "button");
      mark.setAttribute("aria-pressed", kept ? "true" : "false");
      mark.setAttribute("aria-label", (kept ? "Kept: " : "Will be redacted as " + d.type + ": ") + d.text);
      mark.dataset.value = d.text;
      mark.appendChild(document.createTextNode(d.text));
      mark.appendChild(el("span", "tag", kept ? "KEPT" : d.type));
      frag.appendChild(mark);
      last = d.end;
    });
    frag.appendChild(document.createTextNode(text.slice(last)));
    box.replaceChildren(frag);
  }

  function renderOutput(text, result) {
    var frag = document.createDocumentFragment();
    var last = 0;
    result.detections.forEach(function (d, i) {
      frag.appendChild(document.createTextNode(text.slice(last, d.start)));
      var span = el("span", "ph " + familyClass(d.type), result.placeholders[i]);
      span.title = d.type;
      frag.appendChild(span);
      last = d.end;
    });
    frag.appendChild(document.createTextNode(text.slice(last)));
    $("output").replaceChildren(text ? frag : document.createDocumentFragment());
    $("copy-output").disabled = !text;
  }

  function renderChips(detections) {
    var counts = {};
    detections.forEach(function (d) {
      counts[d.type] = (counts[d.type] || 0) + 1;
    });
    var box = $("chips");
    var focusedType = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.type : null;
    box.replaceChildren();
    var entries = E.spec.map(function (d) {
      return { type: d.id, title: d.label + ". " + d.validation + "." };
    });
    state.custom.forEach(function (c) {
      entries.push({ type: c.type, title: "Custom pattern: " + c.regex });
    });
    entries.forEach(function (entry) {
      var on = isOn(entry.type);
      var n = counts[entry.type] || 0;
      var chip = el("button", "chip " + familyClass(entry.type));
      chip.type = "button";
      chip.dataset.type = entry.type;
      chip.title = entry.title;
      chip.setAttribute("aria-pressed", on ? "true" : "false");
      chip.setAttribute("aria-label", entry.type + ", " + (on ? n + " found, on" : "off"));
      chip.appendChild(el("span", "name", entry.type));
      chip.appendChild(el("span", "n", on ? String(n) : "off"));
      box.appendChild(chip);
      if (entry.type === focusedType) chip.focus();
    });
  }

  function renderSummary(text, detections) {
    var line = $("summary");
    if (!text) {
      line.textContent = "Nothing to redact yet.";
      return;
    }
    if (!detections.length) {
      line.textContent = "Nothing found. Check for names, addresses and anything else this tool cannot see.";
      return;
    }
    var counts = {};
    detections.forEach(function (d) {
      counts[d.type] = (counts[d.type] || 0) + 1;
    });
    var parts = Object.keys(counts).map(function (t) {
      return t + " " + counts[t];
    });
    line.textContent =
      detections.length + (detections.length === 1 ? " value" : " values") + " replaced: " + parts.join(", ") + ".";
  }

  function activeMapping() {
    return state.loadedMapping || (state.result ? state.result.mapping : new E.Mapping());
  }

  function renderMapping() {
    var mapping = activeMapping();
    var keys = Object.keys(mapping.placeholders);
    var show = $("show-values").checked;
    var body = $("mapping-table").tBodies[0];
    body.replaceChildren();
    keys.forEach(function (ph) {
      var row = el("tr");
      var a = el("td");
      a.appendChild(el("span", "token", ph));
      var value = mapping.placeholders[ph];
      var b = el("td", show ? "" : "masked", show ? value : "•".repeat(Math.min(12, Math.max(6, value.length))));
      row.appendChild(a);
      row.appendChild(b);
      body.appendChild(row);
    });
    $("mapping-count").textContent = keys.length ? "(" + keys.length + (state.loadedMapping ? ", from file" : "") + ")" : "";
    $("download-mapping").disabled = !keys.length;
  }

  function renderRestore() {
    var answer = $("answer").value;
    var mapping = activeMapping();
    var box = $("restored");
    if (!answer) {
      box.replaceChildren();
      $("restore-summary").textContent = "";
      $("copy-restored").disabled = true;
      return;
    }
    var frag = document.createDocumentFragment();
    var last = 0;
    var m;
    PLACEHOLDER.lastIndex = 0;
    while ((m = PLACEHOLDER.exec(answer)) !== null) {
      frag.appendChild(document.createTextNode(answer.slice(last, m.index)));
      var ph = m[0];
      if (Object.prototype.hasOwnProperty.call(mapping.placeholders, ph)) {
        var span = el("span", "restored " + familyClass(typeOfPlaceholder(ph)), mapping.placeholders[ph]);
        span.title = ph;
        frag.appendChild(span);
      } else {
        frag.appendChild(el("span", "unknown", ph));
      }
      last = m.index + ph.length;
    }
    frag.appendChild(document.createTextNode(answer.slice(last)));
    box.replaceChildren(frag);

    var r = E.restore(answer, mapping);
    var msg = r.restored + (r.restored === 1 ? " placeholder" : " placeholders") + " restored.";
    if (r.unknown.length) msg += " Not in the mapping, left as they are: " + r.unknown.join(", ") + ".";
    if (!Object.keys(mapping.placeholders).length) msg = "No mapping yet. Redact some text above first, or load a mapping file.";
    $("restore-summary").textContent = msg;
    $("copy-restored").disabled = false;
  }

  function renderCustomList() {
    var list = $("custom-list");
    list.replaceChildren();
    state.custom.forEach(function (c, i) {
      var li = el("li");
      li.appendChild(el("span", "token", "<" + c.type + "_n>"));
      li.appendChild(el("code", "", c.regex));
      var remove = el("button", "button button-quiet", "Remove");
      remove.type = "button";
      remove.dataset.index = String(i);
      remove.setAttribute("aria-label", "Remove " + c.type);
      li.appendChild(remove);
      list.appendChild(li);
    });
    $("custom-count").textContent = state.custom.length ? "(" + state.custom.length + ")" : "";
  }

  function renderAllowCount() {
    $("allow-count").textContent = state.allowlist.length ? "(" + state.allowlist.length + ")" : "";
  }

  // ------------------------------------------------------------ actions

  var timer = null;
  function scheduleRender() {
    window.clearTimeout(timer);
    timer = window.setTimeout(render, 120);
  }

  function setView(view) {
    var review = view === "review";
    $("tab-edit").setAttribute("aria-selected", review ? "false" : "true");
    $("tab-review").setAttribute("aria-selected", review ? "true" : "false");
    $("input").hidden = review;
    $("review").hidden = !review;
    if (!review) $("input").focus();
  }

  function setInput(text, note) {
    $("input").value = text;
    render();
    setView(text ? "review" : "edit");
    $("review-hint").textContent =
      note || "In review, select a highlight to keep that value (it is added to the allowlist).";
  }

  function toggleAllow(value) {
    var key = value.trim().toLowerCase();
    var i = -1;
    state.allowlist.forEach(function (a, idx) {
      if (a.trim().toLowerCase() === key) i = idx;
    });
    if (i === -1) state.allowlist.push(value);
    else state.allowlist.splice(i, 1);
    $("allowlist").value = state.allowlist.join("\n");
    renderAllowCount();
    saveSettings();
    render();
  }

  function copyText(text, button, label) {
    function done() {
      button.textContent = "Copied";
      button.classList.add("done");
      window.setTimeout(function () {
        button.textContent = label;
        button.classList.remove("done");
      }, 1600);
    }
    function fallback() {
      var area = el("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "visually-hidden";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        done();
      } finally {
        document.body.removeChild(area);
      }
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  function download(filename, data) {
    var blob = new Blob([JSON.stringify(data, null, 2) + "\n"], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = el("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  function readFile(file, onText) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      $("review-hint").textContent = "That file is over 10 MB. Split it, or use the command-line tool.";
      return;
    }
    file.text().then(onText, function () {
      $("review-hint").textContent = "Could not read that file as text.";
    });
  }

  // ----------------------------------------------------------- wiring

  function buildExamples() {
    var box = $("examples");
    SAMPLES.forEach(function (sample) {
      var b = el("button", "button", sample.title);
      b.type = "button";
      b.dataset.example = sample.id;
      b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", function () {
        var added = [];
        (sample.custom || []).forEach(function (c) {
          var exists = state.custom.some(function (x) {
            return x.type === c.type;
          });
          if (!exists) {
            state.custom.push({ type: c.type, regex: c.regex });
            added.push(c.type);
          }
          var off = state.disabled.indexOf(c.type);
          if (off !== -1) state.disabled.splice(off, 1);
        });
        if (added.length) {
          saveSettings();
          renderCustomList();
        }
        Array.prototype.forEach.call(box.children, function (other) {
          other.setAttribute("aria-pressed", other === b ? "true" : "false");
        });
        setInput(
          sample.text,
          added.length
            ? "This example uses its own claim and policy number formats, so " + added.join(" and ") + " were added as custom patterns."
            : "Synthetic example. Select a highlight to keep that value."
        );
      });
      box.appendChild(b);
    });
  }

  function drawGuilloche() {
    var svg = $("guilloche");
    var NS = "http://www.w3.org/2000/svg";
    var W = 1200;
    var H = 220;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("preserveAspectRatio", "none");
    var lines = 22;
    for (var i = 0; i < lines; i++) {
      var phase = (i / lines) * Math.PI * 2;
      var d = "";
      for (var x = 0; x <= W; x += 3) {
        var t = (x / W) * Math.PI * 2;
        var y =
          H * 0.5 +
          H * 0.3 * Math.sin(t * 3 + phase) * Math.cos(t * 5 - phase / 2) +
          H * 0.07 * Math.sin(t * 17 + phase * 2);
        d += (x === 0 ? "M" : "L") + x + " " + y.toFixed(1);
      }
      var path = document.createElementNS(NS, "path");
      path.setAttribute("d", d);
      path.setAttribute("class", i % 2 ? "ga" : "gb");
      svg.appendChild(path);
    }
  }

  function checkPolicy() {
    var meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    var policy = meta ? meta.getAttribute("content") : "";
    if (policy.indexOf("connect-src 'none'") === -1) {
      $("privacy").classList.add("off");
      $("privacy-status").textContent = "This copy of the page does not block network access";
    }
  }

  function init() {
    loadSettings();
    drawGuilloche();
    checkPolicy();
    buildExamples();
    $("version").textContent = "Version " + E.version + ".";
    $("output").dataset.empty = "The redacted text appears here.";
    $("review").dataset.empty = "Nothing to review yet. Paste some text or try an example.";
    $("restored").dataset.empty = "The answer with real values appears here.";
    $("allowlist").value = state.allowlist.join("\n");
    renderAllowCount();
    renderCustomList();

    $("input").addEventListener("input", function () {
      Array.prototype.forEach.call($("examples").children, function (b) {
        b.setAttribute("aria-pressed", "false");
      });
      scheduleRender();
    });
    $("input").addEventListener("paste", function () {
      // After a paste into an empty box, jump to the review so people see what was found.
      var wasEmpty = !$("input").value;
      window.setTimeout(function () {
        render();
        if (wasEmpty && $("input").value) setView("review");
      }, 0);
    });
    $("tab-edit").addEventListener("click", function () {
      setView("edit");
    });
    $("tab-review").addEventListener("click", function () {
      render();
      setView("review");
    });

    $("review").addEventListener("click", function (ev) {
      var mark = ev.target.closest("mark.hl");
      if (mark) toggleAllow(mark.dataset.value);
    });
    $("review").addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      var mark = ev.target.closest("mark.hl");
      if (!mark) return;
      ev.preventDefault();
      var value = mark.dataset.value;
      toggleAllow(value);
      var again = Array.prototype.find.call($("review").querySelectorAll("mark.hl"), function (m) {
        return m.dataset.value === value;
      });
      if (again) again.focus();
    });

    $("chips").addEventListener("click", function (ev) {
      var chip = ev.target.closest(".chip");
      if (!chip) return;
      var type = chip.dataset.type;
      var i = state.disabled.indexOf(type);
      if (i === -1) state.disabled.push(type);
      else state.disabled.splice(i, 1);
      saveSettings();
      render();
    });

    $("copy-output").addEventListener("click", function () {
      if (state.result) copyText(state.result.text, $("copy-output"), "Copy redacted text");
    });
    $("copy-restored").addEventListener("click", function () {
      copyText(E.restore($("answer").value, activeMapping()).text, $("copy-restored"), "Copy restored text");
    });
    $("answer").addEventListener("input", renderRestore);

    $("clear").addEventListener("click", function () {
      $("answer").value = "";
      state.loadedMapping = null;
      Array.prototype.forEach.call($("examples").children, function (b) {
        b.setAttribute("aria-pressed", "false");
      });
      setInput("");
    });

    $("file-input").addEventListener("change", function (ev) {
      var file = ev.target.files[0];
      readFile(file, function (text) {
        setInput(text, "Loaded " + file.name + " from this device.");
      });
      ev.target.value = "";
    });

    var zone = $("drop-zone");
    zone.addEventListener("dragover", function (ev) {
      ev.preventDefault();
      zone.classList.add("dragging");
    });
    zone.addEventListener("dragleave", function () {
      zone.classList.remove("dragging");
    });
    zone.addEventListener("drop", function (ev) {
      ev.preventDefault();
      zone.classList.remove("dragging");
      var file = ev.dataTransfer && ev.dataTransfer.files[0];
      readFile(file, function (text) {
        setInput(text, "Loaded " + file.name + " from this device.");
      });
    });
    // Dropping a file anywhere else would open it in the tab and lose the work.
    window.addEventListener("dragover", function (ev) {
      ev.preventDefault();
    });
    window.addEventListener("drop", function (ev) {
      ev.preventDefault();
    });

    $("allowlist").addEventListener("input", function () {
      state.allowlist = $("allowlist")
        .value.split("\n")
        .map(function (s) {
          return s.trim();
        })
        .filter(Boolean);
      renderAllowCount();
      saveSettings();
      scheduleRender();
    });

    $("custom-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var name = $("custom-name").value.trim().toUpperCase().replace(/[ -]+/g, "_");
      var regex = $("custom-regex").value;
      var error = $("custom-error");
      if (!name || !regex) {
        error.textContent = "Give the pattern a name and a regular expression.";
        return;
      }
      if (state.custom.some(function (c) { return c.type === name; })) {
        error.textContent = "There is already a pattern called " + name + ".";
        return;
      }
      try {
        E.compileCustom([{ type: name, regex: regex }]);
        if (new RegExp(regex).test("")) throw new Error("That pattern matches empty text, so it would match everywhere.");
      } catch (err) {
        error.textContent = err.message;
        return;
      }
      error.textContent = "";
      state.custom.push({ type: name, regex: regex });
      $("custom-name").value = "";
      $("custom-regex").value = "";
      saveSettings();
      renderCustomList();
      render();
    });

    $("custom-list").addEventListener("click", function (ev) {
      var button = ev.target.closest("button[data-index]");
      if (!button) return;
      var removed = state.custom.splice(Number(button.dataset.index), 1)[0];
      var off = state.disabled.indexOf(removed.type);
      if (off !== -1) state.disabled.splice(off, 1);
      saveSettings();
      renderCustomList();
      render();
    });

    $("show-values").addEventListener("change", renderMapping);
    $("download-mapping").addEventListener("click", function () {
      download("local-redact-mapping.json", activeMapping().toJSON());
    });
    $("mapping-file").addEventListener("change", function (ev) {
      var file = ev.target.files[0];
      readFile(file, function (text) {
        try {
          state.loadedMapping = E.Mapping.fromJSON(JSON.parse(text));
          renderMapping();
          renderRestore();
          $("restore-summary").textContent = "Loaded " + file.name + ". " + $("restore-summary").textContent;
        } catch (err) {
          $("restore-summary").textContent = file.name + " is not a local-redact mapping file.";
        }
      });
      ev.target.value = "";
    });
    $("export-settings").addEventListener("click", function () {
      var opts = options(true);
      download("local-redact-settings.json", { types: opts.types, allowlist: opts.allowlist, custom: opts.custom });
    });

    render();

    // Links such as index.html#example=claim-note open with that example loaded.
    var wanted = /^#example=([a-z-]+)$/.exec(window.location.hash);
    if (wanted) {
      var button = $("examples").querySelector('[data-example="' + wanted[1] + '"]');
      if (button) button.click();
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
