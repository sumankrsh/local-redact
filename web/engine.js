/*
 * local-redact detection engine (browser and Node).
 *
 * This is a line-for-line port of src/local_redact/engine.py and
 * validators.py. Both read the same pattern spec (patterns/*.json, bundled
 * into web/patterns.js) and pass the same fixtures in tests/fixtures.
 *
 * No network access, no dependencies.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./patterns.js"));
  } else {
    root.LocalRedact = factory(root.LOCAL_REDACT_SPEC);
  }
})(typeof self !== "undefined" ? self : this, function (SPEC) {
  "use strict";

  var CUSTOM_PRIORITY = 100;
  var TYPE_NAME_RE = /^[A-Z][A-Z0-9_]{0,31}$/;
  var PLACEHOLDER_SOURCE = "<[A-Z][A-Z0-9_]*_[0-9]+>";

  // ------------------------------------------------------------ validators

  function digitsOnly(text) {
    var out = "";
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (ch >= "0" && ch <= "9") out += ch;
    }
    return out;
  }

  function hasPrefix(digits, prefixes) {
    for (var i = 0; i < prefixes.length; i++) {
      var prefix = prefixes[i];
      if (prefix.indexOf("-") !== -1) {
        var bounds = prefix.split("-");
        var head = digits.slice(0, bounds[0].length);
        if (
          head.length === bounds[0].length &&
          parseInt(bounds[0], 10) <= parseInt(head, 10) &&
          parseInt(head, 10) <= parseInt(bounds[1], 10)
        ) {
          return true;
        }
      } else if (digits.slice(0, prefix.length) === prefix) {
        return true;
      }
    }
    return false;
  }

  // Luhn (mod 10), ISO/IEC 7812-1 Annex B. https://en.wikipedia.org/wiki/Luhn_algorithm
  function luhnOk(digits) {
    var total = 0;
    for (var i = 0; i < digits.length; i++) {
      var d = digits.charCodeAt(digits.length - 1 - i) - 48;
      if (i % 2 === 1) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      total += d;
    }
    return total % 10 === 0;
  }

  // Verhoeff tables. https://en.wikipedia.org/wiki/Verhoeff_algorithm
  var VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  var VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  function verhoeffOk(digits) {
    var check = 0;
    for (var i = 0; i < digits.length; i++) {
      var d = digits.charCodeAt(digits.length - 1 - i) - 48;
      check = VERHOEFF_D[check][VERHOEFF_P[i % 8][d]];
    }
    return check === 0;
  }

  // ISO 13616 / ISO 7064 MOD 97-10.
  function mod97Ok(iban) {
    var rearranged = iban.slice(4) + iban.slice(0, 4);
    var remainder = 0;
    for (var i = 0; i < rearranged.length; i++) {
      var value = parseInt(rearranged[i], 36);
      remainder = (remainder * (value > 9 ? 100 : 10) + value) % 97;
    }
    return remainder === 1;
  }

  function lengthOk(digits, params) {
    var min = params.min_length !== undefined ? params.min_length : 0;
    var max = params.max_length !== undefined ? params.max_length : 1e6;
    return min <= digits.length && digits.length <= max;
  }

  function validateLuhn(text, params) {
    var digits = digitsOnly(text);
    if (!lengthOk(digits, params)) return null;
    if (params.prefixes && !hasPrefix(digits, params.prefixes)) return null;
    return luhnOk(digits) ? text.length : null;
  }

  function validateVerhoeff(text, params) {
    var digits = digitsOnly(text);
    if (!lengthOk(digits, params)) return null;
    if (params.prefixes && !hasPrefix(digits, params.prefixes)) return null;
    if (params.reject_palindromes && digits === digits.split("").reverse().join("")) return null;
    return verhoeffOk(digits) ? text.length : null;
  }

  function validateIban(text, params) {
    var lengths = params.lengths;
    var country = text.slice(0, 2);
    if (!Object.prototype.hasOwnProperty.call(lengths, country)) return null;
    var want = lengths[country];
    var compact = "";
    var keep = 0;
    for (var i = 0; i < text.length; i++) {
      if (text[i] !== " ") {
        compact += text[i];
        if (compact.length === want) {
          keep = i + 1;
          break;
        }
      }
    }
    if (compact.length < want) return null;
    if (keep < text.length && text[keep] !== " ") return null;
    return mod97Ok(compact) ? keep : null;
  }

  function validateE164(text, params) {
    var digits = digitsOnly(text);
    if (text.slice(0, 2) === "00") digits = digits.slice(2);
    var min = params.min_digits !== undefined ? params.min_digits : 0;
    var max = params.max_digits !== undefined ? params.max_digits : 15;
    return min <= digits.length && digits.length <= max ? text.length : null;
  }

  function ipv4Ok(text) {
    var parts = text.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (!part || part.length > 3 || !/^[0-9]+$/.test(part)) return false;
      if (part.length > 1 && part[0] === "0") return false;
      if (parseInt(part, 10) > 255) return false;
    }
    return true;
  }

  function validateIpv4(text) {
    return ipv4Ok(text) ? text.length : null;
  }

  function validateIpv6(text, params) {
    if (text.indexOf(":::") !== -1) return null;
    var first = text.indexOf("::");
    if (first !== -1 && text.indexOf("::", first + 2) !== -1) return null;
    var compressed = first !== -1;
    var groups;
    if (compressed) {
      var head = text.slice(0, first);
      var tail = text.slice(first + 2);
      groups = (head ? head.split(":") : []).concat(tail ? tail.split(":") : []);
    } else {
      groups = text.split(":");
    }
    var width = groups.length;
    var nonEmpty = groups.length;
    if (groups.length && groups[groups.length - 1].indexOf(".") !== -1) {
      if (!ipv4Ok(groups[groups.length - 1])) return null;
      groups = groups.slice(0, -1);
      width += 1;
      nonEmpty += 1;
    }
    for (var i = 0; i < groups.length; i++) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(groups[i])) return null;
    }
    if (compressed && width > 7) return null;
    if (!compressed && width !== 8) return null;
    if (nonEmpty < (params.min_groups || 0)) return null;
    return text.length;
  }

  function base64UrlToBytes(part) {
    var b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var binary = atob(b64); // throws on malformed input
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function validateJwt(text) {
    var header = text.split(".")[0];
    var decoded;
    try {
      var json = new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(header));
      decoded = JSON.parse(json);
    } catch (e) {
      return null;
    }
    if (decoded && typeof decoded === "object" && !Array.isArray(decoded) && typeof decoded.alg === "string") {
      return text.length;
    }
    return null;
  }

  var VALIDATORS = {
    luhn: validateLuhn,
    verhoeff: validateVerhoeff,
    iban: validateIban,
    e164: validateE164,
    ipv4: validateIpv4,
    ipv6: validateIpv6,
    jwt: validateJwt,
  };

  function runValidator(name, text, params) {
    if (!name) return text.length;
    return VALIDATORS[name](text, params || {});
  }

  // ------------------------------------------------------------- detection

  var builtinSpec = SPEC.detectors.slice().sort(function (a, b) {
    return a.order - b.order;
  });

  function compile(detectors) {
    return detectors.map(function (det) {
      return {
        id: det.id,
        priority: det.priority,
        patterns: det.patterns.map(function (p) {
          return { name: p.name, regex: new RegExp(p.regex, "g"), validator: p.validator || null, params: p.params || {} };
        }),
      };
    });
  }

  var builtin = compile(builtinSpec);

  function detectorIds() {
    return builtinSpec.map(function (d) {
      return d.id;
    });
  }

  function compileCustom(custom) {
    var ids = detectorIds();
    return (custom || []).map(function (item) {
      var name = item.type;
      if (!TYPE_NAME_RE.test(name)) {
        throw new Error("Custom type name '" + name + "' must be capitals, digits and _, starting with a letter");
      }
      if (ids.indexOf(name) !== -1) {
        throw new Error("Custom type name '" + name + "' clashes with a built-in type");
      }
      var regex;
      try {
        regex = new RegExp(item.regex, "g");
      } catch (e) {
        throw new Error("Custom pattern " + name + ": " + e.message);
      }
      return { id: name, priority: CUSTOM_PRIORITY, patterns: [{ name: name, regex: regex, validator: null, params: {} }] };
    });
  }

  function compareCandidates(a, b) {
    for (var i = 0; i < 5; i++) {
      if (a.key[i] !== b.key[i]) return a.key[i] - b.key[i];
    }
    return 0;
  }

  /**
   * Find sensitive values in text.
   * options.types: built-in type ids to use (default all). Custom patterns always run.
   * options.allowlist: values never to redact (case-insensitive exact match).
   * options.custom: [{type: "POLICY_NO", regex: "POL-[0-9]{6}"}]
   * Returns [{type, start, end, text, pattern}] sorted by start (UTF-16 offsets).
   */
  function detect(text, options) {
    options = options || {};
    var wanted = options.types ? options.types : null;
    var allowed = {};
    (options.allowlist || []).forEach(function (a) {
      var key = a.trim().toLowerCase();
      if (key) allowed[key] = true;
    });
    var detectors = builtin.filter(function (d) {
      return wanted === null || wanted.indexOf(d.id) !== -1;
    });
    detectors = detectors.concat(compileCustom(options.custom));

    var candidates = [];
    detectors.forEach(function (det, dIndex) {
      det.patterns.forEach(function (pat, pIndex) {
        pat.regex.lastIndex = 0;
        var m;
        while ((m = pat.regex.exec(text)) !== null) {
          if (m[0].length === 0) {
            pat.regex.lastIndex += 1;
            continue;
          }
          var start = m.index;
          var keep = runValidator(pat.validator, m[0], pat.params);
          if (keep === null) continue;
          var end = start + keep;
          var value = text.slice(start, end);
          if (Object.prototype.hasOwnProperty.call(allowed, value.trim().toLowerCase())) continue;
          candidates.push({
            key: [-(end - start), -det.priority, start, dIndex, pIndex],
            type: det.id,
            start: start,
            end: end,
            text: value,
            pattern: pat.name,
          });
        }
      });
    });

    // Overlaps: the longest match wins, then the higher priority, then the earliest.
    candidates.sort(compareCandidates);
    var accepted = [];
    candidates.forEach(function (c) {
      var lo = 0;
      var hi = accepted.length;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (accepted[mid].start < c.start) lo = mid + 1;
        else hi = mid;
      }
      if (lo > 0 && accepted[lo - 1].end > c.start) return;
      if (lo < accepted.length && accepted[lo].start < c.end) return;
      accepted.splice(lo, 0, { type: c.type, start: c.start, end: c.end, text: c.text, pattern: c.pattern });
    });
    return accepted;
  }

  // -------------------------------------------------- redaction and restore

  function Mapping(placeholders) {
    this.placeholders = {};
    this._reverse = {};
    this._next = {};
    var self = this;
    Object.keys(placeholders || {}).forEach(function (ph) {
      var value = placeholders[ph];
      var inner = ph.slice(1, -1);
      var cut = inner.lastIndexOf("_");
      var type = inner.slice(0, cut);
      var number = parseInt(inner.slice(cut + 1), 10);
      self.placeholders[ph] = value;
      self._reverse[type + "\u0000" + value] = ph;
      self._next[type] = Math.max(self._next[type] || 1, number + 1);
    });
  }

  Mapping.prototype.placeholderFor = function (type, value, sourceText) {
    var key = type + "\u0000" + value;
    if (Object.prototype.hasOwnProperty.call(this._reverse, key)) return this._reverse[key];
    var n = this._next[type] || 1;
    while (sourceText.indexOf("<" + type + "_" + n + ">") !== -1) n += 1;
    var ph = "<" + type + "_" + n + ">";
    this._next[type] = n + 1;
    this._reverse[key] = ph;
    this.placeholders[ph] = value;
    return ph;
  };

  Mapping.prototype.toJSON = function () {
    return { format: "local-redact-mapping", version: 1, placeholders: this.placeholders };
  };

  Mapping.fromJSON = function (data) {
    if (!data || data.format !== "local-redact-mapping") throw new Error("Not a local-redact mapping file");
    var placeholders = data.placeholders || {};
    var full = new RegExp("^" + PLACEHOLDER_SOURCE + "$");
    Object.keys(placeholders).forEach(function (ph) {
      if (!full.test(ph)) throw new Error("Bad placeholder in mapping: " + ph);
    });
    return new Mapping(placeholders);
  };

  /**
   * Replace each detection with a numbered placeholder such as <EMAIL_1>.
   * Returns {text, detections, placeholders, mapping}.
   */
  function redact(text, options, mapping) {
    mapping = mapping || new Mapping();
    var detections = detect(text, options);
    var parts = [];
    var placeholders = [];
    var last = 0;
    detections.forEach(function (det) {
      var ph = mapping.placeholderFor(det.type, det.text, text);
      placeholders.push(ph);
      parts.push(text.slice(last, det.start));
      parts.push(ph);
      last = det.end;
    });
    parts.push(text.slice(last));
    return { text: parts.join(""), detections: detections, placeholders: placeholders, mapping: mapping };
  }

  /** Put original values back. Returns {text, restored, unknown, unused}. */
  function restore(text, mapping) {
    var used = {};
    var unknown = [];
    var count = 0;
    var out = text.replace(new RegExp(PLACEHOLDER_SOURCE, "g"), function (ph) {
      if (Object.prototype.hasOwnProperty.call(mapping.placeholders, ph)) {
        used[ph] = true;
        count += 1;
        return mapping.placeholders[ph];
      }
      if (unknown.indexOf(ph) === -1) unknown.push(ph);
      return ph;
    });
    var unused = Object.keys(mapping.placeholders).filter(function (ph) {
      return !used[ph];
    });
    return { text: out, restored: count, unknown: unknown, unused: unused };
  }

  return {
    version: SPEC.version,
    spec: builtinSpec,
    detectorIds: detectorIds,
    detect: detect,
    redact: redact,
    restore: restore,
    Mapping: Mapping,
    compileCustom: compileCustom,
    _validators: { luhnOk: luhnOk, verhoeffOk: verhoeffOk, mod97Ok: mod97Ok, runValidator: runValidator },
  };
});
