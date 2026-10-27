// Runs the shared fixture corpus against the browser engine (web/engine.js).
// tests/test_corpus.py runs the same files against the Python package.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const E = require(path.join(ROOT, "web", "engine.js"));
const load = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", name), "utf8"));

function options(c) {
  const o = c.options || {};
  return { types: o.types || null, allowlist: o.allowlist || [], custom: o.custom || [] };
}

test("bundled spec matches patterns/*.json", () => {
  const dir = path.join(ROOT, "patterns");
  const fromFiles = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")))
    .sort((a, b) => a.order - b.order);
  assert.deepEqual(E.spec, fromFiles);
});

for (const c of [...load("cases.json"), ...load("generated.json")]) {
  test(`case: ${c.name}`, () => {
    const found = E.detect(c.text, options(c)).map((d) => [d.type, d.text]);
    assert.deepEqual(found, c.expect);
    const result = E.redact(c.text, options(c), new E.Mapping(c.mapping || {}));
    if ("redacted" in c) assert.equal(result.text, c.redacted);
    assert.equal(E.restore(result.text, result.mapping).text, c.text);
  });
}

const samples = Object.fromEntries(JSON.parse(fs.readFileSync(path.join(ROOT, "samples", "index.json"), "utf8")).map((s) => [s.id, s]));
for (const expected of load("samples.expected.json")) {
  test(`sample matches the Python snapshot: ${expected.id}`, () => {
    const sample = samples[expected.id];
    const text = fs.readFileSync(path.join(ROOT, "samples", sample.file), "utf8");
    const result = E.redact(text, { custom: sample.custom || [] });
    assert.deepEqual(result.detections.map((d) => [d.type, d.text, d.pattern]), expected.detections);
    assert.equal(result.text, expected.redacted);
  });
}

for (const d of E.spec) {
  test(`spec examples: ${d.id}`, () => {
    for (const v of d.examples.valid) {
      assert.deepEqual(E.detect(`x ${v} y`).map((x) => [x.type, x.text]), [[d.id, v]], v);
    }
    for (const v of d.examples.invalid) {
      assert.ok(!E.detect(`x ${v} y`).some((x) => x.type === d.id), v);
    }
  });
}

test("checksum vectors", () => {
  const vectors = load("checksums.json");
  const fns = { luhn: E._validators.luhnOk, verhoeff: E._validators.verhoeffOk, mod97: E._validators.mod97Ok };
  for (const [name, fn] of Object.entries(fns)) {
    for (const v of vectors[name].valid) assert.equal(fn(v), true, `${name} ${v}`);
    for (const v of vectors[name].invalid) assert.equal(fn(v), false, `${name} ${v}`);
  }
});

test("restore reports unknown and unused placeholders", () => {
  const m = new E.Mapping({ "<EMAIL_1>": "a@example.com", "<PHONE_1>": "+971 50 000 1234" });
  const r = E.restore("Reply to <EMAIL_1> and <EMAIL_9>", m);
  assert.equal(r.text, "Reply to a@example.com and <EMAIL_9>");
  assert.equal(r.restored, 1);
  assert.deepEqual(r.unknown, ["<EMAIL_9>"]);
  assert.deepEqual(r.unused, ["<PHONE_1>"]);
});

test("mapping JSON round trip and validation", () => {
  const { mapping } = E.redact("a@example.com");
  const again = E.Mapping.fromJSON(JSON.parse(JSON.stringify(mapping)));
  assert.deepEqual(again.placeholders, { "<EMAIL_1>": "a@example.com" });
  assert.throws(() => E.Mapping.fromJSON({ format: "other" }));
  assert.throws(() => E.Mapping.fromJSON({ format: "local-redact-mapping", placeholders: { "EMAIL_1": "x" } }));
});

test("custom pattern errors are reported", () => {
  assert.throws(() => E.detect("x", { custom: [{ type: "bad name", regex: "x" }] }), /capitals/);
  assert.throws(() => E.detect("x", { custom: [{ type: "EMAIL", regex: "x" }] }), /clashes/);
  assert.throws(() => E.detect("x", { custom: [{ type: "OK", regex: "(" }] }), /Custom pattern OK/);
});
