const STORAGE_KEY = "cipher.workbench.v1";
const ENGLISH = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.36, 0.15, 1.974, 0.074];
const PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
const CIPHERS = {
  caesar: {
    name: "Caesar",
    tag: "SUBSTITUTION",
    desc: "Shift every letter by a fixed amount.",
    formula: "C = (P + k) mod 26",
    security: "Only 25 possible keys. Frequency analysis and a short shift scan break it almost instantly.",
    hint: "A single shift keeps the shape of English letter frequency. That silhouette is the weakness."
  },
  vigenere: {
    name: "Vigenère",
    tag: "POLYALPHABETIC",
    desc: "A keyword drives a repeating sequence of shifts.",
    formula: "Cᵢ = (Pᵢ + Kᵢ) mod 26",
    security: "Stronger than Caesar, but a repeating key leaves periodic patterns. Kasiski and IoC analysis can recover the key length.",
    hint: "A long keyword pushes the index of coincidence toward 0.038. A short one leaves visible periodicity."
  },
  atbash: {
    name: "Atbash",
    tag: "MIRROR",
    desc: "Flip the alphabet from end to end.",
    formula: "C = 25 − P",
    security: "No key and no key space. Atbash is a mirror, not a secret. It is its own inverse.",
    hint: "Atbash preserves the frequency silhouette exactly. It changes the letters, not their rhythm."
  },
  rail: {
    name: "Rail Fence",
    tag: "TRANSPOSITION",
    desc: "Fold the message across a zigzag of rails.",
    formula: "Write on a zigzag, then read rail by rail",
    security: "Letters keep their identities; only their order changes. An anagram attack can reconstruct short rails.",
    hint: "Transposition hides order, not letter frequency. The same letters are still present, just rearranged."
  },
  playfair: {
    name: "Playfair",
    tag: "DIGRAPH",
    desc: "Substitute letter pairs on a 5 × 5 key square.",
    formula: "5 × 5 square · pairs · row, column, rectangle",
    security: "Pair substitution flattens single-letter frequency, but common digraphs still repeat. It is a historical field cipher, not modern encryption.",
    hint: "Digraph substitution hides single letters, but repeated pairs and known plaintext can still expose the square."
  }
};
const SAMPLES = [
  { name: "Field dispatch", text: "Meet me at the old observatory at midnight. Bring the ledger." },
  { name: "Pangram", text: "The quick brown fox jumps over the lazy dog." },
  { name: "Telegraph", text: "Attack at dawn. Hold the eastern bridge until reinforcements arrive." },
  { name: "Coordinates", text: "Coordinates 51.5074 N, 0.1278 W. Package is waiting." }
];

const $ = (id) => document.getElementById(id);
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
let toastTimer = 0;

let state = {
  cipher: "caesar",
  mode: "encode",
  text: SAMPLES[0].text,
  shift: 7,
  vigenereKey: "LEMON",
  rails: 4,
  playfairKey: "CIPHER"
};

function caesar(text, shift, decode) {
  const amount = ((decode ? -shift : shift) % 26 + 26) % 26;
  return [...text].map((char) => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode((code - 65 + amount + 26) % 26 + 65);
    if (code >= 97 && code <= 122) return String.fromCharCode((code - 97 + amount + 26) % 26 + 97);
    return char;
  }).join("");
}

function atbash(text) {
  return [...text].map((char) => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
    if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
    return char;
  }).join("");
}

function normalizeLetters(text) {
  return String(text).toUpperCase().replace(/[^A-Z]/g, "");
}

function vigenere(text, key, decode) {
  const cleaned = normalizeLetters(key) || "KEY";
  let index = 0;
  return [...text].map((char) => {
    const code = char.charCodeAt(0);
    const upper = code >= 65 && code <= 90;
    const lower = code >= 97 && code <= 122;
    if (!upper && !lower) return char;
    const amount = cleaned.charCodeAt(index % cleaned.length) - 65;
    index += 1;
    const base = upper ? 65 : 97;
    const shift = decode ? -amount : amount;
    return String.fromCharCode((code - base + shift + 26) % 26 + base);
  }).join("");
}

function railFence(text, rails, decode) {
  if (rails <= 1 || text.length <= 1) return text;
  const chars = [...text];
  const pattern = [];
  let rail = 0;
  let direction = 1;
  for (let i = 0; i < chars.length; i += 1) {
    pattern.push(rail);
    rail += direction;
    if (rail === 0 || rail === rails - 1) direction *= -1;
  }
  if (!decode) {
    const rows = Array.from({ length: rails }, () => []);
    chars.forEach((char, index) => rows[pattern[index]].push(char));
    return rows.flat().join("");
  }
  const counts = Array(rails).fill(0);
  pattern.forEach((value) => { counts[value] += 1; });
  const rows = [];
  let cursor = 0;
  counts.forEach((count) => {
    rows.push(chars.slice(cursor, cursor + count));
    cursor += count;
  });
  const positions = Array(rails).fill(0);
  return pattern.map((value) => {
    const char = rows[value][positions[value]];
    positions[value] += 1;
    return char;
  }).join("");
}

function playfairGrid(keyword) {
  const source = normalizeLetters(keyword).replace(/J/g, "I") + PLAYFAIR_ALPHABET;
  const seen = new Set();
  const grid = [];
  [...source].forEach((char) => {
    if (!seen.has(char)) {
      seen.add(char);
      grid.push(char);
    }
  });
  return grid;
}

function playfair(text, keyword, decode) {
  const grid = playfairGrid(keyword);
  const positions = new Map();
  grid.forEach((char, index) => positions.set(char, [Math.floor(index / 5), index % 5]));
  let letters = normalizeLetters(text).replace(/J/g, "I");
  if (!letters) return "";

  if (decode) {
    if (letters.length % 2) letters += "X";
    const output = [];
    for (let i = 0; i < letters.length; i += 2) {
      const first = letters[i];
      const second = letters[i + 1];
      const a = positions.get(first);
      const b = positions.get(second);
      if (!a || !b) continue;
      if (a[0] === b[0]) {
        output.push(grid[a[0] * 5 + (a[1] + 4) % 5], grid[b[0] * 5 + (b[1] + 4) % 5]);
      } else if (a[1] === b[1]) {
        output.push(grid[((a[0] + 4) % 5) * 5 + a[1]], grid[((b[0] + 4) % 5) * 5 + b[1]]);
      } else {
        output.push(grid[a[0] * 5 + b[1]], grid[b[0] * 5 + a[1]]);
      }
    }
    return output.join("").replace(/X+$/, "");
  }

  const pairs = [];
  for (let i = 0; i < letters.length;) {
    const first = letters[i];
    let second = letters[i + 1];
    if (!second) {
      pairs.push([first, "X"]);
      i += 1;
    } else if (first === second) {
      pairs.push([first, first === "X" ? "Q" : "X"]);
      i += 1;
    } else {
      pairs.push([first, second]);
      i += 2;
    }
  }
  const output = [];
  pairs.forEach(([first, second]) => {
    const a = positions.get(first);
    const b = positions.get(second);
    if (!a || !b) return;
    if (a[0] === b[0]) {
      output.push(grid[a[0] * 5 + (a[1] + 1) % 5], grid[b[0] * 5 + (b[1] + 1) % 5]);
    } else if (a[1] === b[1]) {
      output.push(grid[((a[0] + 1) % 5) * 5 + a[1]], grid[((b[0] + 1) % 5) * 5 + b[1]]);
    } else {
      output.push(grid[a[0] * 5 + b[1]], grid[b[0] * 5 + a[1]]);
    }
  });
  return output.join("").replace(/(.{2})/g, "$1 ").trim();
}

function transformMode(text, cipher, mode) {
  const decode = mode === "decode";
  if (cipher === "caesar") return caesar(text, state.shift, decode);
  if (cipher === "atbash") return atbash(text);
  if (cipher === "vigenere") return vigenere(text, state.vigenereKey, decode);
  if (cipher === "rail") return railFence(text, state.rails, decode);
  if (cipher === "playfair") return playfair(text, state.playfairKey, decode);
  return text;
}

function transform(text) {
  return transformMode(text, state.cipher, state.mode);
}

function normalizeForCompare(text) {
  return String(text).toUpperCase().replace(/J/g, "I").replace(/[^A-Z0-9]/g, "").replace(/X+$/, "");
}

function roundTripCheck() {
  if (!state.text.trim()) return { pass: false, label: "EMPTY" };
  const encoded = transformMode(state.text, state.cipher, "encode");
  const decoded = transformMode(encoded, state.cipher, "decode");
  const pass = normalizeForCompare(decoded) === normalizeForCompare(state.text);
  return { pass, label: pass ? "PASS" : "CHECK" };
}

function renderMode() {
  document.querySelectorAll("#mode-toggle button").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === state.mode);
  });
  $("direction-label").textContent = state.mode === "encode" ? "ENCRYPT →" : "DECRYPT →";
  $("message-state").textContent = `${CIPHERS[state.cipher].name.toUpperCase()} / ${state.mode === "encode" ? "ENCODE" : "DECODE"}`;
}

function renderCipherList() {
  const list = $("cipher-list");
  list.innerHTML = "";
  Object.entries(CIPHERS).forEach(([id, cipher], index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `cipher-button${state.cipher === id ? " active" : ""}`;
    button.innerHTML = `<span class="cipher-index">${String(index + 1).padStart(2, "0")}</span><span><span class="cipher-name">${cipher.name}</span><span class="cipher-desc">${cipher.desc}</span></span>`;
    button.addEventListener("click", () => {
      state.cipher = id;
      renderCipherList();
      renderKeyPanel();
      renderMode();
      process();
    });
    list.append(button);
  });
}

function updatePlayfairGrid() {
  const wrap = $("pf-grid");
  if (!wrap) return;
  wrap.innerHTML = playfairGrid(state.playfairKey).map((letter) => `<span class="pf-cell">${letter}</span>`).join("");
}

function renderKeyPanel() {
  const panel = $("key-panel");
  const stateLabel = $("key-state");
  stateLabel.textContent = state.cipher === "atbash" ? "FIXED" : "KEYED";

  if (state.cipher === "caesar") {
    panel.innerHTML = `<div class="shift-readout"><strong id="shift-value">${state.shift}</strong><span>positions forward</span></div><label class="key-field">Shift amount <output id="shift-out">+${state.shift}</output><input type="range" id="shift-range" min="1" max="25" value="${state.shift}"></label><p class="key-note">Encode moves forward. Decode moves back by the same amount.</p>`;
    $("shift-range").addEventListener("input", (event) => {
      state.shift = Number(event.target.value);
      $("shift-value").textContent = String(state.shift);
      $("shift-out").textContent = `+${state.shift}`;
      process();
    });
  } else if (state.cipher === "vigenere") {
    panel.innerHTML = `<label class="key-field">Keyword<input type="text" id="vigenere-key" maxlength="40" value="${escapeHtml(state.vigenereKey)}" placeholder="LEMON"></label><div class="key-fingerprint">Normalized <strong id="key-normalized">${escapeHtml(normalizeLetters(state.vigenereKey) || "KEY")}</strong></div><p class="key-note">Only A–Z is used. Spaces and punctuation wrap around the key stream.</p>`;
    $("vigenere-key").addEventListener("input", (event) => {
      state.vigenereKey = event.target.value;
      $("key-normalized").textContent = normalizeLetters(state.vigenereKey) || "KEY";
      process();
    });
  } else if (state.cipher === "atbash") {
    panel.innerHTML = `<p class="key-empty">No key material. Atbash is a fixed alphabet mirror and is its own inverse.</p><div class="key-fingerprint">Mapping <strong>A ↔ Z · B ↔ Y · C ↔ X</strong></div>`;
  } else if (state.cipher === "rail") {
    panel.innerHTML = `<div class="shift-readout"><strong id="rail-value">${state.rails}</strong><span>rails deep</span></div><label class="key-field">Rails <output id="rail-out">${state.rails}</output><input type="range" id="rails-range" min="2" max="8" value="${state.rails}"></label><p class="key-note">The message is written along a zigzag and read rail by rail.</p>`;
    $("rails-range").addEventListener("input", (event) => {
      state.rails = Number(event.target.value);
      $("rail-value").textContent = String(state.rails);
      $("rail-out").textContent = String(state.rails);
      process();
    });
  } else if (state.cipher === "playfair") {
    panel.innerHTML = `<label class="key-field">Keyword<input type="text" id="playfair-key" maxlength="40" value="${escapeHtml(state.playfairKey)}" placeholder="CIPHER"></label><div class="key-fingerprint">Square <strong id="key-normalized">${escapeHtml(normalizeLetters(state.playfairKey) || "CIPHER")}</strong></div><div class="playfair-grid" id="pf-grid"></div><p class="key-note">J is merged into I. Repeated letters and odd endings receive X padding; trailing X is removed on decode.</p>`;
    $("playfair-key").addEventListener("input", (event) => {
      state.playfairKey = event.target.value;
      $("key-normalized").textContent = normalizeLetters(state.playfairKey) || "CIPHER";
      updatePlayfairGrid();
      process();
    });
    updatePlayfairGrid();
  }
}

function renderSamples() {
  const list = $("sample-list");
  list.innerHTML = "";
  SAMPLES.forEach((sample) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = sample.name;
    button.addEventListener("click", () => {
      state.text = sample.text;
      $("input-text").value = state.text;
      process();
      $("input-text").focus();
      showToast(`${sample.name} loaded`);
    });
    list.append(button);
  });
}

function renderAnalysis(output) {
  const letters = normalizeLetters(output);
  const total = letters.length;
  const counts = Array(26).fill(0);
  [...letters].forEach((letter) => { counts[letter.charCodeAt(0) - 65] += 1; });
  let entropy = 0;
  counts.forEach((count) => {
    if (!count) return;
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  });
  let repeats = 0;
  counts.forEach((count) => { repeats += count * (count - 1); });
  const ioc = total > 1 ? repeats / (total * (total - 1)) : 0;
  const unique = counts.filter((count) => count > 0).length;
  const ranked = counts.map((count, index) => ({ count, letter: String.fromCharCode(65 + index) })).sort((a, b) => b.count - a.count);
  const maximum = ranked[0] ? ranked[0].count : 0;
  const hot = new Set(ranked.filter((item) => item.count === maximum && maximum > 0).map((item) => item.letter));

  $("stat-entropy").textContent = entropy.toFixed(2);
  $("stat-ioc").textContent = ioc.toFixed(3);
  $("stat-letters").textContent = String(total);
  $("stat-unique").textContent = String(unique);
  $("freq-top").textContent = ranked[0] && ranked[0].count ? ranked.slice(0, 2).map((item) => `${item.letter} ${item.count}`).join(" · ") : "—";

  const chart = $("freq-chart");
  chart.innerHTML = "";
  counts.forEach((count, index) => {
    const bar = document.createElement("div");
    const letter = String.fromCharCode(65 + index);
    bar.className = `freq-bar${hot.has(letter) ? " hot" : ""}`;
    const fill = document.createElement("i");
    fill.style.height = maximum ? `${Math.max(count / maximum * 100, count ? 2 : 0)}%` : "0%";
    const label = document.createElement("span");
    label.textContent = letter;
    bar.append(fill, label);
    chart.append(bar);
  });

  $("analysis-hint").textContent = CIPHERS[state.cipher].hint;
}

function chiSquared(text) {
  const letters = normalizeLetters(text);
  if (!letters) return Infinity;
  const counts = Array(26).fill(0);
  [...letters].forEach((letter) => { counts[letter.charCodeAt(0) - 65] += 1; });
  let score = 0;
  counts.forEach((count, index) => {
    const expected = ENGLISH[index] / 100 * letters.length;
    score += Math.pow(count - expected, 2) / expected;
  });
  return score;
}

function renderCaesarScan(text) {
  $("scan-title").textContent = "Caesar shift scan";
  const body = $("scan-body");
  if (!normalizeLetters(text)) {
    $("scan-meta").textContent = "no letters";
    body.innerHTML = `<p class="scan-empty">Add a message to scan all 25 Caesar shifts for an English fit.</p>`;
    return;
  }
  const candidates = [];
  for (let shift = 1; shift <= 25; shift += 1) {
    const decoded = caesar(text, shift, true);
    candidates.push({ shift, decoded, score: chiSquared(decoded) });
  }
  const scores = candidates.map((candidate) => candidate.score);
  const minimum = Math.min(...scores);
  const maximum = Math.max(...scores);
  const best = candidates.find((candidate) => candidate.score === minimum);
  candidates.forEach((candidate) => {
    candidate.fit = maximum === minimum ? 100 : Math.round((1 - (candidate.score - minimum) / (maximum - minimum)) * 100);
  });
  $("scan-meta").textContent = `best +${best.shift} · ${best.fit}% fit`;
  body.innerHTML = "";
  candidates.forEach((candidate) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `scan-row${candidate.shift === best.shift ? " best" : ""}`;
    row.innerHTML = `<span class="scan-shift">+${candidate.shift}</span><span class="scan-preview"></span><span class="scan-bar"><i style="width:${candidate.fit}%"></i></span><span class="scan-score">${candidate.fit}%</span>`;
    row.querySelector(".scan-preview").textContent = candidate.decoded.replace(/\s+/g, " ").trim().slice(0, 72) || "—";
    row.addEventListener("click", () => {
      state.shift = candidate.shift;
      state.mode = "decode";
      renderMode();
      renderKeyPanel();
      process();
      showToast(`Shift +${candidate.shift} applied`);
    });
    body.append(row);
  });
}

function displayGlyph(char) {
  if (char === " ") return "·";
  if (char === "\n") return "↵";
  if (char === "\t") return "→";
  return char;
}

function renderTrace(text, output) {
  $("scan-title").textContent = "Signal trace";
  const body = $("scan-body");
  const trip = roundTripCheck();
  const inputChars = [...text].slice(0, 22);
  const outputChars = [...output].slice(0, 22);
  $("scan-meta").textContent = `${Math.min(text.length, 22)} characters`;
  body.innerHTML = "";

  if (!text.length) {
    body.innerHTML = `<p class="scan-empty">The trace appears when there is a message to transform.</p>`;
    return;
  }

  const wrap = document.createElement("div");
  wrap.className = "trace-wrap";
  const head = document.createElement("div");
  head.className = "trace-head";
  head.innerHTML = `<span>Ordered character preview</span><span>Method ${CIPHERS[state.cipher].tag}</span>`;
  const lines = document.createElement("div");
  lines.className = "trace-lines";

  [["IN", inputChars, ""], ["OUT", outputChars, "out"]].forEach(([label, chars, className]) => {
    const line = document.createElement("div");
    line.className = `trace-line ${className}`;
    const tag = document.createElement("span");
    tag.className = "trace-label";
    tag.textContent = label;
    line.append(tag);
    chars.forEach((char) => {
      const cell = document.createElement("span");
      cell.className = "trace-char";
      cell.textContent = displayGlyph(char);
      line.append(cell);
    });
    lines.append(line);
  });

  const roundTrip = document.createElement("div");
  roundTrip.className = "trace-roundtrip";
  roundTrip.innerHTML = `<span>Encode → decode integrity</span><span class="roundtrip ${trip.pass ? "pass" : "warn"}">${trip.label}</span>`;
  wrap.append(head, lines, roundTrip);
  body.append(wrap);
}

function renderScan(text, output) {
  if (state.cipher === "caesar") renderCaesarScan(text);
  else renderTrace(text, output);
}

function getKeyDisplay() {
  if (state.cipher === "caesar") return `Shift +${state.shift}`;
  if (state.cipher === "vigenere") return normalizeLetters(state.vigenereKey) || "KEY (fallback)";
  if (state.cipher === "atbash") return "No key material";
  if (state.cipher === "rail") return `${state.rails} rails`;
  if (state.cipher === "playfair") return normalizeLetters(state.playfairKey) || "CIPHER (fallback)";
  return "—";
}

function renderNotes() {
  const cipher = CIPHERS[state.cipher];
  const trip = roundTripCheck();
  const badge = $("roundtrip-badge");
  badge.textContent = trip.pass ? "RT PASS" : "RT WARN";
  badge.className = trip.pass ? "pass" : "warn";
  $("method-notes").innerHTML = `<div class="note-block"><span class="note-label">Operation</span><p class="note-copy">${escapeHtml(cipher.desc)}</p></div><div class="note-formula">${escapeHtml(cipher.formula)}</div><div class="note-block"><span class="note-label">Security read</span><p class="note-copy">${escapeHtml(cipher.security)}</p></div><div class="note-key"><span>Key</span><strong>${escapeHtml(getKeyDisplay())}</strong></div>`;
}

function process() {
  const output = transform(state.text);
  $("output-text").value = output;
  const words = state.text.trim() ? state.text.trim().split(/\s+/).length : 0;
  const outputWords = output.trim() ? output.trim().split(/\s+/).length : 0;
  $("input-count").textContent = `${state.text.length} chars · ${words} words`;
  $("output-count").textContent = `${output.length} chars · ${outputWords} words`;
  $("message-state").textContent = state.mode === "encode" ? "ENCRYPTED" : "DECODED";
  renderMode();
  renderAnalysis(output);
  renderScan(state.text, output);
  renderNotes();
  saveState();
}

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      cipher: state.cipher,
      mode: state.mode,
      text: state.text,
      shift: state.shift,
      vigenereKey: state.vigenereKey,
      rails: state.rails,
      playfairKey: state.playfairKey
    }));
  } catch (error) {
    return;
  }
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    if (!data || !CIPHERS[data.cipher]) return;
    state.cipher = data.cipher;
    state.mode = data.mode === "decode" ? "decode" : "encode";
    state.text = typeof data.text === "string" ? data.text : state.text;
    state.shift = clamp(Number(data.shift) || 7, 1, 25);
    state.vigenereKey = typeof data.vigenereKey === "string" ? data.vigenereKey : "LEMON";
    state.rails = clamp(Number(data.rails) || 4, 2, 8);
    state.playfairKey = typeof data.playfairKey === "string" ? data.playfairKey : "CIPHER";
  } catch (error) {
    return;
  }
}

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Output copied");
  } catch (error) {
    const field = document.createElement("textarea");
    field.value = text;
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.append(field);
    field.select();
    try {
      document.execCommand("copy");
      showToast("Output copied");
    } catch (fallbackError) {
      showToast("Copy failed — select the output manually");
    }
    field.remove();
  }
}

function downloadOutput() {
  const header = `CIPHER / ${CIPHERS[state.cipher].name} / ${state.mode}\nKey: ${getKeyDisplay()}\n----------------------------------------\n`;
  const blob = new Blob([header + $("output-text").value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `cipher-${state.cipher}-${state.mode}.txt`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast("Text file downloaded");
}

function bindEvents() {
  document.querySelectorAll("#mode-toggle button").forEach((button) => {
    button.addEventListener("click", () => {
      state.mode = button.dataset.mode;
      renderMode();
      process();
    });
  });
  $("input-text").addEventListener("input", (event) => {
    state.text = event.target.value;
    process();
  });
  $("copy-output").addEventListener("click", () => copyText($("output-text").value));
  $("download-output").addEventListener("click", downloadOutput);
  $("chain-output").addEventListener("click", () => {
    const output = $("output-text").value;
    if (!output) {
      showToast("Nothing to chain yet");
      return;
    }
    state.text = output;
    $("input-text").value = output;
    process();
    showToast("Output moved into input");
  });
  const clear = () => {
    state.text = "";
    $("input-text").value = "";
    process();
    $("input-text").focus();
  };
  $("clear-message").addEventListener("click", clear);
  $("new-message").addEventListener("click", clear);
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      copyText($("output-text").value);
    }
  });
}

loadState();
$("input-text").value = state.text;
bindEvents();
renderCipherList();
renderSamples();
renderKeyPanel();
renderMode();
process();
