/* Text Encrypt — AES-256-GCM with a PBKDF2-SHA256 key (600,000 rounds), all via the browser's SubtleCrypto.
   Wire format (see README): "S3E1." + base64( version | kdf | iterations | salt | iv | ciphertext+tag ), header bytes are the GCM AAD. */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;
  var PREFIX = "S3E1.", VERSION = 1, KDF_PBKDF2_SHA256 = 1, ITER = 600000;
  var MIN_ITER = 100000, MAX_ITER = 10000000; // refuse absurd counts from a crafted header (would freeze the tab)
  var SALT_LEN = 16, IV_LEN = 12, HEADER_LEN = 2 + 4 + SALT_LEN + IV_LEN, TAG_LEN = 16;
  var enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: true });

  // ---------- base64 (standard; decoder also accepts base64url and stray whitespace) ----------
  function toB64(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromB64(str) {
    var s = str.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 === 1) throw new Error("not base64");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) { var b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
  function deriveKey(password, salt, iterations) {
    return crypto.subtle.importKey("raw", enc.encode(String(password).normalize("NFC")), "PBKDF2", false, ["deriveKey"]).then(function (base) {
      return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iterations }, base,
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    });
  }

  function encryptText(plain, password, iterations) {
    iterations = iterations || ITER;
    var salt = randomBytes(SALT_LEN), iv = randomBytes(IV_LEN);
    var header = new Uint8Array(HEADER_LEN), dv = new DataView(header.buffer);
    header[0] = VERSION; header[1] = KDF_PBKDF2_SHA256; dv.setUint32(2, iterations, false);
    header.set(salt, 6); header.set(iv, 6 + SALT_LEN);
    return deriveKey(password, salt, iterations).then(function (key) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: header, tagLength: 128 }, key, enc.encode(plain));
    }).then(function (ct) {
      var all = new Uint8Array(HEADER_LEN + ct.byteLength);
      all.set(header, 0); all.set(new Uint8Array(ct), HEADER_LEN);
      return PREFIX + toB64(all);
    });
  }

  function DecryptError(msg) { var e = new Error(msg); e.userFacing = true; return e; }
  function parse(text) {
    var t = String(text).trim();
    if (t.slice(0, 3) === "S3E" && t.slice(0, PREFIX.length) !== PREFIX) throw DecryptError("This was made by a newer version of Text Encrypt. Open the latest version to decrypt it.");
    if (t.slice(0, PREFIX.length) !== PREFIX) throw DecryptError("This doesn't look like Text Encrypt output (it should start with " + PREFIX + ").");
    var bytes;
    try { bytes = fromB64(t.slice(PREFIX.length)); } catch (e) { throw DecryptError("The encrypted text is damaged (not valid base64). Make sure you copied all of it."); }
    if (bytes.length < HEADER_LEN + TAG_LEN) throw DecryptError("The encrypted text is too short. It was probably cut off when copying.");
    if (bytes[0] !== VERSION) throw DecryptError("Unsupported format version " + bytes[0] + ".");
    if (bytes[1] !== KDF_PBKDF2_SHA256) throw DecryptError("Unsupported key derivation method.");
    var iterations = new DataView(bytes.buffer, bytes.byteOffset).getUint32(2, false);
    if (iterations < MIN_ITER || iterations > MAX_ITER) throw DecryptError("The encrypted text has an invalid header.");
    return {
      header: bytes.subarray(0, HEADER_LEN), iterations: iterations,
      salt: bytes.slice(6, 6 + SALT_LEN), iv: bytes.slice(6 + SALT_LEN, HEADER_LEN), ct: bytes.subarray(HEADER_LEN)
    };
  }
  function decryptText(text, password) {
    var p;
    try { p = parse(text); } catch (e) { return Promise.reject(e); }
    return deriveKey(password, p.salt, p.iterations).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: p.iv, additionalData: p.header, tagLength: 128 }, key, p.ct);
    }).then(function (buf) {
      try { return dec.decode(buf); } catch (e) { throw DecryptError("Decrypted, but the result isn't valid text."); }
    }, function () {
      throw DecryptError("Wrong password, or the encrypted text was changed or cut off.");
    });
  }

  // ---------- UI ----------
  var mode = "enc", result = "", busy = false;
  var input = $("#input"), pw = $("#pw"), pw2 = $("#pw2"), out = $("#out");

  function setMode(m) {
    mode = m;
    $$("#mode button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.v === m)); });
    var e = m === "enc";
    $("#in-title").textContent = e ? "Your message" : "Encrypted text";
    $("#in-label").textContent = e ? "Message to encrypt" : "Encrypted text to decrypt";
    input.placeholder = e ? "Type or paste the text you want to protect" : "Paste the text that starts with " + PREFIX;
    input.classList.toggle("prose", e); input.classList.toggle("te-cipher", !e);
    $("#pw2-wrap").hidden = !e; $("#open").hidden = e;
    pw.autocomplete = e ? "new-password" : "current-password";
    $("#go span").textContent = e ? "Encrypt" : "Decrypt";
    $("#out-title").textContent = e ? "Encrypted text" : "Decrypted message";
    clearOut();
  }
  function clearOut() {
    result = ""; out.classList.remove("bad", "te-plain");
    out.innerHTML = '<span class="faint">The result appears here.</span>'; $("#meta").innerHTML = "";
  }
  function chip(text, cls) { return S3.h("span", { "class": "chip " + (cls || "") }, [text]); }

  function run() {
    if (busy) return;
    var text = input.value, p = pw.value;
    if (!text.trim()) { S3.toast(mode === "enc" ? "Type a message first" : "Paste the encrypted text first", "error"); input.focus(); return; }
    if (!p) { S3.toast("Enter a password", "error"); pw.focus(); return; }
    if (mode === "enc" && p !== pw2.value) { S3.toast("The two passwords don't match", "error"); pw2.focus(); return; }
    busy = true; $("#go").disabled = true;
    out.classList.remove("bad"); out.innerHTML = '<span class="faint">Deriving the key (600,000 rounds)…</span>';
    var t0 = performance.now();
    var job = mode === "enc" ? encryptText(text, p) : decryptText(text, p);
    job.then(function (r) {
      result = r; out.textContent = r; out.classList.toggle("te-plain", mode === "dec"); $("#meta").innerHTML = "";
      var ms = Math.round(performance.now() - t0);
      if (mode === "enc") {
        $("#meta").appendChild(chip("✓ Encrypted", "ok"));
        $("#meta").appendChild(chip(enc.encode(text).length.toLocaleString() + " bytes → " + r.length.toLocaleString() + " characters"));
      } else {
        $("#meta").appendChild(chip("✓ Decrypted and verified", "ok"));
      }
      $("#meta").appendChild(chip(ms + " ms"));
      S3.done();
    }, function (e) {
      result = ""; out.classList.add("bad");
      out.textContent = e && e.userFacing ? e.message : "Something went wrong: " + (e && e.message || e);
      $("#meta").innerHTML = "";
    }).then(function () { busy = false; $("#go").disabled = false; });
  }

  $$("#mode button").forEach(function (b) { b.addEventListener("click", function () { setMode(b.dataset.v); }); });
  $("#go").addEventListener("click", run);
  [input, pw, pw2].forEach(function (el) {
    el.addEventListener("keydown", function (e) { if (e.key === "Enter" && (e.ctrlKey || e.metaKey || el !== input)) { e.preventDefault(); run(); } });
  });
  $("#eye").addEventListener("click", function () {
    var show = pw.type === "password";
    pw.type = pw2.type = show ? "text" : "password";
    this.setAttribute("aria-pressed", String(show)); this.textContent = show ? "Hide" : "Show";
  });
  $("#clear").addEventListener("click", function () { input.value = ""; clearOut(); input.focus(); });
  $("#copy").addEventListener("click", function () { if (result) S3.copy(result); else S3.toast("Nothing to copy yet", "error"); });
  $("#save").addEventListener("click", function () {
    if (!result) { S3.toast("Nothing to save yet", "error"); return; }
    S3.download(result + (mode === "enc" ? "\n" : ""), mode === "enc" ? "encrypted.txt" : "decrypted.txt", "text/plain;charset=utf-8");
  });
  $("#open input").addEventListener("change", function (e) {
    var f = e.target.files[0]; if (!f) return;
    S3.readFile(f, "text").then(function (t) { input.value = t.trim(); clearOut(); pw.focus(); });
    e.target.value = "";
  });
  // Passwords live only in these fields; wipe them when the page is hidden for good.
  window.addEventListener("pagehide", function () { pw.value = pw2.value = ""; });
  setMode("enc");

  window.S3_DEMO = function () {
    input.value = "Meet at the old library, 7 pm.\nالرمز: النخلة الزرقاء 🌴";
    pw.value = pw2.value = "correct horse battery staple";
    run();
    return new Promise(function (res) { var t = setInterval(function () { if (!busy) { clearInterval(t); res(); } }, 50); });
  };

  // Fixed vector made with this exact format: proves old messages keep decrypting.
  var KNOWN = { pw: "s3eidat", text: "Hello, مرحبا 👋", data: "S3E1.AQEACSfAtcIyfKiQlnccWg4e2uFxBglGUizyF0IsTYNU0kSqKpIDX4xsscpbHaTSv0AGmLwAcP3l341prQNNoeukuzER22r7" };

  window.S3_SELFTEST = async function () {
    var fails = [];
    function check(cond, why) { if (!cond) fails.push(why); }
    async function rejects(p) { try { await p; return false; } catch (e) { return !!e.userFacing; } }
    var msg = "Round trip ✓ — عربي — 🔐\nline 2", pwd = "pässwörd 🔑";
    var a = await encryptText(msg, pwd), b = await encryptText(msg, pwd);
    check(a.slice(0, 5) === PREFIX, "prefix");
    check(a !== b, "salt/iv must make each output unique");
    var raw = fromB64(a.slice(5));
    check(raw.length === HEADER_LEN + enc.encode(msg).length + TAG_LEN, "length");
    check(raw[0] === 1 && raw[1] === 1 && new DataView(raw.buffer).getUint32(2) === 600000, "header fields");
    check(toB64(fromB64(raw.length ? toB64(raw) : "")) === toB64(raw), "base64 round trip");
    check(await decryptText(a, pwd) === msg, "decrypt round trip");
    check(await decryptText(a, pwd.normalize("NFD")) === msg, "same password typed in NFD form must work");
    check(await rejects(decryptText(a, pwd + "x")), "wrong password must fail");
    function flip(s, at) { var r = fromB64(s.slice(5)); r[at] ^= 1; return PREFIX + toB64(r); }
    check(await rejects(decryptText(flip(a, raw.length - 20), pwd)), "flipped ciphertext byte must fail");
    check(await rejects(decryptText(flip(a, 8), pwd)), "flipped salt byte must fail");
    check(await rejects(decryptText(flip(a, 2 + 4 + 16 + 3), pwd)), "flipped iv byte must fail");
    var cut = fromB64(a.slice(5)); check(await rejects(decryptText(PREFIX + toB64(cut.subarray(0, cut.length - 1)), pwd)), "truncated must fail");
    check(await rejects(decryptText(PREFIX + toB64(cut.subarray(0, 40)), pwd)), "too short must fail");
    var big = fromB64(a.slice(5)); new DataView(big.buffer).setUint32(2, 0xFFFFFFFF); check(await rejects(decryptText(PREFIX + toB64(big), pwd)), "absurd iterations must be refused");
    check(await rejects(decryptText("hello", pwd)), "garbage must fail");
    check(await decryptText(KNOWN.data, KNOWN.pw) === KNOWN.text, "known vector");
    if (fails.length) console.error("selftest: " + fails.join("; "));
    return fails.length === 0;
  };
})();
