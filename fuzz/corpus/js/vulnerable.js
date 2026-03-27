// Zentinel ground truth — every line with a // TRIGGER comment should fire the named rule.
// Lines without TRIGGER should NOT fire any rule.
const child_process = require('child_process');
const crypto = require('crypto');
const http = require('http');

// ── Code Injection ──────────────────────────────────────
function evalInput(code) {
    eval(code);                                     // TRIGGER javascript.security.eval-usage
}

function funcConstructor(code) {
    return Function(code);                          // TRIGGER javascript.security.function-constructor
}

function delayedEval(code) {
    setTimeout(code, 1000);                         // TRIGGER javascript.security.settimeout-string
}

function repeatedEval(code) {
    setInterval(code, 1000);                        // TRIGGER javascript.security.setinterval-string
}

// ── Command Injection ───────────────────────────────────
function runCommand(cmd) {
    exec(cmd);                                      // TRIGGER javascript.security.exec-usage
}

function cpExec(cmd) {
    child_process.exec(cmd);                        // TRIGGER javascript.security.child-process-exec
}

function cpSpawn(cmd) {
    child_process.spawn(cmd);                       // TRIGGER javascript.security.child-process-spawn
}

// ── XSS / DOM ───────────────────────────────────────────
function writeHtml(html) {
    document.write(html);                           // TRIGGER javascript.security.innerhtml
}

// ── Deserialization ─────────────────────────────────────
function parseData(data) {
    return JSON.parse(data);                        // TRIGGER javascript.security.json-parse
}

// ── Cryptography ────────────────────────────────────────
function hashData(data) {
    return crypto.createHash("md5");                // TRIGGER javascript.security.crypto-createhash-md5
}

// ── Network / TLS ───────────────────────────────────────
function startServer() {
    http.createServer(handler);                     // TRIGGER javascript.security.http-createserver
}

// ── Hardcoded Secrets ───────────────────────────────────
const API_KEY = "sk-1234567890abcdef";              // TRIGGER javascript.security.hardcoded-secret
const DB_PASSWORD = "hunter2";                      // TRIGGER javascript.security.hardcoded-secret

// ── Dangerous Patterns ──────────────────────────────────
function shutdown() {
    process.exit(1);                                // TRIGGER javascript.security.process-exit
}
