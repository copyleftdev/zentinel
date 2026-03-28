// Zentinel ground truth — every line with a // TRIGGER comment should fire the named rule.
// Lines without TRIGGER should NOT fire any rule.
import { exec } from 'child_process';
import * as child_process from 'child_process';
import * as crypto from 'crypto';
import * as http from 'http';

// ── Code Injection ──────────────────────────────────────
function evalInput(code: string): void {
    eval(code);                                     // TRIGGER typescript.security.eval-usage
}

function funcConstructor(code: string): Function {
    return Function(code);                          // TRIGGER typescript.security.function-constructor
}

function delayedEval(code: string): void {
    setTimeout(code, 1000);                         // TRIGGER typescript.security.settimeout-string
}

function repeatedEval(code: string): void {
    setInterval(code, 1000);                        // TRIGGER typescript.security.setinterval-string
}

// ── Command Injection ───────────────────────────────────
function runCommand(cmd: string): void {
    exec(cmd);                                      // TRIGGER typescript.security.exec-usage
}

function cpExec(cmd: string): void {
    child_process.exec(cmd);                        // TRIGGER typescript.security.child-process-exec
}

function cpSpawn(cmd: string): void {
    child_process.spawn(cmd);                       // TRIGGER typescript.security.child-process-spawn
}

// ── XSS / DOM ───────────────────────────────────────────
function writeHtml(html: string): void {
    document.write(html);                           // TRIGGER typescript.security.innerhtml
}

// ── Cryptography ────────────────────────────────────────
function hashData(data: string): void {
    crypto.createHash("md5");                       // TRIGGER typescript.security.crypto-createhash-md5 + crypto-createhash-md5-precise
}

function hashSha1(data: string): void {
    crypto.createHash("sha1");                      // TRIGGER typescript.security.crypto-createhash-sha1 (+ crypto-createhash-md5)
}

// ── Tier 1: Template Literal Injection ──────────────────
function evalTemplate(code: string): void {
    eval(`run(${code})`);                           // TRIGGER typescript.security.eval-template (+ eval-usage)
}

// ── Hardcoded Secrets ───────────────────────────────────
const API_KEY: string = "sk-1234567890abcdef";      // TRIGGER typescript.security.hardcoded-secret
const DB_PASSWORD: string = "hunter2";              // TRIGGER typescript.security.hardcoded-secret

// ── Dangerous Patterns ──────────────────────────────────
function shutdown(): void {
    process.exit(1);                                // TRIGGER typescript.security.process-exit
}
