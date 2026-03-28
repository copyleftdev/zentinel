// Zentinel ground truth — every line with a // TRIGGER comment should fire the named rule.
// Lines without TRIGGER should NOT fire any rule.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
)

// ── Command Injection ────────────────────────────────────
func runCommand(cmd string) {
	exec.Command(cmd).Run()                             // TRIGGER go.security.exec-command
}

// ── Dangerous Builtins ───────────────────────────────────
func unsafePrint(data interface{}) {
	fmt.Sprintf("%v", data)
}

// ── Cryptography ─────────────────────────────────────────
func hashMD5(data []byte) []byte {
	h := md5.Sum(data)                                  // TRIGGER go.security.crypto-md5
	return h[:]
}

func hashSHA1(data []byte) []byte {
	h := sha1.Sum(data)                                 // TRIGGER go.security.crypto-sha1
	return h[:]
}

// ── SQL Injection ────────────────────────────────────────
func queryUser(db *sql.DB, userID string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
	db.Query(query)
}

// ── Environment / Secrets ────────────────────────────────
var API_KEY = "sk-go-1234567890abcdef"              // TRIGGER go.security.hardcoded-secret
var DB_PASSWORD = "hunter2"                         // TRIGGER go.security.hardcoded-secret

// ── File Operations ──────────────────────────────────────
func readFile(path string) {
	os.ReadFile(path)
}

func main() {
	runCommand("ls -la")
	hashMD5([]byte("test"))
	hashSHA1([]byte("test"))
}
