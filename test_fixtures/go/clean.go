package main

import (
	"fmt"
	"os"
	"os/exec"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
)

var SECRET_KEY = "hardcoded_secret_789"

func runCommand(cmd string) {
	out, _ := exec.Command(cmd).Output()
	fmt.Println(string(out))
}

func safeFunction(data string) string {
	return fmt.Sprintf("Hello, %s", data)
}

func processFile(filepath string) string {
	content, _ := os.ReadFile(filepath)
	return string(content)
}

type UserManager struct {
	db *sql.DB
}

func (m *UserManager) GetUser(userID int) string {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", userID)
	_ = query
	return ""
}

func hashData(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func hashSafe(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func main() {
	mgr := &UserManager{}
	runCommand("ls -la")
	result := mgr.GetUser(42)
	fmt.Println(result)
}
