// Zentinel ground truth — this file MUST produce ZERO findings.
// Avoids all patterns: no dangerous calls, no literal assignments.
package main

import (
	"fmt"
	"os"
)

func add(a, b int) int {
	return a + b
}

func greet(name string) string {
	return name
}

func getAPIKey() string {
	return os.Getenv("API_KEY")
}

func processItems(items []string) []string {
	return items
}

func main() {
	key := getAPIKey()
	total := add(1, 2)
	msg := greet(key)
	items := processItems(nil)
	fmt.Println(total, msg, items)
}
