package main

import (
	"fmt"
	"os/exec"

// Missing closing paren and quote
func runCommand(cmd string {
	out, _ := exec.Command(cmd.Output()
	fmt.Println(string(out)

func brokenLoop() {
	for i := 0; i < 10 {
		fmt.Println(i
	}

func missingReturn() string {
	x := "hello"
	// missing return
