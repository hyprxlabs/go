# exec

## Overview

The `exec` package provides wraps the os/exec package to provide additional convienience methods for executing commands in Go, including
capturing output, logging, and piping commands together.

## Usage

To use `secrets`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/exec"

func main() {
    cmd := exec.New("ls", "-l")
    result, err := cmd.Run()
    if err != nil {
        panic(err)
    }
    println("Command output:", string(result.Stdout))

    o, err := exec.Run("git commit -m 'test'")
    if err != nil {
        panic(err)
    }
    if !o.IsOk() {
        err := o.ToError()
        panic(err)
    }

    o2, err := exec.Output("ls -l")
    if o.IsOk() {
        for _, line := range o2.Lines() {
            println(line)
        }
    }

    o3, err := exec.Command("echo 'Hello World'").PipeCommand("grep Hello").Output()
    if err != nil {
        panic(err)
    }
    println("Piped command output:", string(o3.Stdout))
}

```
