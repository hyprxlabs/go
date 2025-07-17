# cmdargs

## Overview

`cmdargs` is a Go module designed to handle command-line arguments in a structured way. It
provides functionality to parse, manipulate, and format command-line arguments efficiently.

## Features

- **Parsing**: Split command-line strings into structured arguments.
- **Manipulation**: Add, remove, and modify arguments easily.
- **Formatting**: Convert arguments back into a command-line string format.

## Usage

To use `cmdargs`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/cmdargs"

func main() {
  args := cmdargs.Split("arg1 'arg 2' \"arg 3\"")
  args.Push("arg4")
  args.RemoveAt(1) // Removes 'arg 2'
  fmt.Println(args.ToArray()) // arg1 "arg 3" arg4

  // bash and powershell multiline continuations are supported
  args2 := cmdargs.Split(`git commit \ 
    -m 'Initial commit'`)
}

```
