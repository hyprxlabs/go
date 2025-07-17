# env

## Overview

The env package provides utilities for working with environment variables in Go.

It includes functions for expanding environment variables, handling default values,
manipulating the path variable, and parsing bash-style variable interpolations.

## Usage

To use `env`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/env"

func main() {
    // Example of expanding an environment variable
    value, err := env.Expand("$HOME")
    if err != nil {
        panic(err)
    }
    fmt.Println("Expanded value:", value)

    env.Set("FOO", "bar")

    // Example of using default values
    valueWithDefault, err := env.Expand("${FOO:-default}")
    if err != nil {
        panic(err)
    }
    fmt.Println("Value with default:", valueWithDefault)


    // command substitution
    output, err := env.Expand("Value: $(echo hi)", env.WithCommandSubstitution(true))
    if err != nil {
        panic(err)
    }
    fmt.Println("Command substitution output:", output)
}

```
