# secrets

## Overview

The `secrets` package provides functionality to mask sensitive information in strings and generate cryptographically
secure random strings. It is particularly useful for applications that need to handle sensitive data, such as passwords
or API keys, while ensuring that this data is not exposed in logs or error messages.

## Usage

To use `secrets`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/secrets"

func main() {
    // Example of masking a sensitive string
    secrets.DefaultMasker.AddValue("my-secret-password")

    maskedString := secrets.DefaultMasker.Mask("This is my-secret-password and it should be masked.")
    fmt.Println(maskedString) // Output: This is ******** and it should be masked.

    // Example of generating a random string
    newSecret := secrets.Generate(16, secrets.WithSymbols("!@#$%^&*()"))
}

```
