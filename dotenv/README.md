# dotenv

## Overview

The dotenv package enables parsing, reading, and writing dotenv (.env) files in Go

Parse returns an `EnvDoc` object that represents the parsed content of a dotenv file. 
The `EnvDoc` object provides methods to access and manipulate environment variables defined in the file
and retains the original formatting and comments in the order they were defined.

The order is important for both keeping same order for writing back to the file and for preserving comments
and for variable expansion.

If you wish to use a map, then you can use the `ToMap` method to convert the `EnvDoc` to a map[string]string.

If you wish to use variable expansion or command substitution, you can use the `env` package
which provides functions to expand variables and perform command substitution.

## Usage

To use `env`, import the module in your Go project:

```go
import "github.com/hyprxlabs/go/dotenv"
import "github.com/hyprxlabs/go/env"

func main() {

    content := `KEY1="value1"

KEY2='value2'
Key3=value3
Key4=a value with spaces
# This is a comment
Key5="a value with \"escaped quotes\""
Key6='a value with \'single quotes\''
Key7="line1
line2
line3
"
Key8="value with \nnewlines"
Key9="value with \t tabs"
Key11="😈"
`

    doc, err := dotenv.Parse([]byte(content))
    if err != nil {
        panic(err) 
    }

    println("Parsed keys:")
    for _, key := range doc.Keys() {
        println(key, "=", doc.Get(key))
    }

    // Example of writing the document back to a string
    output := doc.String()
    println("Output content:")
    println(output)

    doc2 := dotenv.NewDocument()
    doc2.AddNewLine()
    doc2.AddComment("This is a new comment"
    doc2.AddVariable("KEY1", "value1")
    doc2.AddQuotedVariable("KEY2", "value2", '"')

    println("New document content:")
    println(doc2.String())
    // New document content:
    // 
    // # This is a new comment
    // KEY1=value1
    // KEY2="value2"

    content2 := `
KEY1=value1
KEY2="Hello ${KEY1}
WHOAMI=$(whoami)
PWD=$(pwd)
`

    envMap := map[string]string{}
    doc3, err := dotenv.Parse([]byte(content2))
    if err != nil {
        panic(err)
    }

    var get func(string) string 
    var set func(string, string) error 

    get = func(key string) string {
        if value, ok := envMap[key]; ok {
            return value
        }

        value = doc3.Get(key)
        if value != "" {
            return value
        }

        return env.Get(key)
    }

    set = func(key, value string) error {
        envMap[key] = value
        return nil
    }

    opts := env.ExpandOptions{
        Get: get,
        Set: set,
        CommandSubstitution: true,
    }

    println("Parsed keys with substitutions:")
    for _, key := range doc3.Keys() {
        value, _ := doc3.Get(key)
        envMap[key] = env.ExpandWithOptions(value, opts)
    }

    for _, key := range doc3.Keys() {
        println(key, "=", envMap[key])
    }
    // Output:
    // KEY1 = value1
    // KEY2 = Hello value1
    // WHOAMI = <current user>
    // PWD = <current working directory>
}

```
