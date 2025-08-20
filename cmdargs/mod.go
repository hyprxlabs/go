// Package cmdargs provides utilities for parsing, manipulating, and formatting
// command-line arguments. It offers a convenient Args type for working with
// argument slices, including methods for searching, modifying, and converting
// arguments. The package also includes robust parsing logic to split command-line
// strings into arguments, handling quoting, escaping, and whitespace similar to
// shell behavior. Additionally, it provides normalization and formatting functions
// to ensure arguments are handled consistently and safely for CLI usage.
package cmdargs

import (
	"strings"
	"unicode"
)

const (
	quoteNone   = iota
	quoteDouble = 1
	quoteSingle = 2
)

// Args encapsulates a slice of command-line arguments.
type Args struct {
	args []string
}

// New creates a new Args instance from a slice of strings, normalizing the arguments
// to ensure they are properly formatted for command-line usage.
func New(args []string) *Args {
	return &Args{
		args: normalizeArgs(args),
	}
}

// ToArray returns a copy of the underlying slice of arguments, ensuring that modifications
// to the returned slice do not affect the original Args instance.
// This is useful for safely accessing the arguments without risking unintended changes.
func (a *Args) ToArray() []string {
	copy2 := make([]string, len(a.args))
	copy(copy2, a.args)
	return copy2
}

// Len returns the number of arguments in the Args instance.
// This is a simple utility method to get the count of arguments without exposing the underlying slice.
func (a *Args) Len() int {
	return len(a.args)
}

// Get retrieves the argument at the specified index i.
// If the index is out of bounds, it returns an empty string.
// This method provides safe access to individual arguments without risking panics from out-of-bounds access
func (a *Args) Get(i int) string {
	if i < 0 || i >= len(a.args) {
		return ""
	}
	return a.args[i]
}

// Index returns the index of the first occurrence of the specified string s in the Args.
// If the string is not found, it returns -1. This method performs a case-insitive comparison
// to find the index, allowing for flexible matching of arguments regardless of case.
func (a *Args) Index(s string) int {
	for i, token := range a.args {
		if strings.EqualFold(s, token) {
			return i
		}
	}
	return -1
}

// IndexAny returns the index of the first occurrence of any string in the slice s within the Args.
// If none of the strings are found, it returns -1. This method allows for checking multiple
// potential matches in a single call, improving efficiency for certain use cases.
func (a *Args) IndexAny(s []string) int {
	for i, token := range a.args {
		for _, t := range s {
			if t == token {
				return i
			}
		}
	}
	return -1
}

// IndexFold returns the index of the first occurrence of the specified string s in the Args,
// performing a case-insensitive comparison. If the string is not found, it returns -1.
// This method is useful for scenarios where you want to check for matches without worrying about case sensitivity.
func (a *Args) IndexFold(s string) int {
	for i, token := range a.args {
		if strings.EqualFold(s, token) {
			return i
		}
	}
	return -1
}

// IndexAnyFold returns the index of the first occurrence of any string in the slice s within the Args,
// performing a case-insensitive comparison. If none of the strings are found, it returns -1.
// This method is useful for scenarios where you want to check for matches without worrying about case sensitivity
func (a *Args) IndexAnyFold(s []string) int {
	for i, token := range a.args {
		for _, t := range s {
			if strings.EqualFold(t, token) {
				return i
			}
		}
	}
	return -1
}

// Contains checks if the Args contains the specified string s.
func (a *Args) Contains(s string) bool {
	for _, token := range a.args {
		if strings.EqualFold(s, token) {
			return true
		}
	}
	return false
}

// ContainsFold checks if the Args contains the specified string s, performing a case-insensitive comparison.
// This method is useful for scenarios where you want to check for matches without worrying about case sensitivity.
func (a *Args) ContainsFold(s string) bool {
	for _, token := range a.args {
		if strings.EqualFold(s, token) {
			return true
		}
	}
	return false
}

// ContainsAny checks if the Args contains any of the strings in the slice s.
func (a *Args) ContainsAny(s []string) bool {
	for _, token := range a.args {
		for _, t := range s {
			if t == token {
				return true
			}
		}
	}
	return false
}

// ContainsAnyFold checks if the Args contains any of the strings in the slice s,
// performing a case-insensitive comparison. This method is useful for scenarios where
// you want to check for matches without worrying about case sensitivity.
func (a *Args) ContainsAnyFold(s []string) bool {
	for _, token := range a.args {
		for _, t := range s {
			if strings.EqualFold(t, token) {
				return true
			}
		}
	}
	return false
}

// Set updates the argument at the specified index i with the new value.
// If the index is out of bounds, it does nothing. This method allows for modifying
// existing arguments in place.
func (a *Args) Set(i int, value string) {
	if i < 0 || i >= len(a.args) {
		return
	}
	a.args[i] = value
}

// Push appends the specified values to the end of the Args slice.
// It normalizes the values to ensure they are properly formatted for command-line usage.
func (a *Args) Push(values ...string) *Args {
	values = normalizeArgs(values)
	a.args = append(a.args, values...)
	return a
}

// Append appends the specified values to the end of the Args slice.
// It normalizes the values to ensure they are properly formatted for command-line usage.
func (a *Args) Append(values ...string) *Args {
	values = normalizeArgs(values)
	a.args = append(a.args, values...)
	return a
}

// Prepend adds the specified values to the beginning of the Args slice.
// It normalizes the values to ensure they are properly formatted for command-line usage.
func (a *Args) Prepend(values ...string) *Args {
	values = normalizeArgs(values)
	a.args = append(values, a.args...)
	return a
}

// Shift removes and returns the first argument from the Args slice.
// If the slice is empty, it returns an empty string. This method is useful for
// processing command-line arguments in a sequential manner.
func (a *Args) Shift() string {
	if len(a.args) == 0 {
		return ""
	}
	value := a.args[0]
	a.args = a.args[1:]
	return value
}

// Pop removes and returns the last argument from the Args slice.
// If the slice is empty, it returns an empty string. This method is useful for
// processing command-line arguments in a sequential manner.
func (a *Args) Pop() string {
	if len(a.args) == 0 {
		return ""
	}
	value := a.args[len(a.args)-1]
	a.args = a.args[:len(a.args)-1]
	return value
}

// Remove removes the first occurrence of the specified string s from the Args slice.
// It returns true if the removal was successful, or false if the string was not found.
func (a *Args) Remove(s string) bool {
	for i, token := range a.args {
		if s == token {
			a.RemoveAt(i)
			return true
		}
	}

	return false
}

// RemoveAt removes the argument at the specified index i from the Args slice.
// It returns true if the removal was successful, or false if the index is out of range.
func (a *Args) RemoveAt(i int) bool {
	if i < 0 || i >= len(a.args) {
		return false
	}
	a.args = append(a.args[:i], a.args[i+1:]...)
	return true
}

// String returns the command-line arguments as a single string, with each argument
// separated by a space. Arguments are properly formatted using appendCliArg to ensure
// correct escaping or quoting as needed. If there are no arguments, an empty string is returned.
func (a *Args) String() string {
	if len(a.args) == 0 {
		return ""
	}

	sb := &strings.Builder{}
	for i, arg := range a.args {
		if i > 0 {
			sb.WriteString(" ")
		}
		appendCliArg(sb, arg)
	}
	return sb.String()
}

// Split parses the input string s into an Args structure, splitting it into tokens
// similar to how a shell parses command-line arguments. It handles single and double
// quotes, escaped quotes, and whitespace as delimiters. Special handling is included
// for line continuations and escaped newlines. The resulting Args contains the parsed
// arguments as a slice of strings.
func Split(s string) *Args {
	quote := quoteNone
	token := strings.Builder{}
	tokens := []string{}
	runes := []rune(s)
	l := len(runes)
	for i := 0; i < l; i++ {
		c := runes[i]

		if quote != quoteNone {
			previous := rune(0)
			if i > 0 {
				previous = runes[i-1]
			}

			switch quote {
			case quoteSingle:
				if c == '\'' && previous != '\\' {
					quote = quoteNone
					if token.Len() > 0 {
						tokens = append(tokens, token.String())
						token.Reset()
					}

					continue
				}
			case quoteDouble:
				if c == '"' && previous != '\\' {
					quote = quoteNone
					if token.Len() > 0 {
						tokens = append(tokens, token.String())
						token.Reset()
					}

					continue
				}
			}

			token.WriteRune(c)
			continue
		}

		if c == ' ' {
			if token.Len() == 0 {
				continue
			}

			size := i + 1
			remaining := l - size
			if remaining > 2 {
				j := runes[i+1]
				k := runes[i+2]

				if j == '\n' {
					i += 1
					if token.Len() > 0 {
						tokens = append(tokens, token.String())
						token.Reset()
					}

					continue
				}

				if j == '\r' && k == '\n' {
					i += 2
					if token.Len() > 0 {
						tokens = append(tokens, token.String())
						token.Reset()
					}

					continue
				}

				if (j == '\\' || j == '`') && k == '\n' {
					i += 2

					if token.Len() > 0 {
						tokens = append(tokens, token.String())
					}

					token.Reset()
					continue
				}

				if remaining > 3 {
					l := runes[i+3]
					if (j == '\\' || j == '`') && k == '\r' && l == '\n' {
						i += 3
						if token.Len() > 0 {
							tokens = append(tokens, token.String())
						}

						token.Reset()
						continue
					}
				}
			}

			if token.Len() > 0 {
				tokens = append(tokens, token.String())
				token.Reset()
			}
			continue
		}

		if token.Len() == 0 {
			switch c {
			case '\'':
				quote = quoteSingle
				continue

			case '"':
				quote = quoteDouble
				continue
			}
		}

		if unicode.IsSpace(c) {
			break
		}

		token.WriteRune(c)
	}

	if token.Len() > 0 {
		tokens = append(tokens, token.String())
	}

	token.Reset()

	return &Args{
		args: tokens,
	}
}

func SplitAndExpand(s string, expand func(string) (string, error)) (*Args, error) {
	quote := quoteNone
	token := strings.Builder{}
	tokens := []string{}
	runes := []rune(s)
	l := len(runes)
	hasDollar := false
	for i := 0; i < l; i++ {
		c := runes[i]

		if c == '$' {
			hasDollar = true
		}

		if quote != quoteNone {
			previous := rune(0)
			if i > 0 {
				previous = runes[i-1]
			}

			switch quote {
			case quoteSingle:
				if c == '\'' && previous != '\\' {
					quote = quoteNone
					if token.Len() > 0 {
						tokens = append(tokens, token.String())
						token.Reset()
					}
					hasDollar = false

					continue
				}
			case quoteDouble:
				if c == '"' && previous != '\\' {
					quote = quoteNone
					if token.Len() > 0 {
						if hasDollar {
							expanded, err := expand(token.String())
							if err != nil {
								return nil, err
							}
							tokens = append(tokens, expanded)
							hasDollar = false
						} else {
							tokens = append(tokens, token.String())
						}
						token.Reset()
					}
					hasDollar = false

					continue
				}
			}

			token.WriteRune(c)
			continue
		}

		if c == ' ' {
			if token.Len() == 0 {
				continue
			}

			size := i + 1
			remaining := l - size
			if remaining > 2 {
				j := runes[i+1]
				k := runes[i+2]

				if j == '\n' {
					i += 1
					if token.Len() > 0 {
						if hasDollar {
							expanded, err := expand(token.String())
							if err != nil {
								return nil, err
							}
							tokens = append(tokens, expanded)
							hasDollar = false
						} else {
							tokens = append(tokens, token.String())
						}
						token.Reset()
					}

					continue
				}

				if j == '\r' && k == '\n' {
					i += 2
					if token.Len() > 0 {
						if hasDollar {
							expanded, err := expand(token.String())
							if err != nil {
								return nil, err
							}
							tokens = append(tokens, expanded)
							hasDollar = false
						} else {
							tokens = append(tokens, token.String())
						}
						token.Reset()
					}

					continue
				}

				if (j == '\\' || j == '`') && k == '\n' {
					i += 2

					if token.Len() > 0 {
						if hasDollar {
							expanded, err := expand(token.String())
							if err != nil {
								return nil, err
							}
							tokens = append(tokens, expanded)
							hasDollar = false
						} else {
							tokens = append(tokens, token.String())
						}
					}

					token.Reset()
					continue
				}

				if remaining > 3 {
					l := runes[i+3]
					if (j == '\\' || j == '`') && k == '\r' && l == '\n' {
						i += 3
						if token.Len() > 0 {
							if hasDollar {
								expanded, err := expand(token.String())
								if err != nil {
									return nil, err
								}
								tokens = append(tokens, expanded)
								hasDollar = false
							} else {
								tokens = append(tokens, token.String())
							}
						}

						token.Reset()
						continue
					}
				}
			}

			if token.Len() > 0 {
				if hasDollar {
					expanded, err := expand(token.String())
					if err != nil {
						return nil, err
					}
					hasDollar = false
					tokens = append(tokens, expanded)
				} else {
					tokens = append(tokens, token.String())
				}

				token.Reset()
			}
			continue
		}

		if token.Len() == 0 {
			switch c {
			case '\'':
				quote = quoteSingle
				continue

			case '"':
				quote = quoteDouble
				continue
			}
		}

		if unicode.IsSpace(c) {
			break
		}

		token.WriteRune(c)
	}

	if token.Len() > 0 {
		if hasDollar {
			expanded, err := expand(token.String())
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, expanded)
		} else {
			tokens = append(tokens, token.String())
		}
	}

	token.Reset()
	args := &Args{
		args: tokens,
	}
	return args, nil
}

func normalizeArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		if len(arg) == 0 {
			continue
		}

		if (arg[0] == '"' && arg[len(arg)-1] == '"') || (arg[0] == '\'' && arg[len(arg)-1] == '\'') {
			arg = arg[1 : len(arg)-1]
		}

		normalized = append(normalized, arg)
	}

	return normalized
}
