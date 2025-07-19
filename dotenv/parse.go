package dotenv

import (
	"fmt"
	"strconv"
	"unicode"
)

const (
	quote_none     = 0
	quote_single   = 1
	quote_double   = 2
	quote_backtick = 3
	TOKEN_COMMENT  = 1
	TOKEN_NAME     = 2
	TOKEN_VALUE    = 3
	TOKEN_NEWLINE  = 4
	token_none     = 0
)

type Mark struct {
	Line   int
	Column int
}

type Token struct {
	Type     int
	RawValue []rune
	value    *string
	Quote    int
	Start    *Mark
	End      *Mark
}

type parseState struct {
	Current *Token
	Line    int
	Column  int
	Quote   int
	Buffer  []rune
	Tokens  []*Token
	Start   *Mark
}

type ParseError struct {
	Message string
	Line    int
	Column  int
}

func (t *Token) Value() string {
	if t.value != nil {
		return *t.value
	}
	return string(t.RawValue)
}

func (e *ParseError) Error() string {
	return e.Message + " at line " + strconv.Itoa(e.Line) + ", column " + strconv.Itoa(e.Column)
}

func (e *ParseError) String() string {
	return e.Message + " at line " + strconv.Itoa(e.Line) + ", column " + strconv.Itoa(e.Column)
}

func Lex(input string) ([]*Token, error) {

	kind := token_none

	state := &parseState{
		Current: nil,
		Line:    1,
		Column:  1,
		Quote:   quote_none,
		Buffer:  []rune{},
		Tokens:  []*Token{},
		Start:   &Mark{Line: 1, Column: 1},
	}
	runes := []rune(input)

	keyTerminated := false
	max := len(runes)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		var p rune
		p = rune(0)

		if i+1 < max {
			p = runes[i+1]
		}

		linebreak := false
		if c == '\n' || c == 0 {
			linebreak = true
		} else if c == '\r' && p == '\n' {
			i++ // skip the next character if it's a \n after \r
			linebreak = true
		}

		if linebreak && state.Quote == quote_none {
			state.Line++
			state.Column = 1
			state.Start = &Mark{Line: state.Line, Column: state.Column}

			if len(state.Buffer) == 0 {
				state.Current = &Token{
					Type:     NEWLINE_TOKEN,
					RawValue: []rune("\n"),
					Quote:    quote_none,
					Start:    state.Start,
					End: &Mark{
						Line:   state.Line,
						Column: state.Column - 1,
					},
				}

				state.Tokens = append(state.Tokens, state.Current)
				state.Start = &Mark{Line: state.Line, Column: state.Column}
				state.Buffer = []rune{}
				kind = token_none
				continue
			}

			switch kind {
			case TOKEN_NAME:
				fallthrough
			case token_none:
				{

					copy := make([]rune, len(state.Buffer))
					copy = append(copy, state.Buffer...)
					state.Current = &Token{
						Type:     TOKEN_NAME,
						RawValue: copy,
						Quote:    quote_none,
						Start:    state.Start,
						End: &Mark{
							Line:   state.Line,
							Column: state.Column - 1,
						},
					}

					println("Adding TOKEN_NAME:", string(state.Current.RawValue))

					state.Tokens = append(state.Tokens, state.Current)
					state.Start = &Mark{Line: state.Line, Column: state.Column}
					state.Buffer = []rune{}
					kind = token_none
				}
			case TOKEN_COMMENT:
				{
					copy := make([]rune, len(state.Buffer))
					copy = append(copy, state.Buffer...)
					state.Current = &Token{
						Type:     TOKEN_COMMENT,
						RawValue: copy,
						Quote:    quote_none,
						Start:    state.Start,
						End: &Mark{
							Line:   state.Line,
							Column: state.Column - 1,
						},
					}

					state.Tokens = append(state.Tokens, state.Current)
					state.Start = &Mark{Line: state.Line, Column: state.Column}
					state.Buffer = []rune{}
					kind = token_none
				}
			case TOKEN_VALUE:
				{
					if state.Current.Type == TOKEN_VALUE {
						e := &ParseError{
							Message: "Invalid syntax: previous value not terminated",
							Line:    state.Line,
							Column:  state.Column,
						}

						return nil, e
					}

					println("copy buffer", string(state.Buffer))
					var copy = make([]rune, len(state.Buffer))
					copy = append(copy, state.Buffer...)

					l := len(copy)
					pos := l - 1
					for pos >= 0 && unicode.IsSpace(copy[pos]) {
						pos--
						l--
					}

					if l > 0 {
						copy = copy[:l]
						state.Current = &Token{
							Type:     TOKEN_VALUE,
							RawValue: copy,
							Quote:    quote_none,
							Start:    state.Start,
							End: &Mark{
								Line:   state.Line,
								Column: state.Column - 1,
							},
						}

						state.Buffer = []rune{}
						state.Tokens = append(state.Tokens, state.Current)
					} else {
						println("empty value found, creating empty token", string(state.Buffer))
						state.Current = &Token{
							Type:     TOKEN_VALUE,
							RawValue: []rune{},
							Quote:    quote_none,
							Start:    state.Start,
							End: &Mark{
								Line:   state.Line,
								Column: state.Column - 1,
							},
						}

						state.Buffer = []rune{}
						state.Tokens = append(state.Tokens, state.Current)
					}

					kind = token_none

				}
			}

			continue
		}

		state.Column++
		switch kind {
		case token_none:
			if unicode.IsSpace(c) {
				continue
			}
			if c == '#' {
				kind = TOKEN_COMMENT
				continue
			}

			if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' {
				kind = TOKEN_NAME
				state.Buffer = append(state.Buffer, c)
				continue
			}

			fail := &ParseError{
				Message: "Invalid syntax: unexpected character '" + string(c) + "'",
				Line:    state.Line,
				Column:  state.Column,
			}

			return nil, fail

		case TOKEN_NAME:
			{
				// do not append, ignore # and continue
				if c == '#' && len(state.Buffer) == 0 {
					kind = TOKEN_COMMENT
					continue
				}

				if c == '=' {
					if len(state.Buffer) == 0 {
						e := &ParseError{
							Message: "Invalid syntax: '=' without a name",
							Line:    state.Line,
							Column:  state.Column,
						}
						return nil, e
					}

					kind = TOKEN_VALUE
					state.Current = &Token{
						Type:     TOKEN_NAME,
						RawValue: []rune(string(state.Buffer)),
						Quote:    quote_none,
						Start:    state.Start,
						End: &Mark{
							Line:   state.Line,
							Column: state.Column - 1,
						},
					}
					println("Adding TOKEN_NAME:", string(state.Current.RawValue))

					state.Buffer = []rune{}
					state.Tokens = append(state.Tokens, state.Current)
					state.Start = &Mark{Line: state.Line, Column: state.Column}
					continue
				}

				if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' {

					if keyTerminated {
						e := &ParseError{
							Message: "Invalid syntax: key terminated by whitespace. fix key",
							Line:    state.Line,
							Column:  state.Column,
						}

						return nil, e
					}

					state.Buffer = append(state.Buffer, c)
					continue
				}

				if unicode.IsSpace(c) {
					if len(state.Buffer) > 0 {
						keyTerminated = true
					}

					continue
				}

				fail := &ParseError{
					Message: "Invalid syntax: unexpected character '" + string(c) + "'",
					Line:    state.Line,
					Column:  state.Column,
				}

				return nil, fail
			}
		case TOKEN_COMMENT:
			{
				state.Buffer = append(state.Buffer, c)
				continue
			}

		case TOKEN_VALUE:
			{
				if state.Quote == quote_none {
					if len(state.Buffer) == 0 {
						switch c {
						case '\t':
							fallthrough
						case '\n':
							continue
						case '"':
							state.Quote = quote_double
							state.Start = &Mark{Line: state.Line, Column: state.Column}
							continue
						case '\'':
							state.Quote = quote_single
							state.Start = &Mark{Line: state.Line, Column: state.Column}
							continue
						case '`':
							state.Quote = quote_backtick
							state.Start = &Mark{Line: state.Line, Column: state.Column}
							continue
						default:
							if unicode.IsSpace(c) {
								continue
							}

							println("Appending character to buffer:", string(c))
							state.Buffer = append(state.Buffer, c)
							continue
						}
					}

					if c == '#' {
						kind = TOKEN_COMMENT
						copy := make([]rune, len(state.Buffer))
						copy = append(copy, state.Buffer...)
						l := len(copy)
						pos := l - 1
						for pos >= 0 && unicode.IsSpace(copy[pos]) {
							pos--
							l--
						}

						if l > 0 {
							copy = copy[:l]
							state.Current = &Token{
								Type:     TOKEN_VALUE,
								RawValue: copy,
								Quote:    quote_none,
								Start:    state.Start,
								End: &Mark{
									Line:   state.Line,
									Column: state.Column - 1,
								},
							}

							state.Buffer = []rune{}
							state.Tokens = append(state.Tokens, state.Current)
						} else {
							state.Current = &Token{
								Type:     TOKEN_VALUE,
								RawValue: []rune{},
								Quote:    quote_none,
								Start:    state.Start,
								End: &Mark{
									Line:   state.Line,
									Column: state.Column - 1,
								},
							}

							state.Buffer = []rune{}
							state.Tokens = append(state.Tokens, state.Current)
						}

						state.Buffer = []rune{}
						state.Start = &Mark{Line: state.Line, Column: state.Column}
						continue
					}

					println("Appending character to buffer:", string(c))
					state.Buffer = append(state.Buffer, c)
					continue
				}

				if state.Quote == quote_double || state.Quote == quote_backtick {
					if c == '\\' {
						if p == 'n' || p == 'r' || p == 't' || p == '\\' || p == '"' || p == '\'' || p == 'b' || p == '`' {
							i++
							switch p {
							case 'n':
								state.Buffer = append(state.Buffer, '\n')
							case 'r':
								state.Buffer = append(state.Buffer, '\r')
							case 't':
								state.Buffer = append(state.Buffer, '\t')
							case 'b':
								state.Buffer = append(state.Buffer, '\b')
							default:
								state.Buffer = append(state.Buffer, p)
							}

							continue
						}

						if p == 'U' {

							if i+7 < max {
								// capture unicode escape sequence
								hex := string(runes[i+2 : i+10])
								if len(hex) == 8 {
									var codePoint rune
									_, err := fmt.Sscanf(hex, "%x", &codePoint)
									if err == nil {
										state.Buffer = append(state.Buffer, codePoint)
										i += 9 // skip the next 9 characters
									} else {
										return nil, &ParseError{
											Message: "Invalid unicode escape sequence",
											Line:    state.Line,
											Column:  state.Column,
										}
									}
								}
							}
							continue
						}

						if p == 'u' {

							if i+5 < max {
								// capture unicode escape sequence
								hex := string(runes[i+2 : i+6])
								if len(hex) == 4 {
									var codePoint rune
									_, err := fmt.Sscanf(hex, "%x", &codePoint)
									if err == nil {
										state.Buffer = append(state.Buffer, codePoint)
										i += 5 // skip the next 5 characters
									} else {
										return nil, &ParseError{
											Message: "Invalid unicode escape sequence",
											Line:    state.Line,
											Column:  state.Column,
										}
									}
								}
							}
							continue
						}

						state.Buffer = append(state.Buffer, c)
					}
				}

				if captureMultiline(c, state) {
					continue
				}

				if len(state.Buffer) == 0 && unicode.IsSpace(c) {
					continue
				}

				state.Buffer = append(state.Buffer, c)
			}
		}
	}

	if len(state.Buffer) > 0 {
		if state.Current != nil {
			if state.Current.Type == TOKEN_VALUE {
				e := &ParseError{
					Message: "Invalid syntax: value not terminated",
					Line:    state.Line,
					Column:  state.Column,
				}
				return nil, e
			}

			if state.Current.Type == TOKEN_NAME {
				state.Current = &Token{
					Type:     TOKEN_VALUE,
					RawValue: []rune(string(state.Buffer)),
					Quote:    quote_none,
					Start:    state.Start,
					End: &Mark{
						Line:   state.Line,
						Column: state.Column - 1,
					},
				}

				println("Adding TOKEN_VALUE:", string(state.Current.RawValue))

				state.Tokens = append(state.Tokens, state.Current)
				state.Buffer = []rune{}
			} else {
				state.Current = &Token{
					Type:     TOKEN_NAME,
					RawValue: []rune(string(state.Buffer)),
					Quote:    quote_none,
					Start:    state.Start,
					End: &Mark{
						Line:   state.Line,
						Column: state.Column - 1,
					},
				}

				println("Adding TOKEN_NAME:", string(state.Current.RawValue))

				state.Tokens = append(state.Tokens, state.Current)
				state.Buffer = []rune{}
			}

		} else {
			state.Current = &Token{
				Type:     TOKEN_NAME,
				RawValue: []rune(string(state.Buffer)),
				Quote:    quote_none,
				Start:    state.Start,
				End: &Mark{
					Line:   state.Line,
					Column: state.Column - 1,
				},
			}
			state.Tokens = append(state.Tokens, state.Current)
		}
	}

	return state.Tokens, nil
}

func captureMultiline(r rune, state *parseState) bool {
	switch state.Quote {
	case quote_none:
		return false

	case quote_single:
		if r == '\'' {
			if len(state.Buffer) > 0 && state.Buffer[len(state.Buffer)-1] == '\'' {
				state.Buffer = state.Buffer[:len(state.Buffer)-1]
				return false
			}

			state.Quote = quote_none
			state.Current = &Token{
				Type:     TOKEN_VALUE,
				RawValue: []rune(string(state.Buffer)),
				Quote:    quote_single,
				Start:    state.Start,
				End: &Mark{
					Line:   state.Line,
					Column: state.Column,
				},
			}

			state.Start = nil
			state.Buffer = []rune{}
			state.Tokens = append(state.Tokens, state.Current)
			return true
		}
	case quote_double:
		if r == '"' {
			if len(state.Buffer) > 0 && state.Buffer[len(state.Buffer)-1] == '"' {
				state.Buffer = state.Buffer[:len(state.Buffer)-1]
				return false
			}

			state.Quote = quote_none
			state.Current = &Token{
				Type:     TOKEN_VALUE,
				RawValue: []rune(string(state.Buffer)),
				Quote:    quote_double,
				Start:    state.Start,
				End: &Mark{
					Line:   state.Line,
					Column: state.Column,
				},
			}

			state.Start = nil
			state.Buffer = []rune{}
			state.Tokens = append(state.Tokens, state.Current)
			return true
		}
	case quote_backtick:
		if r == '`' {
			if len(state.Buffer) > 0 && state.Buffer[len(state.Buffer)-1] == '`' {
				state.Buffer = state.Buffer[:len(state.Buffer)-1]
				return false
			}

			state.Quote = quote_none
			state.Current = &Token{
				Type:     TOKEN_VALUE,
				RawValue: []rune(string(state.Buffer)),
				Quote:    quote_backtick,
				Start:    state.Start,
				End: &Mark{
					Line:   state.Line,
					Column: state.Column,
				},
			}

			state.Start = nil
			state.Buffer = []rune{}
			state.Tokens = append(state.Tokens, state.Current)
			return true
		}
	}

	return false
}

func Parse(input string) (*EnvDoc, error) {
	tokens, err := Lex(input)
	if err != nil {
		return nil, err
	}

	doc := &EnvDoc{
		tokens: make([]Node, 0, len(tokens)),
	}

	var key *string

	for _, token := range tokens {
		switch token.Type {
		case TOKEN_NEWLINE:
			key = nil
			doc.AddNewline()
			continue
		case TOKEN_COMMENT:
			key = nil
			doc.AddComment(string(token.RawValue))
		case TOKEN_NAME:
			println("Processing TOKEN_NAME:", string(token.RawValue))
			if key == nil {
				v := string(token.RawValue)
				key = &v
				continue
			}

			doc.AddVariable(*key, "")
			v2 := string(token.RawValue)
			key = &v2
		case TOKEN_VALUE:
			println("Processing TOKEN_VALUE:", string(token.RawValue))
			if key == nil {
				return nil, &ParseError{
					Message: "Invalid syntax: value without a key",
					Line:    token.Start.Line,
					Column:  token.Start.Column,
				}
			}

			doc.AddVariable(*key, string(token.RawValue))
			key = nil
		}
	}

	if key != nil {
		doc.AddVariable(*key, "")
		key = nil
	}

	return doc, nil
}
