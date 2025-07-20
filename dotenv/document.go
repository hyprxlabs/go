package dotenv

const (
	NEWLINE_TOKEN  = 0
	COMMENT_TOKEN  = 1
	VARIABLE_TOKEN = 2
	empty_token    = 3
)

type Node struct {
	Type   int
	Value  string
	Key    *string
	Inline bool
	Quote  *rune
}

type EnvDoc struct {
	tokens []Node
}

func NewDocument() *EnvDoc {
	return &EnvDoc{
		tokens: make([]Node, 0),
	}
}

func (doc *EnvDoc) AddNewline() {
	doc.tokens = append(doc.tokens, Node{Type: NEWLINE_TOKEN, Value: "\n"})
}

func (doc *EnvDoc) AddComment(comment string) {
	doc.tokens = append(doc.tokens, Node{Type: COMMENT_TOKEN, Value: comment})
}

func (doc *EnvDoc) AddInlineComment(comment string) {
	doc.tokens = append(doc.tokens, Node{Type: COMMENT_TOKEN, Value: comment, Inline: true})
}

func (doc *EnvDoc) AddVariable(key, value string) {
	if value == "" {
		doc.tokens = append(doc.tokens, Node{
			Type:  VARIABLE_TOKEN,
			Key:   &key,
			Value: "",
		})
		return
	}

	if value[0] == '"' || value[0] == '\'' {
		quote := rune(value[0])
		doc.tokens = append(doc.tokens, Node{
			Type:  VARIABLE_TOKEN,
			Value: value[1 : len(value)-1],
			Key:   &key,
			Quote: &quote,
		})
		return
	}

	quoted := false
	runes := []rune(value)
	min := rune(0)
	l := len(runes)
	for j := 0; j < l; j++ {
		c := runes[j]
		n := min
		if j+1 < l {
			n = runes[j+1]
		}

		if c == '\\' {
			if n == '\\' || n == 'n' || n == 'r' || n == 't' || n == 'u' || n == 'U' || n == 'b' || n == 'f' {
				quoted = true
				break
			}
		}

		if c == '"' || c == '\'' || c == '\n' || c == '\r' || c == '\t' || c == '=' || c == '#' || c == '\b' || c == '\f' || c == '\v' {
			quoted = true
			break
		}
	}

	var quote *rune

	if quoted {
		r := rune('"')
		quote = &r
	}

	doc.tokens = append(doc.tokens, Node{
		Type:  VARIABLE_TOKEN,
		Value: value,
		Key:   &key,
		Quote: quote,
	})
}

func (doc *EnvDoc) AddQuotedVariable(key, value string, quote rune) {
	doc.tokens = append(doc.tokens, Node{
		Type:  VARIABLE_TOKEN,
		Value: value,
		Key:   &key,
		Quote: &quote,
	})
}

func (doc *EnvDoc) Add(token Node) {
	if token.Type == NEWLINE_TOKEN || token.Type == COMMENT_TOKEN || token.Type == VARIABLE_TOKEN {
		doc.tokens = append(doc.tokens, token)
	} else {
		// Ignore other types of tokens
		return
	}
}

func (doc *EnvDoc) AddRange(tokens []Node) {
	if tokens == nil || len(tokens) == 0 {
		return
	}

	for _, token := range tokens {
		doc.Add(token)
	}
}

func (doc *EnvDoc) Len() int {
	return len(doc.tokens)
}

func (doc *EnvDoc) At(index int) *Node {
	if index < 0 || index >= len(doc.tokens) {
		return nil
	}
	return &doc.tokens[index]
}

func (doc *EnvDoc) ToArray() []Node {
	if doc == nil {
		return []Node{}
	}

	arr := make([]Node, len(doc.tokens))
	copy(arr, doc.tokens)
	return arr
}

func (doc *EnvDoc) ToMap() map[string]string {
	m := make(map[string]string)
	for _, token := range doc.tokens {
		if token.Type == VARIABLE_TOKEN && token.Key != nil {
			m[*token.Key] = token.Value
		}
	}
	return m
}

func (doc *EnvDoc) Get(key string) (string, bool) {
	for _, token := range doc.tokens {
		if token.Type == VARIABLE_TOKEN && token.Key != nil && *token.Key == key {
			return token.Value, true
		}
	}
	return "", false
}

func (doc *EnvDoc) Keys() []string {
	keys := make([]string, 0, len(doc.tokens))
	for _, token := range doc.tokens {
		if token.Type == VARIABLE_TOKEN && token.Key != nil {
			keys = append(keys, *token.Key)
		}
	}
	return keys
}

func (doc *EnvDoc) GetComments() []string {
	comments := make([]string, 0, len(doc.tokens))
	for _, token := range doc.tokens {
		if token.Type == COMMENT_TOKEN {
			comments = append(comments, token.Value)
		}
	}
	return comments
}

func (doc *EnvDoc) Set(key, value string) {
	isset := false
	for i, token := range doc.tokens {
		if token.Type == VARIABLE_TOKEN && token.Key != nil && *token.Key == key {
			doc.tokens[i].Value = value
			isset = true
			break
		}
	}
	if !isset {
		doc.AddVariable(key, value)
	}
}

func (doc *EnvDoc) Merge(other *EnvDoc) {
	for _, token := range other.tokens {
		switch token.Type {
		case VARIABLE_TOKEN:
			doc.Set(*token.Key, token.Value)
		}
	}
}

func (doc *EnvDoc) String() string {
	var result string
	empty := &Node{
		Type:  empty_token,
		Value: "",
	}

	for i := 0; i < len(doc.tokens); i++ {
		token := doc.tokens[i]
		nextToken := empty
		if i+1 < len(doc.tokens) {
			nextToken = &doc.tokens[i+1]
		}

		switch token.Type {
		case NEWLINE_TOKEN:
			result += "\n"
		case COMMENT_TOKEN:
			result += "\n# " + token.Value
		case VARIABLE_TOKEN:
			result += "\n"
			if token.Key == nil {
				continue
			}

			result += *token.Key + "="
			if token.Quote != nil {
				result += string(*token.Quote)
				result += token.Value
				result += string(*token.Quote)
			} else {
				result += token.Value
			}

			if nextToken.Type == COMMENT_TOKEN && nextToken.Inline {
				result += " # " + nextToken.Value
				i++
			}
		}
	}

	if len(result) > 0 && result[0] == '\n' {
		result = result[1:] // Remove leading newline
	}

	return result
}
