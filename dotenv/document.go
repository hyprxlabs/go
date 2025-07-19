package dotenv

const (
	NEWLINE_TOKEN  = 0
	COMMENT_TOKEN  = 1
	VARIABLE_TOKEN = 2
)

type Node struct {
	Type  int
	Value string
	Key   *string
}

type EnvDoc struct {
	tokens []Node
}

func (doc *EnvDoc) AddNode(node Node) {
	doc.tokens = append(doc.tokens, node)
}

func (doc *EnvDoc) AddNewline() {
	doc.tokens = append(doc.tokens, Node{Type: NEWLINE_TOKEN, Value: "\n"})
}

func (doc *EnvDoc) AddComment(comment string) {
	doc.tokens = append(doc.tokens, Node{Type: COMMENT_TOKEN, Value: comment})
}

func (doc *EnvDoc) AddVariable(key, value string) {
	doc.tokens = append(doc.tokens, Node{
		Type:  VARIABLE_TOKEN,
		Value: value,
		Key:   &key,
	})
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

func (doc *EnvDoc) GetValue(key string) (string, bool) {
	for _, token := range doc.tokens {
		if token.Type == VARIABLE_TOKEN && token.Key != nil && *token.Key == key {
			return token.Value, true
		}
	}
	return "", false
}

func (doc *EnvDoc) GetKeys() []string {
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

func (doc *EnvDoc) SetValue(key, value string) {
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
			doc.SetValue(*token.Key, token.Value)
		}
	}
}
