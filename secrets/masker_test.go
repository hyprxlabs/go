package secrets_test

import (
	"testing"

	"github.com/hyprxlabs/go/secrets"
	"github.com/stretchr/testify/assert"
)

func TestAddValueAndMask(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("secret")
	result := m.Mask("this is a secret message")
	assert.Equal(t, "this is a **** message", result)
}

func TestAddValueEmpty(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("")
	result := m.Mask("no secrets here")
	assert.Equal(t, "no secrets here", result)
}

func TestMaskMultipleSecrets(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("foo")
	m.AddValue("bar")
	result := m.Mask("foo and bar are secrets")
	assert.Equal(t, "**** and **** are secrets", result)
}

func TestMaskNoMatch(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("secret")
	result := m.Mask("nothing to mask here")
	assert.Equal(t, "nothing to mask here", result)
}

func TestMaskOverlappingSecrets(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("abc")
	m.AddValue("bcd")
	result := m.Mask("xabcd")
	// Only "abc" at position 1, then "bcd" at position 2, so both should be masked
	// But since hits are not overlapping, both are masked
	assert.Equal(t, "x****d", result)
}

func TestAddGenerator(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddGenerator(func(s string) string { return s + "!" })
	m.AddValue("top")
	result := m.Mask("top and top! are both secret")
	assert.Equal(t, "**** and **** are both secret", result)
}

func TestApplyGenerators(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddGenerator(func(s string) string { return s + "X" })
	out := m.ApplyGenerators("foo")
	assert.Equal(t, "fooX", out)
}

func TestMaskCaseInsensitive(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("Secret")
	result := m.Mask("this is a secret message")
	// Should mask "secret" even if added as "Secret" due to unicode.SimpleFold
	assert.Equal(t, "this is a **** message", result)
}

func TestMaskEmptyInput(t *testing.T) {
	m := &secrets.SecretMasker{}
	m.AddValue("secret")
	result := m.Mask("")
	assert.Equal(t, "", result)
}

func TestMaskNoValues(t *testing.T) {
	m := &secrets.SecretMasker{}
	result := m.Mask("something")
	assert.Equal(t, "something", result)
}
