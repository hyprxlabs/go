package secrets

import (
	"crypto/rand"
	"errors"
	"math/big"
	"unicode"
	"unicode/utf8"
)

type Options struct {
	Size      int16
	Lower     bool
	Upper     bool
	Digits    bool
	Symbols   *string
	Chars     *string
	Validator func([]rune) error
	Retries   int
}

type SetOption func(*Options)

type OptionsBuilder struct {
	opts []SetOption
}

func NewOptionsBuilder() *OptionsBuilder {
	return &OptionsBuilder{}
}

func (b *OptionsBuilder) WithLower(lower bool) *OptionsBuilder {
	b.opts = append(b.opts, WithLower(lower))
	return b
}

func (b *OptionsBuilder) WithUpper(upper bool) *OptionsBuilder {
	b.opts = append(b.opts, WithUpper(upper))
	return b
}

func (b *OptionsBuilder) WithDigits(digits bool) *OptionsBuilder {
	b.opts = append(b.opts, WithDigits(digits))
	return b
}

func (b *OptionsBuilder) WithSize(size int16) *OptionsBuilder {
	b.opts = append(b.opts, WithSize(size))
	return b
}

func (b *OptionsBuilder) Push(setter ...SetOption) *OptionsBuilder {
	b.opts = append(b.opts, setter...)
	return b
}

func (b *OptionsBuilder) WithSymbols(symbols string) *OptionsBuilder {
	b.opts = append(b.opts, WithSymbols(symbols))
	return b
}

func (b *OptionsBuilder) WithNoSymbols() *OptionsBuilder {
	b.opts = append(b.opts, WithNoSymbols())
	return b
}

func (b *OptionsBuilder) WithChars(chars string) *OptionsBuilder {
	b.opts = append(b.opts, WithChars(chars))
	return b
}

func (b *OptionsBuilder) WithValidator(validator func([]rune) error) *OptionsBuilder {
	b.opts = append(b.opts, WithValidator(validator))
	return b
}

func (b *OptionsBuilder) WithRetries(retries int) *OptionsBuilder {
	b.opts = append(b.opts, WithRetries(retries))
	return b
}

func (b *OptionsBuilder) ToArray() []SetOption {
	copy2 := make([]SetOption, len(b.opts))
	copy(copy2, b.opts)
	return copy2
}

func (b *OptionsBuilder) Build() Options {
	var opts Options
	for _, o := range b.opts {
		o(&opts)
	}
	return opts
}

func WithSize(size int16) SetOption {
	return func(o *Options) {
		o.Size = size
	}
}

func WithLower(lower bool) SetOption {
	return func(o *Options) {
		o.Lower = lower
	}
}

func WithUpper(upper bool) SetOption {
	return func(o *Options) {
		o.Upper = upper
	}
}

func WithDigits(digits bool) SetOption {
	return func(o *Options) {
		o.Digits = digits
	}
}

func WithSymbols(symbols string) SetOption {
	return func(o *Options) {
		o.Symbols = &symbols
	}
}

func WithNoSymbols() SetOption {
	return func(o *Options) {
		empty := ""
		o.Symbols = &empty
	}
}

func WithChars(chars string) SetOption {
	return func(o *Options) {
		o.Chars = &chars
	}
}

func WithValidator(validator func([]rune) error) SetOption {
	return func(o *Options) {
		o.Validator = validator
	}
}

func WithRetries(retries int) SetOption {
	return func(o *Options) {
		o.Retries = retries
	}
}

func Generate(size int16, opts ...SetOption) (string, error) {
	runes, err := GenerateRunes(size, opts...)
	if err != nil {
		return "", err
	}
	return string(runes), nil
}

func GenerateBytes(size int16, opts ...SetOption) ([]byte, error) {
	runes, err := GenerateRunes(size, opts...)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, utf8.RuneLen(runes[0])*len(runes))
	for i, r := range runes {
		n := utf8.EncodeRune(buffer[i*utf8.RuneLen(r):], r)
		if n != utf8.RuneLen(r) {
			return nil, errors.New("failed to encode rune to bytes")
		}
	}
	return buffer, nil
}

func (options *Options) Generate() (string, error) {
	runes, err := options.GenerateRunes()
	if err != nil {
		return "", err
	}
	return string(runes), nil
}

func (options *Options) GenerateBytes() ([]byte, error) {
	runes, err := options.GenerateRunes()
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, utf8.RuneLen(runes[0])*len(runes))
	for i, r := range runes {
		n := utf8.EncodeRune(buffer[i*utf8.RuneLen(r):], r)
		if n != utf8.RuneLen(r) {
			return nil, errors.New("failed to encode rune to bytes")
		}
	}
	return buffer, nil
}

func (options *Options) GenerateRunes() ([]rune, error) {
	if options.Validator == nil {
		options.Validator = defaultValidator(*options)
	}

	if options.Size <= 0 {
		options.Size = 16
	}

	var chars string
	if options.Chars != nil {
		chars = *options.Chars
	} else {
		if options.Lower {
			chars += "abcdefghijklmnopqrstuvwxyz"
		}
		if options.Upper {
			chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		}
		if options.Digits {
			chars += "0123456789"
		}
		if options.Symbols != nil {
			chars += *options.Symbols
		} else {
			chars += "@_-^+=|{}#~`"
		}
	}
	result := make([]rune, 0)

	if chars == "" {
		return result, errors.New("no character sets selected")
	}

	// retry loop

	var finalError error

	charRunes := []rune(chars)
	for i := 0; i < options.Retries; i++ {
		// use crypto/rand to generate secure random characters
		result := make([]rune, options.Size)
		for i := range result {
			index, finalError := rand.Int(rand.Reader, big.NewInt(int64(len(charRunes))))
			if finalError != nil {
				continue
			}
			result[i] = charRunes[index.Int64()]
		}

		if options.Validator != nil {
			err := options.Validator(result)
			if err != nil {
				finalError = err
				continue
			}
		}

		return result, nil
	}

	return result, finalError
}

func GenerateRunes(size int16, opts ...SetOption) ([]rune, error) {
	options := Options{
		Size:      size,
		Lower:     true,
		Upper:     true,
		Digits:    true,
		Symbols:   nil,
		Chars:     nil,
		Validator: nil,
		Retries:   100,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return options.GenerateRunes()
}

func defaultValidator(options Options) func([]rune) error {
	return func(runes []rune) error {
		if options.Chars != nil {
			return nil
		}

		requiresLower := options.Lower && options.Chars == nil
		requiresUpper := options.Upper && options.Chars == nil
		requiresDigit := options.Digits && options.Chars == nil
		requiresSymbol := options.Symbols != nil && len(*options.Symbols) > 0 && options.Chars == nil

		hasLower := false
		hasUpper := false
		hasDigit := false
		hasSymbol := false

		for _, r := range runes {
			if unicode.IsLower(r) {
				hasLower = true
				continue
			}

			if unicode.IsUpper(r) {
				hasUpper = true
				continue
			}

			if unicode.IsDigit(r) {
				hasDigit = true
				continue
			}

			hasSymbol = true
		}

		if requiresLower && !hasLower {
			return errors.New("password must contain at least one lowercase letter")
		}

		if requiresUpper && !hasUpper {
			return errors.New("password must contain at least one uppercase letter")
		}

		if requiresDigit && !hasDigit {
			return errors.New("password must contain at least one digit")
		}

		if requiresSymbol && !hasSymbol {
			return errors.New("password must contain at least one symbol")
		}

		return nil
	}
}
