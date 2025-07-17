package cmdargs_test

import (
	"reflect"
	"testing"

	"github.com/hyprxlabs/go/cmdargs"
	"github.com/stretchr/testify/assert"
)

func TestNewAndToArray(t *testing.T) {
	args := []string{"a", "b", "c"}
	a := cmdargs.New(args)
	arr := a.ToArray()
	if !reflect.DeepEqual(arr[len(arr)-len(args):], args) {
		t.Errorf("ToArray() = %v, want %v", arr, args)
	}
}

func TestLenAndGet(t *testing.T) {
	a := cmdargs.New([]string{"x", "y"})
	if a.Len() != 2 {
		t.Errorf("Len() = %d, want 2", a.Len())
	}
	if a.Get(0) != "x" || a.Get(1) != "y" {
		t.Errorf("Get() failed: got %q, %q", a.Get(0), a.Get(1))
	}
	if a.Get(-1) != "" || a.Get(2) != "" {
		t.Errorf("Get() out of bounds should return empty string")
	}
}

func TestIndexAndIndexFold(t *testing.T) {
	a := cmdargs.New([]string{"foo", "Bar", "baz"})
	if a.Index("Bar") != 1 {
		t.Errorf("Index() = %d, want 1", a.Index("Bar"))
	}
	if a.Index("notfound") != -1 {
		t.Errorf("Index() = %d, want -1", a.Index("notfound"))
	}
	if a.IndexFold("bAz") != 2 {
		t.Errorf("IndexFold() = %d, want 2", a.IndexFold("bAz"))
	}
}

func TestIndexAnyAndIndexAnyFold(t *testing.T) {
	a := cmdargs.New([]string{"foo", "Bar", "baz"})
	if a.IndexAny([]string{"baz", "Bar"}) != 1 {
		t.Errorf("IndexAny() = %d, want 1", a.IndexAny([]string{"baz", "Bar"}))
	}
	if a.IndexAnyFold([]string{"BAZ", "BAR"}) != 1 {
		t.Errorf("IndexAnyFold() = %d, want 1", a.IndexAnyFold([]string{"BAZ", "BAR"}))
	}
}

func TestContainsAndContainsFold(t *testing.T) {
	a := cmdargs.New([]string{"foo", "Bar"})
	if !a.Contains("foo") {
		t.Errorf("Contains() should be true")
	}
	if a.Contains("baz") {
		t.Errorf("Contains() should be false")
	}
	if !a.ContainsFold("BAR") {
		t.Errorf("ContainsFold() should be true")
	}
}

func TestContainsAnyAndContainsAnyFold(t *testing.T) {
	a := cmdargs.New([]string{"foo", "Bar"})
	if !a.ContainsAny([]string{"baz", "Bar"}) {
		t.Errorf("ContainsAny() should be true")
	}
	if !a.ContainsAnyFold([]string{"BAZ", "BAR"}) {
		t.Errorf("ContainsAnyFold() should be true")
	}
}

func TestSet(t *testing.T) {
	a := cmdargs.New([]string{"a", "b"})
	a.Set(1, "c")
	if a.Get(1) != "c" {
		t.Errorf("Set() failed, got %q", a.Get(1))
	}
	a.Set(-1, "x")
	a.Set(2, "y") // out of bounds, should not panic
}

func TestPushAppendPrepend(t *testing.T) {
	a := cmdargs.New([]string{"a"})
	a.Push("b", "c")

	copy := a.ToArray()
	assert.Equal(t, copy, []string{"a", "b", "c"})
	if !reflect.DeepEqual(copy, []string{"a", "b", "c"}) {
		t.Errorf("Push() failed: %v", copy)
	}
	a.Append("d")
	if !reflect.DeepEqual(a.ToArray(), []string{"a", "b", "c", "d"}) {
		t.Errorf("Append() failed: %v", a.ToArray())
	}
	a.Prepend("z")
	if !reflect.DeepEqual(a.ToArray(), []string{"z", "a", "b", "c", "d"}) {
		t.Errorf("Prepend() failed: %v", a.ToArray())
	}
}

func TestShiftAndPop(t *testing.T) {
	a := cmdargs.New([]string{"x", "y"})
	val := a.Shift()
	if val != "x" || !reflect.DeepEqual(a.ToArray(), []string{"y"}) {
		t.Errorf("Shift() failed: val=%q, args=%v", val, a.ToArray())
	}
	val = a.Pop()
	if val != "y" || len(a.ToArray()) != 0 {
		t.Errorf("Pop() failed: val=%q, args=%v", val, a.ToArray())
	}
	val = a.Pop()
	if val != "" {
		t.Errorf("Pop() on empty should return empty string")
	}
}

func TestRemoveAndRemoveAt(t *testing.T) {
	a := cmdargs.New([]string{"a", "b", "c"})
	ok := a.Remove("b")
	if !ok || !reflect.DeepEqual(a.ToArray(), []string{"a", "c"}) {
		t.Errorf("Remove() failed: %v", a.ToArray())
	}
	ok = a.RemoveAt(1)
	if !ok || !reflect.DeepEqual(a.ToArray(), []string{"a"}) {
		t.Errorf("RemoveAt() failed: %v", a.ToArray())
	}
	ok = a.RemoveAt(5)
	if ok {
		t.Errorf("RemoveAt() out of bounds should return false")
	}
}

func TestString(t *testing.T) {
	a := cmdargs.New([]string{"foo", "bar baz", `"quoted"`})
	s := a.String()
	if s != `foo "bar baz" quoted` {
		t.Errorf("String() = %q", s)
	}
}

func TestSplit(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a b c", []string{"a", "b", "c"}},
		{`"a b" c`, []string{"a b", "c"}},
		{`'x y' z`, []string{"x y", "z"}},
		{`foo "bar baz" 'qux'`, []string{"foo", "bar baz", "qux"}},
		{`foo "bar \"baz\""`, []string{"foo", `bar \"baz\"`}},

		// new line should terminate all args unless escaped
		// or quoted
		{"a b\\\nc", []string{"a", "b\\"}},

		// simulates bash style continuation
		// command a b \
		// c
		{"a b \\\nc", []string{"a", "b", "c"}},
		{"a b \\\r\nc", []string{"a", "b", "c"}},
		{"a b\nc", []string{"a", "b"}},
		{"a b\r\nc", []string{"a", "b"}},
	}
	for _, tt := range tests {
		got := cmdargs.Split(tt.input).ToArray()
		if !assert.Equal(t, tt.want, got) {
			t.Errorf("Split(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
