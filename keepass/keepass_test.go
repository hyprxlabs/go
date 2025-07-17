package keepass_test

import (
	"testing"

	"github.com/hyprxlabs/go/keepass"
	"github.com/stretchr/testify/assert"
)

func TestKeepass(t *testing.T) {
	assert.Equal(t, keepass.TEST, "TEST")
}
