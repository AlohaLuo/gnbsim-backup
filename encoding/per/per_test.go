package per

import (
	"fmt"
	"testing"
)

func compareSlice(actual, expect []byte) bool {
	if len(actual) != len(expect) {
		return false
	}
	for i := 0; i < len(actual); i++ {
		if actual[i] != expect[i] {
			return false
		}
	}
	fmt.Printf("")
	return true
}

func TestMergeBitField(t *testing.T) {

	pattern := []struct {
		in1    []byte
		inlen1 int
		in2    []byte
		inlen2 int
		ev     []byte
		elen   int
	}{
		{nil, 0, []byte{0x00, 0x11}, 8, []byte{0x11}, 8},
		{[]byte{0x80, 0x80}, 9, []byte{0x08, 0x80}, 9, []byte{0x80, 0x84, 0x40}, 18},
	}

	for _, p := range pattern {

		out, outlen := MergeBitField(p.in1, p.inlen1, p.in2, p.inlen2)

		if compareSlice(out, p.ev) == false || outlen != p.elen {
			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.ev, out)
			t.Errorf("expect length %d, actual %d", p.elen, outlen)
		}
	}
}

func TestShiftLeft(t *testing.T) {

	pattern := []struct {
		in    []byte
		inlen int
		ev    []byte
	}{
		{[]byte{0x00, 0x11, 0x22}, 4, []byte{0x01, 0x12, 0x20}},
	}

	for _, p := range pattern {

		out := ShiftLeft(p.in, p.inlen)

		if compareSlice(out, p.ev) == false {
			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.ev, out)
		}
	}
}

func TestShiftRight(t *testing.T) {

	pattern := []struct {
		in    []byte
		inlen int
		ev    []byte
	}{
		{[]byte{0x00, 0x11, 0x22}, 4, []byte{0x00, 0x01, 0x12}},
	}

	for _, p := range pattern {

		out := ShiftRight(p.in, p.inlen)

		if compareSlice(out, p.ev) == false {
			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.ev, out)
		}
	}
}

func TestEncConstrainedWholeNumber(t *testing.T) {

	pattern := []struct {
		in    int64
		min   int64
		max   int64
		ev    []byte
		evlen int
		eerr  bool
	}{
		{256, 0, 255, []byte{}, 0, true},
		{1, 0, 0, []byte{}, 0, true},
		{1, 1, 1, []byte{}, 0, false},
		{1, 0, 7, []byte{0x01}, 4, false},
		{128, 0, 255, []byte{128}, 8, false},
		{256, 0, 65535, []byte{1, 0}, 16, false},
		{256, 0, 65536, []byte{1, 0}, 16, false},
		{255, 0, 4294967295, []byte{0, 255}, 16, false},
		{0x0fffffff, 0, 4294967295, []byte{0x0f, 0xff, 0xff, 0xff}, 32, false},
	}

	for _, p := range pattern {

		out, outlen, err := EncConstrainedWholeNumber(p.in, p.min, p.max)

		if compareSlice(out, p.ev) == false || outlen != p.evlen ||
			(p.eerr == true && err == nil) || (p.eerr == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.ev, out)
			t.Errorf("expect length %d, got %d", p.evlen, outlen)
			t.Errorf("expect error: %v, got %v", p.eerr, err)
		}
	}
}

func TestEncLengthDeterminant(t *testing.T) {

	pattern := []struct {
		in     int
		max    int
		v      []byte
		bitlen int
		err    bool
	}{
		{1, 255, []byte{1}, 8, false},
		{1, 0, []byte{1}, 8, false},
		{16383, 0, []byte{0xbf, 0xff}, 16, false},
		{16384, 0, []byte{}, 0, true},
	}

	for _, p := range pattern {

		v, bitlen, err := EncLengthDeterminant(p.in, p.max)

		if compareSlice(v, p.v) == false || bitlen != p.bitlen ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect length %d, got %d", p.bitlen, bitlen)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestDecLengthDeterminant(t *testing.T) {

	pattern := []struct {
		in     []byte
		max    int
		length int
		err    bool
	}{
		{[]byte{}, 1, 0, true},
		{[]byte{0x7f}, 0, 0x7f, false},
		{[]byte{0x80, 0xff}, 0, 0xff, false},
	}

	for _, p := range pattern {

		length, err := DecLengthDeterminant(&p.in, p.max)

		if length != p.length || len(p.in) != 0 ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("expect length %d, got %d", p.length, length)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestEncInteger(t *testing.T) {

	pattern := []struct {
		in     int64
		min    int64
		max    int64
		ext    bool
		v      []byte
		bitlen int
		err    bool
	}{
		{3, 0, 2, true, []byte{}, 0, true},
		{2, 2, 2, false, []byte{}, 0, false},
		{2, 2, 2, true, []byte{0x00}, 1, false},
		{128, 0, 255, false, []byte{128}, 8, false},
		{1, 0, 7, true, []byte{0x08}, 5, false},
		{128, 0, 255, true, []byte{0x00, 128}, 16, false},
		{256, 0, 65535, false, []byte{1, 0}, 16, false},
		{1, 0, 4294967295, false, []byte{0, 1}, 16, false},
	}

	for _, p := range pattern {

		v, bitlen, err := EncInteger(p.in, p.min, p.max, p.ext)

		if compareSlice(v, p.v) == false || bitlen != p.bitlen ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect length %d, got %d", p.bitlen, bitlen)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestEncEnumerated(t *testing.T) {

	pattern := []struct {
		in     uint
		min    uint
		max    uint
		ext    bool
		v      []byte
		bitlen int
		err    bool
	}{
		{3, 0, 2, false, []byte{}, 0, true},
		{2, 0, 2, false, []byte{0x80}, 2, false},
		{1, 0, 2, true, []byte{0x20}, 3, false},
	}

	for _, p := range pattern {

		v, bitlen, err := EncEnumerated(p.in, p.min, p.max, p.ext)

		if compareSlice(v, p.v) == false || bitlen != p.bitlen ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect length %d, got %d", p.bitlen, bitlen)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestEncSequence(t *testing.T) {

	pattern := []struct {
		ext    bool
		opt    int
		flag   uint
		v      []byte
		bitlen int
		err    bool
	}{
		{false, 8, 0x00, []byte{}, 0, true},
		{true, 1, 0x00, []byte{0x00}, 2, false},
	}

	for _, p := range pattern {

		v, bitlen, err := EncSequence(p.ext, p.opt, p.flag)

		if compareSlice(v, p.v) == false || bitlen != p.bitlen ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect length %d, got %d", p.bitlen, bitlen)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestBitString(t *testing.T) {

	pattern := []struct {
		in    []byte
		inlen int
		min   int
		max   int
		ext   bool
		pv    []byte
		plen  int
		v     []byte
		err   bool
	}{
		{[]byte{}, 0, 16, 63, false, []byte{}, 0, []byte{}, true},
		{[]byte{}, 100, 0, 63, false, []byte{}, 0, []byte{}, true},
		{[]byte{0, 0, 0}, 25, 22, 32, false, []byte{}, 0, []byte{}, true},
		{[]byte{0, 0}, 16, 16, 16, false, []byte{}, 0, []byte{0, 0}, false},
		{[]byte{0, 0x10}, 16, 0, 255, false, []byte{0x10}, 8, []byte{0, 0x10}, false},
		{[]byte{0, 0, 0x02}, 23, 22, 32, false, []byte{0x10}, 4, []byte{0, 0, 0x04}, false},
		{[]byte{0, 0, 0, 0x03}, 25, 22, 32, false, []byte{0x30}, 4, []byte{0, 0, 0x01, 0x80}, false},
	}

	for _, p := range pattern {

		pv, plen, v, err := EncBitString(p.in, p.inlen, p.min, p.max, p.ext)

		if compareSlice(pv, p.pv) == false || plen != p.plen ||
			compareSlice(v, p.v) == false ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.pv, pv)
			t.Errorf("expect length %d, got %d", p.plen, plen)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestOctetString(t *testing.T) {

	pattern := []struct {
		in   []byte
		min  int
		max  int
		ext  bool
		pv   []byte
		plen int
		v    []byte
		err  bool
	}{
		{[]byte{0}, 16, 64, false, []byte{}, 0, []byte{}, true},
		{make([]byte, 8, 8), 8, 8, false, []byte{}, 0, make([]byte, 8, 8), false},
		{[]byte{0x01, 0x80}, 2, 2, true, []byte{0x00, 0xc0, 0x00}, 17, []byte{}, false},
		{make([]byte, 8, 8), 8, 8, true, []byte{0x00}, 1, make([]byte, 8, 8), false},
		{make([]byte, 3, 3), 0, 0, false, []byte{3}, 8, make([]byte, 3, 3), false},
		{make([]byte, 3, 3), 0, 7, true, []byte{0x18}, 5, make([]byte, 3, 3), false},
	}

	for _, p := range pattern {

		pv, plen, v, err := EncOctetString(p.in, p.min, p.max, p.ext)

		if compareSlice(pv, p.pv) == false || plen != p.plen ||
			compareSlice(v, p.v) == false ||
			(p.err == true && err == nil) || (p.err == false && err != nil) {

			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.pv, pv)
			t.Errorf("expect length %d, got %d", p.plen, plen)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.v, v)
			t.Errorf("expect error: %v, got %v", p.err, err)
		}
	}
}

func TestChoice(t *testing.T) {

	pattern := []struct {
		input int
		min   int
		max   int
		mark  bool
		epv   []byte
		eplen int
		eerr  error
	}{
		{0, 0, 0, false, []byte{}, 0, nil},
		{1, 0, 2, false, []byte{0x40}, 2, nil},
	}

	for _, p := range pattern {

		pv, plen, err := EncChoice(p.input, p.min, p.max, p.mark)

		if compareSlice(pv, p.epv) == false ||
			plen != p.eplen || err != p.eerr {
			t.Errorf("pattern = %v\n", p)
			t.Errorf("expect value 0x%02x, got 0x%02x", p.epv, pv)
			t.Errorf("expect length %d, got %d", p.eplen, plen)
			t.Errorf("expect error: %v, got %v", p.eerr, err)
		}
	}
}
