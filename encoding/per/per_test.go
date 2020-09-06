package per

import (
	//	"fmt"
	"testing"
)

func TestMergeBitField(t *testing.T) {

	pattern := []struct {
		in1 BitField
		in2 BitField
		ebf BitField
	}{
		{BitField{[]byte{0x80, 0x80}, 9},
			BitField{[]byte{0x08, 0x80}, 9},
			BitField{[]byte{0x80, 0x84, 0x40}, 18}},
	}

	for _, p := range pattern {

		bf := MergeBitField(p.in1, p.in2)

		ebf := p.ebf
		if compBitField(bf, ebf) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
		}
	}
}

func TestShiftLeft(t *testing.T) {

	pattern := []struct {
		in       BitField
		shiftlen int
		ebf      BitField
	}{
		{BitField{[]byte{0x00, 0x11, 0x22}, 16}, 4,
			BitField{[]byte{0x01, 0x12, 0x20}, 16}},

		{BitField{[]byte{0x00, 0x11, 0x22}, 16}, 8,
			BitField{[]byte{0x11, 0x22}, 16}},
	}

	for _, p := range pattern {

		bf := ShiftLeft(p.in, p.shiftlen)

		ebf := p.ebf
		if compBitField(bf, ebf) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
		}
	}
}

func TestShiftRight(t *testing.T) {

	pattern := []struct {
		in       BitField
		shiftlen int
		ebf      BitField
	}{
		{BitField{[]byte{0x00, 0x11, 0x22}, 16}, 4,
			BitField{[]byte{0x00, 0x01, 0x12}, 16}},
	}

	for _, p := range pattern {

		bf := ShiftRight(p.in, p.shiftlen)

		ebf := p.ebf
		if compBitField(bf, ebf) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
		}
	}
}

func TestEncConstrainedWholeNumber(t *testing.T) {

	pattern := []struct {
		in   int64
		min  int64
		max  int64
		ebf  BitField
		eerr bool
	}{
		{256, 0, 255,
			BitField{[]byte{}, 0}, true},
		{1, 0, 0,
			BitField{[]byte{}, 0}, true},
		{1, 1, 1,
			BitField{[]byte{}, 0}, false},
		{1, 0, 7,
			BitField{[]byte{0x01}, 3}, false},
		{128, 0, 255,
			BitField{[]byte{128}, 0}, false},
		{256, 0, 65535,
			BitField{[]byte{1, 0}, 0}, false},
		{256, 0, 65536,
			BitField{[]byte{1, 0}, 0}, false},
		{255, 0, 4294967295,
			BitField{[]byte{0, 255}, 0}, false},
		{0x0fffffff, 0, 4294967295,
			BitField{[]byte{0x0f, 0xff, 0xff, 0xff}, 0}, false},
	}

	for _, p := range pattern {

		bf, err := EncConstrainedWholeNumber(p.in, p.min, p.max)

		ebf := p.ebf
		eerr := p.eerr
		if compBitFieldAndErr(ebf, eerr, bf, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func TestEncLengthDeterminant(t *testing.T) {

	pattern := []struct {
		in   int
		min  int
		max  int
		ebf  BitField
		eerr bool
	}{
		{1, 0, 255,
			BitField{[]byte{1}, 0}, false},
		{1, 0, 0,
			BitField{[]byte{1}, 0}, false},
		{16383, 0, 0,
			BitField{[]byte{0xbf, 0xff}, 0}, false},
		{16384, 0, 0,
			BitField{[]byte{}, 0}, true},
	}

	for _, p := range pattern {

		bf, err := EncLengthDeterminant(p.in, p.min, p.max)

		ebf := p.ebf
		eerr := p.eerr
		if compBitFieldAndErr(ebf, eerr, bf, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect error: %v, got %v", eerr, err)
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
		in   int64
		min  int64
		max  int64
		ext  bool
		ebf  BitField
		ev   []byte
		eerr bool
	}{
		{3, 0, 2, true,
			BitField{[]byte{}, 0}, []byte{}, true},
		{2, 2, 2, false,
			BitField{[]byte{}, 0}, []byte{}, false},
		{2, 2, 2, true,
			BitField{[]byte{0x00}, 1}, []byte{}, false},
		{128, 0, 255, false,
			BitField{[]byte{}, 0}, []byte{128}, false},
		{1, 0, 7, true,
			BitField{[]byte{0x10}, 4}, []byte{}, false},
		{128, 0, 255, true,
			BitField{[]byte{0}, 1}, []byte{128}, false},
		{256, 0, 65535, false,
			BitField{[]byte{}, 0}, []byte{1, 0}, false},
		{1, 0, 4294967295, false,
			BitField{[]byte{}, 0}, []byte{0, 1}, false},
	}

	for _, p := range pattern {

		bf, v, err := EncInteger(p.in, p.min, p.max, p.ext)

		ebf := p.ebf
		ev := p.ev
		eerr := p.eerr
		if compBitFieldAndValueAndErr(ebf, ev, eerr, bf, v, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect value: %v, got %v", ev, v)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func TestEncEnumerated(t *testing.T) {

	pattern := []struct {
		in   uint
		min  uint
		max  uint
		ext  bool
		ebf  BitField
		ev   []byte
		eerr bool
	}{
		{3, 0, 2, false,
			BitField{[]byte{}, 0}, []byte{}, true},
		{2, 0, 2, false,
			BitField{[]byte{0x80}, 2}, []byte{}, false},
		{1, 0, 2, true,
			BitField{[]byte{0x20}, 3}, []byte{}, false},
	}

	for _, p := range pattern {

		bf, v, err := EncEnumerated(p.in, p.min, p.max, p.ext)

		ebf := p.ebf
		ev := p.ev
		eerr := p.eerr
		if compBitFieldAndValueAndErr(ebf, ev, eerr, bf, v, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect value: %v, got %v", ev, v)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func TestEncSequence(t *testing.T) {

	pattern := []struct {
		ext  bool
		opt  int
		flag uint
		ebf  BitField
		eerr bool
	}{
		{false, 8, 0x00, BitField{[]byte{}, 0}, true},
		{true, 1, 0x00, BitField{[]byte{0x00}, 2}, false},
	}

	for _, p := range pattern {

		bf, err := EncSequence(p.ext, p.opt, p.flag)

		ebf := p.ebf
		eerr := p.eerr
		if compBitFieldAndErr(ebf, eerr, bf, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect error: %v, got %v", eerr, err)
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
		ebf   BitField
		ev    []byte
		eerr  bool
	}{
		{[]byte{}, 0, 16, 63, false,
			BitField{[]byte{}, 0}, []byte{}, true},
		{[]byte{}, 100, 0, 63, false,
			BitField{[]byte{}, 0}, []byte{}, true},
		{[]byte{0, 0, 0}, 25, 22, 32, false,
			BitField{[]byte{}, 0}, []byte{}, true},
		{[]byte{0, 0}, 16, 16, 16, false,
			BitField{[]byte{}, 0}, []byte{0, 0}, false},
		{[]byte{0, 0x10}, 16, 0, 255, false,
			BitField{[]byte{}, 0}, []byte{16, 0, 0x10}, false},
		{[]byte{0, 0, 0x02}, 23, 22, 32, false,
			BitField{[]byte{0x10}, 4}, []byte{0, 0, 0x04}, false},
		{[]byte{0, 0, 0, 0x03}, 25, 22, 32, false,
			BitField{[]byte{0x30}, 4}, []byte{0, 0, 0x01, 0x80}, false},
		{[]byte{0, 0, 0, 0x03}, 25, 22, 32, true,
			BitField{[]byte{0x18}, 5}, []byte{0, 0, 0x01, 0x80}, false},
		{[]byte{0, 0, 0, 0x03}, 25, 0, 128, true,
			BitField{[]byte{0x0c, 0x80}, 9}, []byte{0, 0, 0x01, 0x80}, false},
	}

	for _, p := range pattern {

		bf, v, err := EncBitString(p.in, p.inlen, p.min, p.max, p.ext)

		ebf := p.ebf
		ev := p.ev
		eerr := p.eerr
		if compBitFieldAndValueAndErr(ebf, ev, eerr, bf, v, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect value: %v, got %v", ev, v)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func TestOctetString(t *testing.T) {

	pattern := []struct {
		in   []byte
		min  int
		max  int
		ext  bool
		ebf  BitField
		ev   []byte
		eerr bool
	}{
		{[]byte{0}, 16, 64, false,
			BitField{[]byte{}, 0}, []byte{}, true},
		{make([]byte, 8, 8), 8, 8, false,
			BitField{[]byte{}, 0}, make([]byte, 8, 8), false},
		{[]byte{0x01, 0x80}, 2, 2, true,
			BitField{[]byte{0x00, 0xc0, 0x00}, 17}, []byte{}, false},
		{make([]byte, 8, 8), 8, 8, true,
			BitField{[]byte{0x00}, 1}, make([]byte, 8, 8), false},
		{make([]byte, 3, 3), 0, 0, false,
			BitField{[]byte{}, 0}, []byte{3, 0, 0, 0}, false},
		{make([]byte, 3, 3), 0, 7, true,
			BitField{[]byte{0x30}, 4}, make([]byte, 3, 3), false},
	}

	for _, p := range pattern {

		bf, v, err := EncOctetString(p.in, p.min, p.max, p.ext)

		ebf := p.ebf
		ev := p.ev
		eerr := p.eerr
		if compBitFieldAndValueAndErr(ebf, ev, eerr, bf, v, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect value: %v, got %v", ev, v)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func TestChoice(t *testing.T) {

	pattern := []struct {
		input int
		min   int
		max   int
		mark  bool
		ebf   BitField
		ev    []byte
		eerr  bool
	}{
		{0, 0, 0, false,
			BitField{[]byte{}, 0}, []byte{}, false},
		{1, 0, 2, false,
			BitField{[]byte{0x40}, 2}, []byte{}, false},
	}

	for _, p := range pattern {

		bf, v, err := EncChoice(p.input, p.min, p.max, p.mark)

		ebf := p.ebf
		ev := p.ev
		eerr := p.eerr
		if compBitFieldAndValueAndErr(ebf, ev, eerr, bf, v, err) == false {
			t.Errorf("pattern = %v", p)
			t.Errorf("expect bitfield: %v, got %v", ebf, bf)
			t.Errorf("expect value: %v, got %v", ev, v)
			t.Errorf("expect error: %v, got %v", eerr, err)
		}
	}
}

func compSlice(ev, v []byte) bool {
	if len(ev) != len(v) {
		return false
	}
	for i := 0; i < len(ev); i++ {
		if ev[i] != v[i] {
			return false
		}
	}
	return true
}

func compBitField(ebf BitField, bf BitField) bool {

	if compSlice(ebf.Value, bf.Value) == false {
		return false
	}
	if ebf.Len != bf.Len {
		return false
	}
	return true
}

func compBitFieldAndErr(ebf BitField, eerr bool, bf BitField, err error) bool {

	if compBitField(ebf, bf) == false {
		return false
	}
	if eerr == true && err == nil {
		return false
	}
	if eerr == false && err != nil {
		return false
	}
	return true
}

func compBitFieldAndValueAndErr(ebf BitField, ev []byte, eerr bool,
	bf BitField, v []byte, err error) bool {

	if compBitFieldAndErr(ebf, eerr, bf, err) == false {
		return false
	}
	if compSlice(ev, v) == false {
		return false
	}
	return true
}
