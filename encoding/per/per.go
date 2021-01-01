// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package per is implementation for Basic Pckage Encoding Rule (PER) in
// ALIGNED variant.
// document version: T-REC-X.691-201508
package per

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

type BitField struct {
	Value []byte
	Len   int
}

// MergeBitField is utility function for merging bit-field.
// e.g. preamble or short integer value is not octet alined value, so
// those fields need to be packed in same octets.
func MergeBitField(in1 BitField, in2 BitField) (out BitField) {
	/*
	   ex.
	   in1(len=4)  b1010 xxxx
	   in2(len=14) b1110 1011 1100 00xx
	   out(len=18) b1010 1110 1011 1100 00xx
	*/
	out.Value = make([]byte, len(in1.Value), len(in1.Value))
	out.Value = append(out.Value, in2.Value...)
	out = ShiftLeft(out, len(in1.Value)*8-in1.Len)
	for n := 0; n < len(in1.Value); n++ {
		out.Value[n] |= in1.Value[n]
	}
	out.Len = in1.Len + in2.Len

	octetlen := (out.Len-1)/8 + 1
	out.Value = out.Value[:octetlen]
	return
}

// ShiftLeft is utility function to left shift the octet values.
func ShiftLeft(in BitField, shiftlen int) (out BitField) {
	out = in
	for n := 0; n < shiftlen; n++ {
		overflow := false
		for m := len(out.Value) - 1; m >= 0; m-- {
			do := false
			if overflow == true {
				do = true
				overflow = false
			}
			if out.Value[m]&0x80 == 0x80 {
				overflow = true
			}
			out.Value[m] <<= 1
			if do == true {
				out.Value[m] |= 0x01
			}
		}
	}
	for n := 0; n < (shiftlen / 8); n++ {
		out.Value = out.Value[:len(out.Value)-1]
	}
	return
}

// ShiftRight is utility function to right shift the octet values.
func ShiftRight(in BitField, shiftlen int) (out BitField) {
	out = in
	for n := 0; n < shiftlen; n++ {
		underflow := false
		for m := 0; m < len(out.Value); m++ {
			do := false
			if underflow == true {
				do = true
				underflow = false
			}
			if out.Value[m]&0x1 == 0x1 {
				underflow = true
			}
			out.Value[m] >>= 1
			if do == true {
				out.Value[m] |= 0x80
			}
		}
	}
	return
}

// ShiftLeftMost is utility function to shift the octet values to the leftmost.
func ShiftLeftMost(in BitField) (out BitField) {
	out = in
	out = ShiftLeft(out, len(in.Value)*8-in.Len)
	return
}

// EncConstrainedWholeNumber is the implementation for
// 11.5 Encoding of constrained whole number.
func EncConstrainedWholeNumber(input, min, max int64) (bf BitField, err error) {

	if input < min || input > max {
		err = fmt.Errorf("EncConstrainedWholeNumber: "+
			"input value=%d is out of range. "+
			"(should be %d <= %d)", input, min, max)
		return
	}

	inputRange := max - min + 1
	inputEnc := input - min

	bf.Len = 0 // default: octet aligned
	switch {
	case inputRange == 1: // empty bit-field
		return
	case inputRange < 256: // the bit-field case
		bf.Value = []byte{byte(inputEnc)}
		bf.Len = bits.Len(uint(inputRange - 1))
		return
	case inputRange == 256: // the one-octet case
		bf.Value = []byte{byte(inputEnc)}
		return
	case inputRange <= 65536: // the two-octet case
		bf.Value = make([]byte, 2)
		binary.BigEndian.PutUint16(bf.Value, uint16(inputEnc))
		return
	}
	// case inputRange > 65536: // the indefinite length case
	bf.Value, _ = EncNonNegativeBinaryInteger(uint(input))

	return
}

func encConstrainedWholeNumberWithExtmark(input, min, max int64, extmark bool) (
	bf BitField, v []byte, err error) {

	bf, err = EncConstrainedWholeNumber(input, min, max)
	if err != nil {
		return
	}

	// octet aligned
	if bf.Len == 0 {
		v = bf.Value
		bf.Value = []byte{}
	}

	if extmark == true {
		if bf.Len%8 == 0 {
			bf.Value = append([]byte{0x00}, bf.Value...)
		}
		bf.Len++
	}
	bf = ShiftLeftMost(bf)

	return
}

// EncLengthDeterminant is the implementation for
// 11.9 General rules for encoding a length determinant
func EncLengthDeterminant(input, min, max int) (bf BitField, err error) {

	if max != 0 && max < 65536 {
		bf, err = EncConstrainedWholeNumber(
			int64(input), int64(min), int64(max))
		return
	}

	bf.Len = 0 // default: octet aligned
	switch {
	case input < 128:
		bf.Value = []byte{byte(input)}
		return
	case input < 16384:
		bf.Value = []byte{byte((input >> 8) & 0xff)}
		bf.Value = append(bf.Value, byte(input&0xff))
		bf.Value[0] |= 0x80
		return
	}
	err = fmt.Errorf("EncLengthDeterminant: "+
		"not implemented yet for input=%d, max=%d", input, max)
	return
}

func DecLengthDeterminant(pdu *[]byte, max int) (length int, err error) {

	if max != 0 {
		err = fmt.Errorf("DecLengthDeterminant: "+
			"not implemented yet for max=%d", max)
		return
	}

	oct1 := (*pdu)[0]
	if (oct1 & 0x80) == 0 {
		length = int((*pdu)[0])
		*pdu = (*pdu)[1:]
		return
	}

	(*pdu)[0] &= 0x7f /// lay the most significant bit down
	length = int(binary.BigEndian.Uint16(*pdu))
	*pdu = (*pdu)[2:]
	return
}

func encLengthWithExtmark(inlen, min, max int, extmark bool) (
	bf BitField, v []byte, err error) {

	bf, err = EncLengthDeterminant(inlen, min, max)
	if bf.Len == 0 {
		v = bf.Value
		bf.Value = []byte{}
		bf.Len = 0
	}

	if extmark == true {
		if bf.Len%8 == 0 {
			bf.Value = append([]byte{0x00}, bf.Value...)
		}
		bf.Len++
	}

	bf = ShiftLeftMost(bf)

	return
}

// EncNonNegativeBinaryInteger is the implementation for
// 11.3 Encoding as a non-negative-binary-integer
func EncNonNegativeBinaryInteger(input uint) (v []byte, err error) {

	bytelen := bits.Len(input)/8 + 1
	if bytelen == 1 {
		v = []byte{0x00, byte(input)}
		return
	}

	for i := 0; i < bytelen; i++ {
		v = append([]byte{byte(input)}, v...)
		input >>= 8
	}
	return
}

// EncInteger is the implementation for
// 13. Encoding the integer type
// but it is only for the case of single value and constrained whole nuber.
func EncInteger(input, min, max int64, extmark bool) (
	bf BitField, v []byte, err error) {

	if min == max { // 12.2.1 single value
		if extmark == true {
			bf.Value = make([]byte, 1, 1)
			bf.Len = 1
		}
		return
	}

	// 13.2.2 constrained whole number
	bf, v, err = encConstrainedWholeNumberWithExtmark(input, min, max, extmark)
	return
}

// EncEnumerated is the implementation for
// 14. Encoding the enumerated type
func EncEnumerated(input, min, max uint, extmark bool) (
	bf BitField, v []byte, err error) {
	bf, v, err = encConstrainedWholeNumberWithExtmark(int64(input),
		int64(min), int64(max), extmark)
	return
}

// EncBitString returns multi-byte BIT STRING
// 16. Encoding the bitstering type
func EncBitString(input []byte, inputlen, min, max int, extmark bool) (
	bf BitField, v []byte, err error) {

	if inputlen < min || inputlen > max {
		err = fmt.Errorf("EncBitString: "+
			"input len(value)=%d is out of range. "+
			"(should be %d <= %d)", inputlen, min, max)
		return
	}

	if len(input)*8 < inputlen {
		err = fmt.Errorf("EncBitString: "+
			"input len(value)=%d is too short.", len(input))
		return
	}

	var in BitField
	in.Value = input
	in.Len = inputlen
	out := ShiftLeftMost(in)
	v = out.Value

	if min == max {
		// fixed length case. not implemented yet.
		switch {
		case min < 17:
		case min > 16 && min < 65537:
		}
		return
	}

	bf, v2, err := encLengthWithExtmark(inputlen, min, max, extmark)
	v = append(v2, v...)

	return
}

// EncOctetString returns multi-byte OCTET STRING
// 17. Encoding the octetstring type
//
// - the length of returned value can be calculated by len().
// - returned value can be len(value) == 0 if the specified octet string has
//   fixed length and the lenght is less than 3. And then the octet string is
//   encoded as bit field.
func EncOctetString(input []byte, min, max int, extmark bool) (
	bf BitField, v []byte, err error) {

	inputlen := len(input)
	if max != 0 && (inputlen < min || inputlen > max) {
		err = fmt.Errorf("EncOctetString: "+
			"input len(value)=%d is out of range. "+
			"(should be %d <= %d)", inputlen, min, max)
		return
	}

	// fixed length case
	if min == max && min != 0 {
		switch {
		case min < 3: // not octet aligned
			bf.Value = input
			bf.Len = inputlen * 8
			if extmark == true {
				bf.Value = append([]byte{0x00}, bf.Value...)
				bf.Len++
			}
			bf = ShiftLeftMost(bf)
		case min < 65537:
			v = input
			if extmark == true {
				bf.Value = []byte{0x00}
				bf.Len = 1
				bf = ShiftLeftMost(bf)
			}
		}
		return
	}

	v = input

	bf, v2, err := encLengthWithExtmark(inputlen, min, max, extmark)
	v = append(v2, v...)

	return
}

// EncSequence return Sequence Preamble but it just returns 0x00 for now.
// 19. Encoding the sequence type
func EncSequence(extmark bool, optnum int, optflag uint) (
	b BitField, err error) {
	if optnum > 7 {
		err = fmt.Errorf("EncSequence: "+
			"optnum=%d is not implemented yet. (should be < 8)",
			optnum)
		return
	}
	if extmark == true {
		b.Len++
	}

	b.Len += optnum
	b.Value = make([]byte, 1, 1)
	b.Value[0] |= byte(optflag)
	b = ShiftLeftMost(b)
	return
}

// EncSequenceOf return Sequence-Of Preamble.
// 20. Encoding the sequence-of type
var EncSequenceOf = EncEnumerated

// EncChoice is the implementation for
// 23. Encoding the choice type
func EncChoice(input, min, max int, extmark bool) (
	bf BitField, v []byte, err error) {
	bf, v, err = EncInteger(int64(input), int64(min), int64(max), extmark)
	return
}
