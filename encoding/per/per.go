// Copyright 2019-2020 hhorai. All rights reserved.
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

// MergeBitField is utility function for merging bit-field.
// e.g. preamble or short integer value is not octet alined value, so
// those fields need to be packed in same octets.
func MergeBitField(in1 []byte, inlen1 int, in2 []byte, inlen2 int) (
	out []byte, outlen int) {
	/*
	   ex1.
	   in1(len=4)  nil
	   in2(len=14) bxx11 1010 1111 0000
	   out(len=18) b1110 1011 1100 00xx

	   ex2.
	   in1(len=4)  b1010 xxxx
	   in2(len=14) b1110 1011 1100 00xx
	   out(len=18) b1010 1110 1011 1100 00xx
	*/

	if in1 == nil {
		out, outlen = ShiftLeftMost(in2, inlen2)
		return
	}

	out = make([]byte, len(in1), len(in1))
	out = append(out, in2...)
	out = ShiftLeft(out, len(in1)*8-inlen1)
	for n := 0; n < len(in1); n++ {
		out[n] |= in1[n]
	}
	outlen = inlen1 + inlen2

	octetlen := (outlen-1)/8 + 1
	out = out[:octetlen]
	return
}

// ShiftLeft is utility function to left shift the octet values.
func ShiftLeft(in []byte, shiftlen int) (out []byte) {
	out = in
	for n := 0; n < shiftlen; n++ {
		overflow := false
		for m := len(out) - 1; m >= 0; m-- {
			do := false
			if overflow == true {
				do = true
				overflow = false
			}
			if out[m]&0x80 == 0x80 {
				overflow = true
			}
			out[m] <<= 1
			if do == true {
				out[m] |= 0x01
			}
		}
	}
	for n := 0; n < (shiftlen / 8); n++ {
		out = out[:len(out)-1]
	}
	return
}

// ShiftRight is utility function to right shift the octet values.
func ShiftRight(in []byte, shiftlen int) (out []byte) {
	out = in
	for n := 0; n < shiftlen; n++ {
		underflow := false
		for m := 0; m < len(out); m++ {
			do := false
			if underflow == true {
				do = true
				underflow = false
			}
			if out[m]&0x1 == 0x1 {
				underflow = true
			}
			out[m] >>= 1
			if do == true {
				out[m] |= 0x80
			}
		}
	}
	return
}

// ShiftLeftMost is utility function to shift the octet values to the leftmost.
func ShiftLeftMost(in []byte, inlen int) (out []byte, outlen int) {
	out = in
	outlen = inlen
	out = ShiftLeft(out, len(in)*8-inlen)
	return
}

// EncConstrainedWholeNumber is the implementation for
// 11.5 Encoding of constrained whole number.
func EncConstrainedWholeNumber(input, min, max int64) (
	v []byte, bitlen int, err error) {

	if input < min || input > max {
		err = fmt.Errorf("EncConstrainedWholeNumber: "+
			"input value=%d is out of range. "+
			"(should be %d <= %d)", input, min, max)
		return
	}

	inputRange := max - min + 1
	inputEnc := input - min

	switch {
	case inputRange == 1: // empty bit-field
		return
	case inputRange < 256: // the bit-field case
		bitlen = bits.Len(uint(inputRange))
		v = []byte{byte(inputEnc)}
		return
	case inputRange == 256: // the one-octet case
		bitlen = 8
		v = []byte{byte(inputEnc)}
		return
	case inputRange <= 65536: // the two-octet case
		bitlen = 16
		v = make([]byte, 2)
		binary.BigEndian.PutUint16(v, uint16(inputEnc))
		return
	}
	// case inputRange > 65536: // the indefinite length case
	v, _ = EncNonNegativeBinaryInteger(uint(input))
	bitlen = len(v) * 8
	return
}

// EncLengthDeterminant is the implementation for
// 11.9 General rules for encoding a length determinant
func EncLengthDeterminant(input, max int) (
	v []byte, bitlen int, err error) {

	if max != 0 && max < 65536 {
		v, bitlen, err = EncConstrainedWholeNumber(int64(input), 0, int64(max))
		return
	}

	switch {
	case input < 128:
		v = append(v, byte(input))
		bitlen = 8
		return
	case input < 16384:
		v = append(v, byte((input>>8)&0xff))
		v = append(v, byte(input&0xff))
		v[0] |= 0x80
		bitlen = 16
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
		return
	}

	(*pdu)[0] &= 0x7f /// lay the most significant bit down
	length = int(binary.BigEndian.Uint16(*pdu))
	return
}

func encConstrainedWholeNumberWithExtmark(input, min, max int64, extmark bool) (
	v []byte, bitlen int, err error) {
	v, bitlen, err = EncConstrainedWholeNumber(input, min, max)
	if err != nil {
		return
	}
	if extmark == true {
		switch {
		case bitlen%8 == 0:
			bitlen += 8
			v = append([]byte{0x00}, v...)
		case bitlen < 8:
			bitlen++
		}
	}
	ShiftLeftMost(v, bitlen)
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
	v []byte, bitlen int, err error) {

	if min == max { // 12.2.1 single value
		if extmark == true {
			bitlen = 1
			v = make([]byte, 1, 1)
		}
		return
	}

	// 13.2.2 constrained whole number
	v, bitlen, err = encConstrainedWholeNumberWithExtmark(input,
		min, max, extmark)
	return
}

// EncEnumerated is the implementation for
// 14. Encoding the enumerated type
func EncEnumerated(input, min, max uint, extmark bool) (
	v []byte, bitlen int, err error) {
	v, bitlen, err =
		encConstrainedWholeNumberWithExtmark(int64(input),
			int64(min), int64(max), extmark)
	return
}

// EncBitString returns multi-byte BIT STRING
// 16. Encoding the bitstering type
func EncBitString(input []byte, inputlen, min, max int, extmark bool) (
	pv []byte, plen int, v []byte, err error) {

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

	v, _ = ShiftLeftMost(input, inputlen)

	if min == max {
		// fixed length case. not implemented yet.
		switch {
		case min < 17:
		case min > 16 && min < 65537:
		}
		return
	}

	// range is constrained whole number.
	pv, plen, _ = encConstrainedWholeNumberWithExtmark(int64(inputlen),
		int64(min), int64(max), extmark)

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
	pv []byte, plen int, v []byte, err error) {

	inputlen := len(input)
	if max != 0 && (inputlen < min || inputlen > max) {
		err = fmt.Errorf("EncOctetString: "+
			"input len(value)=%d is out of range. "+
			"(should be %d <= %d)", inputlen, min, max)
		return
	}

	if min == max && min != 0 {
		switch {
		case min < 3:
			pv = input
			plen = inputlen * 8
			if extmark == true {
				pv = append([]byte{0x00}, pv...)
				plen++
			}
			pv, plen = ShiftLeftMost(pv, plen)
		case min < 65537:
			v = input
			if extmark == true {
				pv = []byte{0x00}
				plen = 1
				pv, plen = ShiftLeftMost(pv, plen)
			}
		}
		return
	}

	v = input
	if max == 0 {
		// infinite upper bound case.
		pv, plen, err = EncLengthDeterminant(inputlen, max)
		return
	}

	// lower bound and upper bound are specified.
	pv, plen, err =
		encConstrainedWholeNumberWithExtmark(int64(inputlen),
			int64(min), int64(max), extmark)
	return
}

// EncSequence return Sequence Preamble but it just returns 0x00 for now.
// 19. Encoding the sequence type
func EncSequence(extmark bool, optnum int, optflag uint) (
	pv []byte, plen int, err error) {
	if optnum > 7 {
		err = fmt.Errorf("EncSequence: "+
			"optnum=%d is not implemented yet. (should be < 8)",
			optnum)
		return
	}
	if extmark == true {
		plen++
	}

	pv = make([]byte, 1, 1)
	plen += optnum
	pv = make([]byte, 1, 1)
	pv[0] |= byte(optflag)
	pv, plen = ShiftLeftMost(pv, plen)
	return
}

// EncSequenceOf return Sequence-Of Preamble.
// 20. Encoding the sequence-of type
var EncSequenceOf = EncEnumerated

// EncChoice is the implementation for
// 23. Encoding the choice type
func EncChoice(input, min, max int, extmark bool) (
	pv []byte, plen int, err error) {
	pv, plen, err = EncInteger(int64(input), int64(min), int64(max), extmark)
	return
}
