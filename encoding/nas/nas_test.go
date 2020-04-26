package nas

import (
	"encoding/hex"
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

func TestStr2BCD(t *testing.T) {
	bcd := Str2BCD("12345")
	expect := []byte{0x21, 0x43, 0x05}
	if compareSlice(expect, bcd) == false {
		t.Errorf("value expect: 0x%02x, actual 0x%02x", expect, bcd)
	}

	bcd = Str2BCD("12345f")
	expect = []byte{0x21, 0x43, 0xf5}
	if compareSlice(expect, bcd) == false {
		t.Errorf("value expect: 0x%02x, actual 0x%02x", expect, bcd)
	}
}

func TestMakeRegistrationRequest(t *testing.T) {
	ue := NewNAS("nas_test.json")
	v := ue.MakeRegistrationRequest()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := "7e004179000d0121f3542143000010325476981001202e0480800000"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, v) == false {
		t.Errorf("RegistrationRequest\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestDecode(t *testing.T) {
	ue := NewNAS("nas_test.json")

	in_str := "7e0056070200002123e87a6d2b0cde95ca763ded3a017c3020102b3e6160baed8000b77ab234553870f1"
	in, _ := hex.DecodeString(in_str)
	length := len(in)
	ue.Decode(&in, length)

	expect_str := "7e0056070200002123e87a6d2b0cde95ca763ded3a017c3020102b3e6160baed8000b77ab234553870f1"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, in) == false {
		t.Errorf("Decode\nexpect: %x\nactual: %x", expect, in)
	}
}
