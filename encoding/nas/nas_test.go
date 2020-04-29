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

func TestMakeAuthenticationResponse(t *testing.T) {
	ue := NewNAS("nas_test.json")
	ue.AuthParam.RESstar = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	v := ue.MakeAuthenticationResponse()
	//fmt.Printf("MakeRegistrationRequest: %02x\n", v)
	expect_str := "7e00572d10000102030405060708090a0b0c0d0e0f"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, v) == false {
		t.Errorf("AuthenticationResponse\nexpect: %x\nactual: %x", expect, v)
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
