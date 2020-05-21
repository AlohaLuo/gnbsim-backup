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
	expect_str := "7e004179000d0102f8392143000010325476981001202e0480a00000"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, v) == false {
		t.Errorf("RegistrationRequest\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeSecurityModeComplete(t *testing.T) {
	ue := NewNAS("nas_test.json")
	v := ue.MakeSecurityModeComplete()
	fmt.Printf("MakeSecurityModeCoplete: %02x\n", v)

	ue.recv.flag.rinmr = true
	v = ue.MakeSecurityModeComplete()
	fmt.Printf("MakeSecurityModeCoplete: %02x\n", v)
	/*
		expect_str := "7e004179000d0102f8392143000010325476981001202e0480a00000"
		expect, _ := hex.DecodeString(expect_str)
		if compareSlice(expect, v) == false {
			t.Errorf("RegistrationRequest\nexpect: %x\nactual: %x", expect, v)
		}
	*/
}

func TestDecode(t *testing.T) {
	ue := NewNAS("nas_test.json")

	pattern := []struct {
		in_str string
	}{
		{"7e005600020000217d9192431b0560ca6c35a0212d6759e520109a4a995a657a800089c03b9ac78a0614"},
		{"7e03ca400b02007e035d02000480a00000e1360100"},
	}
	/*
		Kausf = 1c8b838366037b534006054b3572a0f2320db15982408bb4339e350665a54885
		Kseaf = 11aaee4f7d9262208ce72a8cc4ee35caaa26e8d42484f629cbf46fa17f38fb63
		ue.supi = imsi-208930123456789
		Kamf = 2836b8c08e73027fd28135ac1a9640203f98eb7a5613f8f303c5b559d4601ec3
		KnasEnc = 9dcacc5aed08757f17693ba88da3e365
		KnasInt = a809c2888513cfc73a343e7c27dd63ef
	*/

	for _, p := range pattern {
		fmt.Printf("----------\n")
		in, _ := hex.DecodeString(p.in_str)
		length := len(in)
		ue.Decode(&in, length)
	}
}
