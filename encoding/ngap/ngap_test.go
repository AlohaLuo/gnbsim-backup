package ngap

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

func TestMakeInitialUEMessage(t *testing.T) {
	gnbp := NewNGAP("ngap_test.json")
	v := gnbp.MakeInitialUEMessage()
	expect_str := "000f40440000040055000200000026001a197e004179000d0121f3542143000010325476982e04a0a000000079000f4021f354000004001021f354000102005a4001180070400100"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, v) == false {
		t.Errorf("InitialUEMessage\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestMakeNGSetupRequest(t *testing.T) {
	gnbp := NewNGAP("ngap_test.json")
	v := gnbp.MakeNGSetupRequest()
	expect_str := "00150028000003001b00080021f354000000040066001000000001020021f354000010081234560015400100"
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, v) == false {
		t.Errorf("NGSetupRequest\nexpect: %x\nactual: %x", expect, v)
	}
}

func TestDecode(t *testing.T) {
	gnbp := NewNGAP("ngap_test.json")
	in_str := "0004403e000003000a000200010055000200000026002b2a7e0056070200002123e87a6d2b0cde95ca763ded3a017c3020102b3e6160baed8000b77ab234553870f1"
	in, _ := hex.DecodeString(in_str)
	gnbp.Decode(&in)

	expect_str := ""
	expect, _ := hex.DecodeString(expect_str)
	if compareSlice(expect, in) == false {
		t.Errorf("NGSetupRequest\nexpect: %x\nactual: %x", expect, in)
	}
}
