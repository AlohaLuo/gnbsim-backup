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
	fmt.Printf("MakeInitialUEMessage: %02x\n", v)
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
