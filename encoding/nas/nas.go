// Copyright 2019-2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package nas is implementation for non-access stratum (NAS) procedure
// in the 5GS Sytem.
// document version: 3GPP TS 24.501 v16.3.0 (2019-12)
package nas

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"strconv"

	"github.com/wmnsk/milenage"
)

type UE struct {
	MSIN             string
	MCC              int
	MNC              int
	RoutingIndicator uint16
	ProtectionScheme string
	AuthParam        AuthParam

	state struct {
		securityHeaderParsed bool
	}
}

// 9.1.1 NAS message format
type NasMessageMM struct {
	ExtendedProtocolDiscriminator uint8
	SecurityHeaderType            uint8
	MessageType                   uint8
}

// TS 24.007 11.2.3.1.1A Extended protocol discriminator (EPD)
const (
	EPD5GSSessionManagement  = 0x2e
	EPD5GSMobilityManagement = 0x7e
)

var epdStr = map[int]string{
	EPD5GSSessionManagement:  "5G Session Management",
	EPD5GSMobilityManagement: "5G Mobility Management",
}

/*
type NasMessageSM struct {
	ExtendedProtocolDiscriminator uint8
	PDUSessionID uint8
	ProcedureTransactionID uint8
	MessageType uint8
}
*/

// 9.3 Security header type
const (
	SecurityHeaderTypePlain = iota
	SecurityHeaderTypeIntegrityProtected
	SecurityHeaderTypeIntegrityProtectedAndCiphered
)

// 9.7 Message type
const (
	MessageTypeRegistrationRequest    = 0x41
	MessageTypeAuthenticationRequest  = 0x56
	MessageTypeAuthenticationResponse = 0x57
	MessageTypeSecurityModeCommand    = 0x5d
)

var msgTypeStr = map[int]string{
	MessageTypeRegistrationRequest:    "Registration Request",
	MessageTypeAuthenticationRequest:  "Authentication Request",
	MessageTypeAuthenticationResponse: "Authentication Response",
	MessageTypeSecurityModeCommand:    "Security Mode Command",
}

const (
	ieiIMEISVRequest                   = 0xe0
	iei5GMMCapability                  = 0x10
	ieiAuthParamAUTN                   = 0x20
	ieiAuthParamRAND                   = 0x21
	ieiAuthParamRES                    = 0x2d
	ieiUESecurityCapability            = 0x2e
	ieiAdditional5GSecurityInformation = 0x36
)

func NewNAS(filename string) (p *UE) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var ue UE
	p = &ue
	json.Unmarshal(bytes, p)

	return
}

func (ue *UE) Decode(pdu *[]byte, length int) (msgType int) {
	epd := int((*pdu)[0])
	fmt.Printf("EPD: %s (0x%x)\n", epdStr[epd], epd)
	*pdu = (*pdu)[1:]
	length--

	secHeader := int((*pdu)[0])
	fmt.Printf("Security Header: 0x%x\n", secHeader)
	*pdu = (*pdu)[1:]
	length--
	fmt.Printf("security header parse = %v\n", ue.state.securityHeaderParsed)

	if secHeader != 0x00 && ue.state.securityHeaderParsed == false {
		mac := (*pdu)[:4]
		seq := int((*pdu)[4])
		fmt.Printf("mac: %x, seq = %d\n", mac, seq)
		*pdu = (*pdu)[5:]
		length -= 5
		ue.state.securityHeaderParsed = true
		msgType = ue.Decode(pdu, length)
		return
	}

	if secHeader != 0x00 {
		fmt.Printf("# Well..., free5gc seems to set the security header != 0" +
			" for the plain NAS message. My workaround is invoked.\n")
	}

	msgType = int((*pdu)[0])
	fmt.Printf("Message Type: %s (0x%x)\n", msgTypeStr[msgType], msgType)
	*pdu = (*pdu)[1:]

	switch msgType {
	case MessageTypeAuthenticationRequest:
		ue.decAuthenticationRequest(pdu)
		break
	case MessageTypeSecurityModeCommand:
		ue.decSecurityModeCommand(pdu)
		break
	default:
		break
	}

	ue.state.securityHeaderParsed = false
	return
}

func (ue *UE) decInformationElement(pdu *[]byte) {

	for len(*pdu) > 0 {
		iei := int((*pdu)[0])
		*pdu = (*pdu)[1:]

		switch iei {
		case ieiAuthParamAUTN:
			ue.decAuthParamAUTN(pdu)
		case ieiAuthParamRAND:
			ue.decAuthParamRAND(pdu)
		case ieiAdditional5GSecurityInformation:
			fmt.Printf("Additional 5G Security Information\n")
		default:
			switch iei & 0xf0 {
			case ieiIMEISVRequest:
				fmt.Printf("IMEISV Request\n")
			default:
				fmt.Printf("unsupported IE\n")
				*pdu = []byte{}
			}
		}
	}
}

// 8.2.1 Authentication request
func (ue *UE) decAuthenticationRequest(pdu *[]byte) {
	fmt.Printf("decAuthenticationRequest\n")

	ue.decngKSI(pdu)
	ue.decABBA(pdu)
	ue.decInformationElement(pdu)

	k, _ := hex.DecodeString(ue.AuthParam.K)
	opc, _ := hex.DecodeString(ue.AuthParam.OPc)
	amf := binary.BigEndian.Uint16(ue.AuthParam.amf)

	m := milenage.NewWithOPc(k, opc, ue.AuthParam.rand, 0, amf)
	m.F2345()
	for n, v := range ue.AuthParam.seqxorak {
		m.SQN[n] = v ^ m.AK[n]
	}
	m.F1()

	fmt.Printf("   K: %x\n", m.K)
	fmt.Printf("   OP: %x\n", m.OP)
	fmt.Printf("   OPc: %x\n", m.OPc)
	fmt.Printf("   AMF: %x\n", m.AMF)
	fmt.Printf("   SQN(%d): %x\n", len(m.SQN), m.SQN)
	fmt.Printf("   CK: %x\n", m.CK)
	fmt.Printf("   IK: %x\n", m.IK)
	fmt.Printf("   AK(%d): %x\n", len(m.AK), m.AK)
	fmt.Printf("   MACA: %x\n", m.MACA)
	fmt.Printf("   MACS: %x\n", m.MACS)
	fmt.Printf("   RAND: %x\n", m.RAND)
	fmt.Printf("   RES: %x\n", m.RES)

	if reflect.DeepEqual(ue.AuthParam.mac, m.MACA) == false {
		fmt.Printf("  received and calculated MAC values do not match.\n")
		// need response for error.
		return
	}
	fmt.Printf("  received and calculated MAC values match.\n")

	ue.AuthParam.RESstar = ComputeRESstar(ue.MCC, ue.MNC, m.RAND, m.RES, m.CK, m.IK)
	fmt.Printf("   RES*: %x\n", ue.AuthParam.RESstar)
	return
}

// 8.2.2 Authentication response
func (ue *UE) MakeAuthenticationResponse() (pdu []byte) {

	var h NasMessageMM
	h.ExtendedProtocolDiscriminator = EPD5GSMobilityManagement
	h.SecurityHeaderType = SecurityHeaderTypePlain
	h.MessageType = MessageTypeAuthenticationResponse

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, h)
	binary.Write(data, binary.BigEndian, ue.encAuthParamRes())
	pdu = data.Bytes()

	return
}

// 8.2.6 Registration request
// 5.5.1.2 Registration procedure for initial registration
type RegistrationRequest struct {
	head                     NasMessageMM
	registrationTypeAndngKSI uint8
	fiveGSMobileID           FiveGSMobileID
}

func (p *UE) MakeRegistrationRequest() (pdu []byte) {

	var req RegistrationRequest
	var h *NasMessageMM = &req.head
	h.ExtendedProtocolDiscriminator = EPD5GSMobilityManagement
	h.SecurityHeaderType = SecurityHeaderTypePlain
	h.MessageType = MessageTypeRegistrationRequest

	var regType uint8 = RegistrationTypeInitialRegistration |
		RegistrationTypeFlagFollowOnRequestPending
	var ngKSI uint8 = KeySetIdentityNoKeyIsAvailable

	req.registrationTypeAndngKSI = regType | (ngKSI << 4)

	var f *FiveGSMobileID = &req.fiveGSMobileID
	var typeID uint8 = TypeIDSUCI
	var supiFormat uint8 = SUPIFormatIMSI

	/*
	 * it doesn't work with "f.length = uint16(unsafe.Sizeof(*f) - 2)"
	 * because of the octet alignment.
	 */
	f.length = 13
	f.supiFormatAndTypeID = typeID | (supiFormat << 4)
	f.plmn = encPLMN(p.MCC, p.MNC)
	f.routingIndicator = encRoutingIndicator(p.RoutingIndicator)
	f.protectionScheme = encProtectionScheme(p.ProtectionScheme)
	f.homeNetworkPublicKeyID = 0
	f.schemeOutput = encSchemeOutput(p.MSIN)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, req)
	binary.Write(data, binary.BigEndian, enc5GMMCapability())
	binary.Write(data, binary.BigEndian, encUESecurityCapability())
	pdu = data.Bytes()

	return
}

// 8.2.25 Security mode command
func (ue *UE) decSecurityModeCommand(pdu *[]byte) {

	ue.decNASSecurityAlgorithms(pdu)
	ue.decngKSI(pdu)
	ue.decUESecurityCapability(pdu)

	ue.decInformationElement(pdu)

	return
}

func encPLMN(mcc, mnc int) (plmn [3]byte) {
	format := "%d%d"
	if mnc < 100 {
		format = "%df%d"
	}

	str := fmt.Sprintf(format, mcc, mnc)
	for i, v := range Str2BCD(str) {
		plmn[i] = v
	}
	return
}

func encRoutingIndicator(ind uint16) (ri [2]byte) {
	str := fmt.Sprintf("%d", ind)
	for i, v := range Str2BCD(str) {
		ri[i] = v
	}
	return
}

func encProtectionScheme(profile string) (p uint8) {
	switch profile {
	case "null":
		p = ProtectionSchemeNull
	}
	return
}

func encSchemeOutput(msin string) (so [5]byte) {
	for i, v := range Str2BCD(msin) {
		so[i] = v
	}
	return
}

// 9.11.3.1 5GMM capability
type FiveGMMCapability struct {
	iei         uint8
	length      uint8
	capability1 uint8
}

const (
	FiveGMMCapN3data = 0x20
)

func enc5GMMCapability() (f FiveGMMCapability) {
	f.iei = 0x10
	f.length = 1
	f.capability1 = FiveGMMCapN3data

	return
}

// 9.11.3.4 5GS mobile identity
type FiveGSMobileID struct {
	length                 uint16
	supiFormatAndTypeID    uint8
	plmn                   [3]uint8
	routingIndicator       [2]uint8
	protectionScheme       uint8
	homeNetworkPublicKeyID uint8
	schemeOutput           [5]uint8
}

const (
	TypeIDNoIdentity = iota
	TypeIDSUCI
)

const (
	SUPIFormatIMSI = iota
	SUPIFormatNetworkSpecificID
)

const (
	ProtectionSchemeNull = iota
	ProtectionSchemeProfileA
	ProtectionSchemeProfileB
)

// 9.11.3.7 5GS registration type
const (
	RegistrationTypeInitialRegistration        = 0x01
	RegistrationTypeFlagFollowOnRequestPending = 0x08
)

// 9.11.3.10 ABBA
func (ue *UE) decABBA(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	abba := (*pdu)[:length]
	*pdu = (*pdu)[length:]

	fmt.Printf("ABBA\n")
	fmt.Printf(" Length: %d\n", length)
	fmt.Printf(" Value: %02x\n", abba)

	return
}

// 9.11.3.15 Authentication parameter AUTN
// TS 24.008 10.5.3.1.1 Authentication Parameter AUTN (UMTS and EPS authentication challenge)
type AuthParam struct {
	K        string
	OPc      string
	rand     []byte
	autn     []byte
	seqxorak []byte
	amf      []byte
	mac      []byte
	RESstar  []byte
}

func (ue *UE) decAuthParamAUTN(pdu *[]byte) {

	fmt.Printf("Auth Param AUTN\n")

	autnlen := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.AuthParam.autn = (*pdu)[:autnlen]
	*pdu = (*pdu)[autnlen:]
	fmt.Printf(" AUTN: %02x\n", ue.AuthParam.autn)
	ue.AuthParam.seqxorak = ue.AuthParam.autn[:6]
	ue.AuthParam.amf = ue.AuthParam.autn[6:8]
	ue.AuthParam.mac = ue.AuthParam.autn[8:16]
	fmt.Printf("  SEQ xor AK: %02x\n", ue.AuthParam.seqxorak)
	fmt.Printf("  AMF: %02x\n", ue.AuthParam.amf)
	fmt.Printf("  MAC: %02x\n", ue.AuthParam.mac)

	return
}

// 9.11.3.16 Authentication parameter RAND
// TS 24.008 10.5.3.1 Authentication parameter RAND
func (ue *UE) decAuthParamRAND(pdu *[]byte) {

	fmt.Printf("Auth Param RAND\n")

	const randlen = 16
	ue.AuthParam.rand = (*pdu)[:randlen]
	*pdu = (*pdu)[randlen:]
	fmt.Printf(" RAND: %02x\n", ue.AuthParam.rand)
	return
}

// 9.11.3.17 Authentication response parameter
// TS 24.301 9.9.3.4 Authentication response parameter
type AuthParamRes struct {
	iei     uint8
	length  uint8
	resstar [16]byte
}

func (ue *UE) encAuthParamRes() (res AuthParamRes) {
	res.iei = ieiAuthParamRES
	for i, v := range ue.AuthParam.RESstar {
		res.resstar[i] = v
	}
	res.length = uint8(len(res.resstar))
	return
}

// 9.11.3.32 NAS key set identifier
const (
	KeySetIdentityNoKeyIsAvailable          = 0x07
	KeySetIdentityFlagMappedSecurityContext = 0x08
)

func (ue *UE) decngKSI(pdu *[]byte) {

	ksi := int((*pdu)[0])
	fmt.Printf("ngKSI: 0x%x\n", ksi)
	*pdu = (*pdu)[1:]

	return
}

// 9.11.3.34 NAS security algorithms
func (ue *UE) decNASSecurityAlgorithms(pdu *[]byte) {

	fmt.Printf("NAS Security Algorithms\n")
	alg := (*pdu)[:1]
	fmt.Printf(" NAS Security Algorithms: 0x%02x\n", alg)
	*pdu = (*pdu)[1:]

	return
}

// 9.11.3.54 UE security capability
type UESecurityCapability struct {
	iei    uint8
	length uint8
	ea     uint8
	ia     uint8
	eea    uint8
	eia    uint8
}

const (
	EA0 = 0x80
	EA1 = 0x40
	EA2 = 0x20
	IA0 = 0x80
	IA1 = 0x40
	IA2 = 0x20
)

func encUESecurityCapability() (sc UESecurityCapability) {
	sc.iei = ieiUESecurityCapability
	sc.length = 4

	// use null encryption at this moment.
	sc.ea = EA0
	sc.ia = IA0 | IA2

	return
}

func (ue *UE) decUESecurityCapability(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	cap := (*pdu)[:length]
	fmt.Printf(" Replayed UE Security Capability: %02x\n", cap)
	*pdu = (*pdu)[length:]

	return
}

//-----
func Str2BCD(str string) (bcd []byte) {

	byteArray := []byte(str)
	bcdlen := len(byteArray) / 2
	if len(byteArray)%2 == 1 {
		bcdlen++
	}
	bcd = make([]byte, bcdlen, bcdlen)

	for i, v := range byteArray {

		n, _ := strconv.ParseUint(string(v), 16, 8)
		j := i / 2

		if i%2 == 0 {
			bcd[j] = byte(n)
		} else {
			bcd[j] |= (byte(n) << 4)
		}
	}

	return
}

// TS 33.501
// A.4 RES* and XRES* derivation function
func ComputeRESstar(mcc, mnc int, rand, res, ck, ik []byte) (resstar []byte) {

	s := []byte{}
	fc := []byte{0x6b}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", mnc, mcc)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)

	s = append(s, rand...)
	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(rand)))
	s = append(s, l1...)

	s = append(s, res...)
	l2 := make([]byte, 2)
	binary.BigEndian.PutUint16(l2, uint16(len(res)))
	s = append(s, l2...)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	resstar = mac.Sum(nil)

	/*
	 * The (X)RES* is identified with the 128 least significant bits of the output
	 * of the KDF.
	 */
	n := len(resstar)
	resstar = resstar[n-16:]

	return
}
