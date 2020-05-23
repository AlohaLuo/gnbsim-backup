// Copyright 2019-2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package nas is implementation for non-access stratum (NAS) procedure
// in the 5GS Sytem.
// document version: 3GPP TS 24.501 v16.3.0 (2019-12)
package nas

import (
	"bytes"
	"crypto/aes"
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
	"strings"

	"github.com/aead/cmac"
	"github.com/wmnsk/milenage"
)

type UE struct {
	MSIN             string
	MCC              int
	MNC              int
	IMEISV           string
	RoutingIndicator uint16
	ProtectionScheme string
	AuthParam        AuthParam

	state5GMM int

	recv struct {
		flag struct {
			rinmr bool
		}
		state int
	}

	DLCount uint32
	ULCount uint32

	wa struct {
		securityHeaderParsed bool
	}
	indent int // indent for debug print.
}

// 5.1.3 5GMM sublayer states
// actual value is not defined in the standard.
const (
	//fiveGMMNULL = iota
	state5GMMDeregistared = iota
	state5GMMRegistaredInitiated
	state5GMMRegistared
	state5GMMServiceRequestInitiated
	state5GMMDeregistaredInitiated
)

var state5GMMstr = map[int]string{
	//state5GMMNULL:                    "5GMM-NULL",
	state5GMMDeregistared:            "5GMM-DEREGISTERED",
	state5GMMRegistaredInitiated:     "5GMM-REGISTERED-INITIATED",
	state5GMMRegistared:              "5GMM-REGISTERED",
	state5GMMServiceRequestInitiated: "5GMM-SERVICE-REQUEST-INITIATED",
	state5GMMDeregistaredInitiated:   "5GMM-DEREGISTERED-INITIATED",
}

// my receive flag definition
const (
	rcvdNull = iota
	rcvdAuthenticationRequest
	rcvdSecurityModeCommand
)

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
	SecurityHeaderTypeIntegrityProtectedWithNewContext
	SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext
)

// 9.7 Message type
const (
	MessageTypeRegistrationRequest    = 0x41
	MessageTypeAuthenticationRequest  = 0x56
	MessageTypeAuthenticationResponse = 0x57
	MessageTypeSecurityModeCommand    = 0x5d
	MessageTypeSecurityModeComplete   = 0x5e
)

var msgTypeStr = map[int]string{
	MessageTypeRegistrationRequest:    "Registration Request",
	MessageTypeAuthenticationRequest:  "Authentication Request",
	MessageTypeAuthenticationResponse: "Authentication Response",
	MessageTypeSecurityModeCommand:    "Security Mode Command",
	MessageTypeSecurityModeComplete:   "Security Mode Complete",
}

const (
	ieiIMEISVRequest        = 0xe
	iei5GMMCapability       = 0x10
	ieiAuthParamAUTN        = 0x20
	ieiAuthParamRAND        = 0x21
	ieiAuthParamRES         = 0x2d
	ieiUESecurityCapability = 0x2e
	ieiAdditional5GSecInfo  = 0x36
	ieiNASMessageContainer  = 0x71
	iei5GSMobileIdentity    = 0x77
	ieiNonSupported         = 0xff
)

var ieStr = map[int]string{
	ieiIMEISVRequest:        "IMEISV Request IE",
	iei5GMMCapability:       "5G MM Capability IE",
	ieiAuthParamAUTN:        "Authentication Parameter AUTN IE",
	ieiAuthParamRAND:        "Authentication Parameter RAND IE",
	ieiAuthParamRES:         "Authentication response parameter IE",
	ieiUESecurityCapability: "UE Security Capability IE",
	ieiAdditional5GSecInfo:  "Additional 5G Security Information IE",
	ieiNASMessageContainer:  "NAS Message Container IE",
	iei5GSMobileIdentity:    "5GS Mobile Identity IE",
	ieiNonSupported:         "Non Supported IE",
}

func NewNAS(filename string) (ue *UE) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var obj UE
	ue = &obj
	json.Unmarshal(bytes, ue)

	ue.PowerON()

	return
}

func (ue *UE) PowerON() {
	ue.state5GMM = state5GMMDeregistared
	ue.recv.state = rcvdNull
}

func (ue *UE) MakeNasPdu() (pdu []byte) {
	switch ue.recv.state {
	case rcvdNull:
	case rcvdAuthenticationRequest:
		pdu = ue.MakeAuthenticationResponse()
	case rcvdSecurityModeCommand:
		pdu = ue.MakeSecurityModeComplete()
	}
	return
}

func (ue *UE) Decode(pdu *[]byte, length int) (msgType int) {
	epd := int((*pdu)[0])
	ue.dprint("EPD: %s (0x%x)", epdStr[epd], epd)
	*pdu = (*pdu)[1:]
	length--

	secHeader := int((*pdu)[0])
	ue.dprint("Security Header: 0x%x", secHeader)
	*pdu = (*pdu)[1:]
	length--

	if secHeader != 0x00 && ue.wa.securityHeaderParsed == false {
		mac := (*pdu)[:4]
		ue.dprinti("mac: %x", mac)
		*pdu = (*pdu)[4:]
		length -= 4

		seq := uint8((*pdu)[0])
		ue.dprinti("seq: %d", seq)

		macCalc := ue.ComputeMAC(0, 1, pdu)
		if reflect.DeepEqual(mac, macCalc) == false {
			ue.dprint("***** Integrity check failed...")
			ue.dprint("Received  : %x", mac)
			ue.dprint("Calculated: %x", macCalc)
			*pdu = []byte{}
			return
		}
		ue.dprint("***** Integrity check passed")

		*pdu = (*pdu)[1:]
		length--

		ue.wa.securityHeaderParsed = true
		msgType = ue.Decode(pdu, length)
		return
	}

	if secHeader != 0x00 {
		ue.dprinti("# Well..., free5gc seems to set the security header != 0" +
			" for the plain NAS message. My workaround is invoked.")
	}

	msgType = int((*pdu)[0])
	ue.dprint("Message Type: %s (0x%x)", msgTypeStr[msgType], msgType)
	*pdu = (*pdu)[1:]

	ue.indent++
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
	ue.indent--

	ue.wa.securityHeaderParsed = false
	return
}

func (ue *UE) decInformationElement(pdu *[]byte) {

	for len(*pdu) > 0 {
		iei := int((*pdu)[0])

		// see Annex K.1 Common information elements.
		if iei&0x80 != 0 {
			iei >>= 4
			(*pdu)[0] &= 0x0f
		} else {
			*pdu = (*pdu)[1:]
		}

		if ieStr[iei] == "" {
			iei = 0xff
		}
		ue.dprint(ieStr[iei])

		switch iei {
		case ieiIMEISVRequest:
			ue.decIMEISVRequest(pdu)
		case ieiAuthParamAUTN:
			ue.decAuthParamAUTN(pdu)
		case ieiAuthParamRAND:
			ue.decAuthParamRAND(pdu)
		case ieiAdditional5GSecInfo:
			ue.decAdditional5GSecInfo(pdu)
			break
		default:
			*pdu = []byte{}
		}
	}
}

// 8.2.1 Authentication request
func (ue *UE) decAuthenticationRequest(pdu *[]byte) {
	ue.dprint("Authentication Request")

	orig := ue.indent
	ue.indent++
	ue.decngKSI(pdu)
	ue.decABBA(pdu)
	ue.decInformationElement(pdu)
	ue.indent--

	k, _ := hex.DecodeString(ue.AuthParam.K)
	opc, _ := hex.DecodeString(ue.AuthParam.OPc)
	amf := binary.BigEndian.Uint16(ue.AuthParam.amf)

	m := milenage.NewWithOPc(k, opc, ue.AuthParam.rand, 0, amf)
	m.F2345()
	for n, v := range ue.AuthParam.seqxorak {
		m.SQN[n] = v ^ m.AK[n]
	}
	m.F1()

	ue.indent++
	ue.dprint("K   : %x", m.K)
	ue.dprint("OP  : %x", m.OP)
	ue.dprint("OPc : %x", m.OPc)
	ue.dprint("AMF : %x", m.AMF)
	ue.dprint("SQN : %x", m.SQN)
	ue.dprint("CK  : %x", m.CK)
	ue.dprint("IK  : %x", m.IK)
	ue.dprint("AK  : %x", m.AK)
	ue.dprint("MACA: %x", m.MACA)
	ue.dprint("MACS: %x", m.MACS)
	ue.dprint("RAND: %x", m.RAND)
	ue.dprint("RES : %x", m.RES)

	if reflect.DeepEqual(ue.AuthParam.mac, m.MACA) == false {
		ue.dprinti("received and calculated MAC values do not match.\n")
		ue.indent = orig
		// need response for error.
		return
	}

	ue.ComputeKausf(m.CK, m.IK)
	ue.ComputeKseaf()
	ue.ComputeKamf()
	ue.ComputeAlgKey()

	ue.ComputeRESstar(m.RAND, m.RES, m.CK, m.IK)

	ue.dprint("Kausf: %x", ue.AuthParam.Kausf)
	ue.dprint("Kseaf: %x", ue.AuthParam.Kseaf)
	ue.dprint("Kamf : %x", ue.AuthParam.Kamf)
	ue.dprint("Kenc : %x", ue.AuthParam.Kenc)
	ue.dprint("Kint : %x", ue.AuthParam.Kint)
	ue.dprint("RES* : %x", ue.AuthParam.RESstar)
	ue.dprint("received and calculated MAC values match.")
	ue.indent = orig

	ue.recv.state = rcvdAuthenticationRequest

	return
}

// 8.2.2 Authentication response
func (ue *UE) MakeAuthenticationResponse() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeAuthenticationResponse)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, ue.encAuthParamRes())
	pdu = append(pdu, data.Bytes()...)

	return
}

// 8.2.6 Registration request
// 5.5.1.2 Registration procedure for initial registration
func (ue *UE) MakeRegistrationRequest() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeRegistrationRequest)

	regType := RegistrationTypeInitialRegistration |
		RegistrationTypeFlagFollowOnRequestPending
	ngKSI := KeySetIdentityNoKeyIsAvailable

	registrationTypeAndngKSI := byte(regType | (ngKSI << 4))

	pdu = append(pdu, []byte{registrationTypeAndngKSI}...)
	pdu = append(pdu, ue.enc5GSMobileID(false, TypeIDSUCI)...)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, enc5GMMCapability())
	binary.Write(data, binary.BigEndian, encUESecurityCapability())
	pdu = append(pdu, data.Bytes()...)

	ue.state5GMM = state5GMMRegistaredInitiated

	// start T3510 timer. see 5.5.1.2.2 Initial registration initiation

	return
}

// 8.2.25 Security mode command
func (ue *UE) decSecurityModeCommand(pdu *[]byte) {

	ue.dprint("Security Mode Command")

	ue.indent++
	ue.decNASSecurityAlgorithms(pdu)
	ue.decngKSI(pdu)
	ue.decUESecurityCapability(pdu)
	ue.decInformationElement(pdu)
	ue.indent--

	ue.recv.state = rcvdSecurityModeCommand

	return
}

// 8.2.26 Security mode complete
func (ue *UE) MakeSecurityModeComplete() (pdu []byte) {

	pdu = ue.enc5GSMMMessageHeader(SecurityHeaderTypePlain,
		MessageTypeSecurityModeComplete)

	pdu = append(pdu, ue.enc5GSMobileID(true, TypeIDIMEISV)...)
	ue.dprint("pdu = %x", pdu)

	if ue.recv.flag.rinmr == true {
		pdu = append(pdu, ue.encNASMessageContainer(true, MessageTypeRegistrationRequest)...)
		ue.recv.flag.rinmr = false
	}

	head := ue.enc5GSecurityProtectedMessageHeader(
		SecurityHeaderTypeIntegrityProtectedAndCipheredWithNewContext, &pdu)

	pdu = append(head, pdu...)

	return
}

// 9.1.1 NAS message format
func (ue *UE) enc5GSMMMessageHeader(
	headType uint8, msgType uint8) (head []byte) {

	head = append(head, []byte{EPD5GSMobilityManagement}...)
	head = append(head, []byte{headType}...)
	head = append(head, []byte{msgType}...)

	return
}

func (ue *UE) enc5GSecurityProtectedMessageHeader(
	headType uint8, pdu *[]byte) (head []byte) {

	head = append(head, []byte{EPD5GSMobilityManagement}...)
	head = append(head, []byte{headType}...)

	seq := []byte{uint8(ue.ULCount)}
	*pdu = append(seq, *pdu...)

	mac := ue.ComputeMAC(0, 0, pdu)
	head = append(head, mac...)

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

func enc5GMMCapability() (pdu []byte) {

	var f FiveGMMCapability

	f.iei = 0x10
	f.length = 1
	f.capability1 = FiveGMMCapN3data

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

	return
}

// 9.11.3.4 5GS mobile identity
// I need C 'union' for golang...
const (
	TypeIDNoIdentity = iota
	TypeIDSUCI
	TypeID5GGUTI
	TypeIDIMEI
	TypeID5GSTMSI
	TypeIDIMEISV
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

func (ue *UE) enc5GSMobileID(iei bool, typeID int) (pdu []byte) {

	if iei == true {
		pdu = append(pdu, []byte{iei5GSMobileIdentity}...)
	}

	switch typeID {
	//case TypeIDNoIdentity:
	case TypeIDSUCI:
		pdu = append(pdu, ue.enc5GSMobileIDTypeSUCI()...)
	//case TypeID5GGUTI:
	//case TypeIDIMEI:
	//case TypeID5GSTMSI:
	case TypeIDIMEISV:
		pdu = append(pdu, ue.enc5GSMobileIDTypeIMEISV()...)
	}
	return
}

type FiveGSMobileIDSUCI struct {
	length                 uint16
	supiFormatAndTypeID    uint8
	plmn                   [3]uint8
	routingIndicator       [2]uint8
	protectionScheme       uint8
	homeNetworkPublicKeyID uint8
	schemeOutput           [5]uint8
}

func (ue *UE) enc5GSMobileIDTypeSUCI() (pdu []byte) {

	var f FiveGSMobileIDSUCI
	var typeID uint8 = TypeIDSUCI
	var supiFormat uint8 = SUPIFormatIMSI

	/*
	 * it doesn't work with "f.length = uint16(unsafe.Sizeof(*f) - 2)"
	 * because of the octet alignment.
	 */
	f.length = 13
	f.supiFormatAndTypeID = typeID | (supiFormat << 4)
	f.plmn = encPLMN(ue.MCC, ue.MNC)
	f.routingIndicator = encRoutingIndicator(ue.RoutingIndicator)
	f.protectionScheme = encProtectionScheme(ue.ProtectionScheme)
	f.homeNetworkPublicKeyID = 0
	f.schemeOutput = encSchemeOutput(ue.MSIN)

	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

	return
}

type FiveGSMobileIDIMEISV struct {
	length uint16
	imeisv [9]byte
}

func (ue *UE) enc5GSMobileIDTypeIMEISV() (pdu []byte) {

	var f FiveGSMobileIDIMEISV
	var typeID uint8 = TypeIDIMEISV

	f.length = 9

	if len(ue.IMEISV)/2 == 1 {
		typeID |= 0x08 // odd even bit
	}

	imeisv := fmt.Sprintf("%x%sf", typeID, ue.IMEISV)
	for i, v := range Str2BCD(imeisv) {
		f.imeisv[i] = v
	}
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, f)
	pdu = data.Bytes()

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

// 9.11.3.7 5GS registration type
const (
	RegistrationTypeInitialRegistration        = 0x01
	RegistrationTypeFlagFollowOnRequestPending = 0x08
)

// 9.11.3.10 ABBA
func (ue *UE) decABBA(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.AuthParam.abba = (*pdu)[:length]
	*pdu = (*pdu)[length:]

	ue.dprint("ABBA")
	ue.dprinti("Length: %d", length)
	ue.dprinti("Value: 0x%02x", ue.AuthParam.abba)

	return
}

// 9.11.3.12 Additional 5G security information
func (ue *UE) decAdditional5GSecInfo(pdu *[]byte) {

	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	if length != 1 {
		ue.dprinti("unexpected length: %d", length)
		*pdu = (*pdu)[length:]
		return
	}

	ue.indent++
	val := int((*pdu)[0])
	ue.dprint("value: 0x%x", val)

	not := ""
	if val&0x01 == 0x00 {
		not = "not "
	}
	ue.dprinti("KAMF derivation is %srequired", not)

	ue.recv.flag.rinmr = true
	not = ""
	if val&0x02 == 0x00 {
		not = "not "
		ue.recv.flag.rinmr = false
	}
	ue.dprinti("Retransmission of the initial NAS message %srequested", not)

	ue.indent--
	*pdu = (*pdu)[length:]
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
	abba     []byte
	RESstar  []byte
	Kausf    []byte
	Kseaf    []byte
	Kamf     []byte
	Kenc     []byte
	Kint     []byte
}

func (ue *UE) decAuthParamAUTN(pdu *[]byte) {

	autnlen := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	ue.AuthParam.autn = (*pdu)[:autnlen]
	*pdu = (*pdu)[autnlen:]
	ue.dprinti("AUTN: %02x", ue.AuthParam.autn)
	ue.AuthParam.seqxorak = ue.AuthParam.autn[:6]
	ue.AuthParam.amf = ue.AuthParam.autn[6:8]
	ue.AuthParam.mac = ue.AuthParam.autn[8:16]
	ue.dprinti("SEQ xor AK: %02x", ue.AuthParam.seqxorak)
	ue.dprinti("AMF       : %02x", ue.AuthParam.amf)
	ue.dprinti("MAC       : %02x", ue.AuthParam.mac)

	return
}

// 9.11.3.16 Authentication parameter RAND
// TS 24.008 10.5.3.1 Authentication parameter RAND
func (ue *UE) decAuthParamRAND(pdu *[]byte) {

	const randlen = 16
	ue.AuthParam.rand = (*pdu)[:randlen]
	*pdu = (*pdu)[randlen:]
	ue.dprinti("RAND: 0x%02x", ue.AuthParam.rand)
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

	//	data := new(bytes.Buffer)
	//	binary.Write(data, binary.BigEndian, ue.encAuthParamRes())
	//	pdu = append(pdu, data.Bytes()...)

	return
}

// 9.11.3.28 IMEISV request
// TS 24.008 9.11.3.28 IMEISV request
func (ue *UE) decIMEISVRequest(pdu *[]byte) {

	val := int((*pdu)[0])
	ue.dprinti("value: 0x%x", val)
	*pdu = (*pdu)[1:]
	return
}

// 9.11.3.32 NAS key set identifier
const (
	KeySetIdentityNoKeyIsAvailable          = 0x07
	KeySetIdentityFlagMappedSecurityContext = 0x08
)

func (ue *UE) decngKSI(pdu *[]byte) {

	ksi := int((*pdu)[0])
	ue.dprint("ngKSI: 0x%x", ksi)
	*pdu = (*pdu)[1:]

	return
}

// 9.11.3.33 NAS message container
func (ue *UE) encNASMessageContainer(iei bool, msgType int) (pdu []byte) {

	if iei == true {
		pdu = append(pdu, []byte{ieiNASMessageContainer}...)
	}

	tmp := []byte{}
	switch msgType {
	case MessageTypeRegistrationRequest:
		tmp = ue.MakeRegistrationRequest()
	default:
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(tmp)))

	pdu = append(pdu, length...)
	pdu = append(pdu, tmp...)

	return
}

// 9.11.3.34 NAS security algorithms
func (ue *UE) decNASSecurityAlgorithms(pdu *[]byte) {

	ue.dprint("NAS Security Algorithms")
	alg := (*pdu)[:1]
	ue.dprinti(" NAS Security Algorithms: 0x%02x", alg)
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

	ue.dprint("Replayed UE Security Capability")
	length := int((*pdu)[0])
	*pdu = (*pdu)[1:]

	cap := (*pdu)[:length]
	ue.dprinti("Capability: 0x%02x", cap)
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

// TS 33.401
// A.2 KASME derivation function
/*
func (ue *UE) ComputeKasme(ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x10}
	s = append(s, fc...)

	p0 := encPLMN(ue.MCC, ue.MNC)
	s = append(s, p0[:]...)
	ue.dprint("ComputeKasme: P0:%x", p0)

	l0 := []byte{0x00, 0x03}
	s = append(s, l0...)

	p1 := ue.AuthParam.seqxorak
	s = append(s, p1...)
	ue.dprint("ComputeKasme: P1:%x", p1)

	l1 := []byte{0x00, 0x06}
	s = append(s, l1...)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	ue.AuthParam.Kasme = mac.Sum(nil)

	return
}

// TS 33.401
// A.7 Algorithm key derivation functions
func (ue *UE) ComputeEPCAlgKey() {

	var cipher byte = 0x00
	Senc := []byte{0x15, 0x01, 0x00, 0x01, cipher, 0x00, 0x01}
	Menc := hmac.New(sha256.New, ue.AuthParam.Kasme)
	Menc.Write(Senc)
	ue.AuthParam.KencEPC = Menc.Sum(nil)

	var integrity byte = 0x02 // 128-EIA2 see TS 33.401 5.1.4.2
	Sint := []byte{0x15, 0x02, 0x00, 0x01, integrity, 0x00, 0x01}
	Mint := hmac.New(sha256.New, ue.AuthParam.Kasme)
	Mint.Write(Sint)
	ue.AuthParam.KintEPC = Mint.Sum(nil)

	// For an algorithm key of length n bits, where n is less or equal to 256,
 	// the n least significant bits of the 256 bits of the KDF output shall be
	// used as the algorithm key.

	n := len(ue.AuthParam.Kenc)
	ue.AuthParam.KencEPC = ue.AuthParam.KencEPC[n-16:]
	ue.AuthParam.KintEPC = ue.AuthParam.KintEPC[n-16:]
	return
}
*/

// TS 33.501
// A.2 KAUSF derivation function
func (ue *UE) ComputeKausf(ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x6a}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	ue.dprint("ComputeKausf: serving network(%d): %s", len(p0), p0str)

	p1 := ue.AuthParam.seqxorak
	s = append(s, p1...)

	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(p1)))
	s = append(s, l1...)
	ue.dprint("ComputeKausf: SEQ xor AK(%d): %x", len(p1), p1)

	k := append(ck, ik...)

	mac := hmac.New(sha256.New, k)
	mac.Write(s)
	ue.AuthParam.Kausf = mac.Sum(nil)

	return
}

// TS 33.501
// A.4 RES* and XRES* derivation function
func (ue *UE) ComputeRESstar(rand, res, ck, ik []byte) {

	s := []byte{}
	fc := []byte{0x6b}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
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
	resstar := mac.Sum(nil)

	/*
	 * The (X)RES* is identified with the 128 least significant bits of the
	 * output of the KDF.
	 */
	n := len(resstar)
	ue.AuthParam.RESstar = resstar[n-16:]

	return
}

// TS 33.501
// A.6 KSEAF derivation function
func (ue *UE) ComputeKseaf() {

	s := []byte{}
	fc := []byte{0x6c}
	s = append(s, fc...)

	p0str := fmt.Sprintf("5G:mnc%03d.mcc%03d.3gppnetwork.org", ue.MNC, ue.MCC)
	p0 := []byte(p0str)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	ue.dprint("ComputeKseaf: serving network(%d): %s", len(p0), p0str)

	mac := hmac.New(sha256.New, ue.AuthParam.Kausf)
	mac.Write(s)
	ue.AuthParam.Kseaf = mac.Sum(nil)

	return
}

// TS 33.501
// A.7 KAMF derivation function
func (ue *UE) ComputeKamf() {

	s := []byte{}
	fc := []byte{0x6d}
	s = append(s, fc...)

	supi := fmt.Sprintf("imsi-%d%d%s", ue.MCC, ue.MNC, ue.MSIN)
	p0 := []byte(supi)
	s = append(s, p0...)

	l0 := make([]byte, 2)
	binary.BigEndian.PutUint16(l0, uint16(len(p0)))
	s = append(s, l0...)
	ue.dprint("ComputeKamf: supi(%d): %s", len(p0), supi)

	p1 := ue.AuthParam.abba
	s = append(s, p1...)

	l1 := make([]byte, 2)
	binary.BigEndian.PutUint16(l1, uint16(len(p1)))
	s = append(s, l1...)
	ue.dprint("ComputeKamf: abba(%d): %x", len(p1), p1)

	ue.dprint("ComputeKamf: S: %x", s)
	ue.dprint("ComputeKamf: Kseaf: %x", ue.AuthParam.Kseaf)

	mac := hmac.New(sha256.New, ue.AuthParam.Kseaf)
	mac.Write(s)
	ue.AuthParam.Kamf = mac.Sum(nil)

	return
}

// TS 33.501
// A.8 Algorithm key derivation functions
func (ue *UE) ComputeAlgKey() {

	var cipher byte = 0x00
	Senc := []byte{0x69, 0x01, 0x00, 0x01, cipher, 0x00, 0x01}
	Menc := hmac.New(sha256.New, ue.AuthParam.Kamf)
	Menc.Write(Senc)
	ue.AuthParam.Kenc = Menc.Sum(nil)

	var integrity byte = 0x02 // 128-EIA2 see TS 33.401 5.1.4.2
	Sint := []byte{0x69, 0x02, 0x00, 0x01, integrity, 0x00, 0x01}
	Mint := hmac.New(sha256.New, ue.AuthParam.Kamf)
	Mint.Write(Sint)
	ue.AuthParam.Kint = Mint.Sum(nil)

	// For an algorithm key of length n bits, where n is less or equal to 256,
	// the n least significant bits of the 256 bits of the KDF output shall be
	// used as the algorithm key.
	n := len(ue.AuthParam.Kenc)
	ue.AuthParam.Kenc = ue.AuthParam.Kenc[n-16:]
	ue.AuthParam.Kint = ue.AuthParam.Kint[n-16:]
	return
}

func (ue *UE) ComputeMAC(bearer uint8, dir uint8, pdu *[]byte) (mac []byte) {

	m := []byte{}

	tmp := make([]byte, 4)
	ue.DLCount = uint32((*pdu)[0])
	binary.BigEndian.PutUint32(tmp, ue.DLCount)
	m = append(m, tmp...)

	tmp = make([]byte, 1)
	tmp[0] = (bearer << 3) | (dir << 2) // bearer is 5 bit field.
	m = append(m, tmp...)
	m = append(m, []byte{0, 0, 0}...) // 24 bit padding
	m = append(m, *pdu...)

	block, _ := aes.NewCipher(ue.AuthParam.Kint)
	mac, _ = cmac.Sum(m, block, 16)
	mac = mac[:4]

	return
}

//-----
func (ue *UE) dprint(format string, v ...interface{}) {
	indent := strings.Repeat("  ", ue.indent)
	fmt.Printf(indent+format+"\n", v...)
	return
}

func (ue *UE) dprinti(format string, v ...interface{}) {
	ue.indent++
	ue.dprint(format, v...)
	ue.indent--
}
