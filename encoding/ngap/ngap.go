// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package ngap is implementation for NG Application Protocol (NGAP)
// in the 5GS Sytem.
// document version: 3GPP TS 38.413 v16.0.0 (2019-12)

// TODO: implimenting generic PER decoder.

package ngap

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/bits"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/hhorai/gnbsim/encoding/gtp"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/per"
)

const (
	reject = iota
	ignore
	notify
)

const (
	idAllowedNSSAI              = 0
	idAMFName                   = 1
	idAMFUENGAPID               = 10
	idDefaultPagingDRX          = 21
	idGlobalRANNodeID           = 27
	idGUAMI                     = 28
	idMaskedIMEISV              = 34
	idMobilityRestrictionList   = 36
	idNASPDU                    = 38
	idPDUSessResSetupListCxtReq = 71
	idPDUSessResSetupListSUReq  = 74
	idPDUSessResSetupListSURes  = 75
	idPLMNSupportList           = 80
	idRANUENGAPID               = 85
	idRelativeAMFCapacity       = 86
	idRRCEstablishmentCause     = 90
	idSecurityKey               = 94
	idServedGUAMIList           = 96
	idSupportedTAList           = 102
	idUEContextRequest          = 112
	idUESecurityCapabilities    = 119
	idUserLocationInformation   = 121
	idPDUSessionType            = 134
	idQosFlowSetupRequestList   = 136
	idULNGUUPTNLInformation     = 139
)

var ieID = map[int]string{
	idAllowedNSSAI:              "id-AllowedNSSAI",
	idAMFName:                   "id-AMFName",
	idAMFUENGAPID:               "id-AMF-UE-NGAP-ID",
	idDefaultPagingDRX:          "",
	idGlobalRANNodeID:           "",
	idGUAMI:                     "id-GUAMI",
	idMaskedIMEISV:              "id-MaskedIMEISV",
	idMobilityRestrictionList:   "id-MobilityRestrictionList",
	idNASPDU:                    "id-NAS-PDU",
	idPDUSessResSetupListCxtReq: "id-PDUSessionResourceSetupListCxtReq",
	idPDUSessResSetupListSUReq:  "id-PDUSessionResourceSetupListSUReq",
	idPDUSessResSetupListSURes:  "id-PDUSessionResourceSetupListSURes",
	idPLMNSupportList:           "id-PLMNSupportList",
	idRANUENGAPID:               "id-RAN-UE-NGAP-ID",
	idRelativeAMFCapacity:       "id-RelativeAMFCapacity",
	idRRCEstablishmentCause:     "",
	idSecurityKey:               "id-SecurityKey",
	idServedGUAMIList:           "id-ServedGUAMIList",
	idSupportedTAList:           "",
	idUEContextRequest:          "",
	idUESecurityCapabilities:    "id-UESecurityCapabilities",
	idUserLocationInformation:   "",
	idPDUSessionType:            "id-PDUSessionType",
	idQosFlowSetupRequestList:   "id-QosFlowSetupRequestList",
	idULNGUUPTNLInformation:     "id-UL-NGU-UP-TNLInformation",
}

type GNB struct {
	GlobalGNBID     GlobalGNBID
	SupportedTAList []SupportedTA
	PagingDRX       string
	RANUENGAPID     uint32
	ULInfoNR        UserLocationInformationNR
	NGAPPeerAddr    string
	GTPuLocalAddr   string
	GTPuIFname      string
	GTPuTEID        uint32
	UE              nas.UE // base parameter to be used for each UE

	Recv struct {
		GTPuPeerAddr net.IP
		GTPuPeerTEID uint32
	}

	Camper []*Camper

	DecodeError error
	dbgLevel    int
	indent      int // indent for debug print.
}

type Camper struct {
	GNB          *GNB // camped in this gNB
	UE           *nas.UE
	GTPu	     *gtp.GTP
	AmfId        uint32
	RanId        uint32
	RRCstate     int
	PDUSessionID uint8
	QosFlowID    uint8

	SendMsg *[]byte
	RecvMsg *[]byte

	camperType int
}

const (
	CAMPER_TYPE_TEMPORARY = 0
	CAMPER_TYPE_NORMAL    = 1
)

func NewNGAP(filename string) (p *GNB) {

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var gnb GNB
	p = &gnb
	json.Unmarshal(bytes, p)

	p.dbgLevel = 0

	return
}

var RanUeNgapId uint32 = 0

func (gnb *GNB) CampIn(ue *nas.UE) {
	var obj Camper
	c := &obj
	c.GNB = gnb
	c.UE = ue
	c.RanId = RanUeNgapId
	RanUeNgapId++
	c.camperType = CAMPER_TYPE_NORMAL
	gnb.Camper = append(gnb.Camper, c)
}

func (gnb *GNB) LookupCamperByUE(ue *nas.UE) (c *Camper) {

	for _, c = range gnb.Camper {
		if ue == c.UE {
			return
		}
	}
	c = nil
	return
}

func (gnb *GNB) LookupCamperByRanId(id uint32) (c *Camper) {

	for _, c = range gnb.Camper {
		if c.RanId == id {
			return
		}
	}
	c = nil
	return
}

func (gnb *GNB) SendtoUE(c *Camper, pdu *[]byte) {

	if pdu != nil {
		c.UE.SetIndent(gnb.indent)
		c.UE.Receive(pdu)
	}
	return
}

func (gnb *GNB) RecvfromUE(ue *nas.UE, pdu *[]byte) {
	c := gnb.LookupCamperByUE(ue)
	c.RecvMsg = pdu
	return
}

func (gnb *GNB) Decode(pdu *[]byte) {

	gnb.DecodeError = nil
	_, procCode, _, _ := decNgapPdu(pdu)

	str := procCodeStr[procCode]
	if str == "" {
		log.Printf("unsupported procedure: %d", procCode)
	}
	gnb.dprint("Procedure Code: %s (%d)", str, procCode)

	length, _ := per.DecLengthDeterminant(pdu, 0)
	gnb.dprint("PDU Length: %d", length)

	c, err := gnb.decProtocolIEContainer(nil, pdu)

	gnb.DecodeError = err

	if c != nil && c.UE.DecodeError != nil {
		gnb.DecodeError = c.UE.DecodeError
	}

	return
}

// 9.2 Message Functional Definition and Content
// 9.2.1 PDU Session Management Messages
// 9.2.1.1 PDU SESSION RESOURCE SETUP REQUEST
/*
PDUSessionResourceSetupRequest ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {PDUSessionResourceSetupRequestIEs} },
    ...
}

PDUSessionResourceSetupRequestIEs NGAP-PROTOCOL-IES ::= {
    { ID id-AMF-UE-NGAP-ID                          CRITICALITY reject  TYPE AMF-UE-NGAP-ID                             PRESENCE mandatory  }|
    { ID id-RAN-UE-NGAP-ID                          CRITICALITY reject  TYPE RAN-UE-NGAP-ID                             PRESENCE mandatory  }|
    { ID id-RANPagingPriority                       CRITICALITY ignore  TYPE RANPagingPriority                          PRESENCE optional       }|
    { ID id-NAS-PDU                                 CRITICALITY reject  TYPE NAS-PDU                                    PRESENCE optional       }|
    { ID id-PDUSessionResourceSetupListSUReq        CRITICALITY reject  TYPE PDUSessionResourceSetupListSUReq       PRESENCE mandatory  }|
    { ID id-UEAggregateMaximumBitRate               CRITICALITY ignore  TYPE UEAggregateMaximumBitRate              PRESENCE optional       },
    ...
}

PDUSessionResourceSetupListSUReq ::= SEQUENCE (SIZE(1..maxnoofPDUSessions)) OF PDUSessionResourceSetupItemSUReq

PDUSessionResourceSetupItemSUReq ::= SEQUENCE {
    pDUSessionID                                PDUSessionID,
    pDUSessionNAS-PDU                           NAS-PDU                                             OPTIONAL,
    s-NSSAI                                     S-NSSAI,
    pDUSessionResourceSetupRequestTransfer      OCTET STRING (CONTAINING PDUSessionResourceSetupRequestTransfer),
    iE-Extensions       ProtocolExtensionContainer { {PDUSessionResourceSetupItemSUReq-ExtIEs} }    OPTIONAL,
    ...
}

    maxnoofPDUSessions                  INTEGER ::= 256
*/

func (gnb *GNB) decPDUSessionResourceSetupListSUReq(
	c *Camper, pdu *[]byte, length int) {

	seqNum := int(readPduByte(pdu)) + 1
	gnb.dprint("number of sequence: %d", seqNum)

	for i := 0; i < seqNum; i++ {
		seq := readPduByte(pdu)
		gnb.decPDUSessionID(c, pdu)

		seq <<= 1 // skip extension marker

		option := false
		option = (seq & 0x80) != 0
		if option {
			gnb.decNASPDU(c, pdu)
		}
		gnb.decSNSSAI(pdu)
		gnb.decPDUSessionResourceSetupRequestTransfer(c, pdu)
	}

	return
}

// 9.2.1.2 PDU SESSION RESOURCE SETUP RESPONSE
/*
PDUSessionResourceSetupResponse ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {PDUSessionResourceSetupResponseIEs} },
    ...
}

PDUSessionResourceSetupResponseIEs NGAP-PROTOCOL-IES ::= {
    { ID id-AMF-UE-NGAP-ID                              CRITICALITY ignore  TYPE AMF-UE-NGAP-ID                                         PRESENCE mandatory  }|
    { ID id-RAN-UE-NGAP-ID                              CRITICALITY ignore  TYPE RAN-UE-NGAP-ID                                         PRESENCE mandatory  }|
    { ID id-PDUSessionResourceSetupListSURes            CRITICALITY ignore  TYPE PDUSessionResourceSetupListSURes               PRESENCE optional       }|
    { ID id-PDUSessionResourceFailedToSetupListSURes    CRITICALITY ignore  TYPE PDUSessionResourceFailedToSetupListSURes       PRESENCE optional       }|
    { ID id-CriticalityDiagnostics                      CRITICALITY ignore  TYPE CriticalityDiagnostics                             PRESENCE optional       },
    ...
}
*/
func (gnb *GNB) MakePDUSessionResourceSetupResponse(ue *nas.UE) (pdu []byte) {

	c := gnb.LookupCamperByUE(ue)

	pdu = encNgapPdu(successfulOutcome, idPDUSessResSetup, reject)

	v := encProtocolIEContainer(3)

	tmp := gnb.encAMFUENGAPID(c)
	v = append(v, tmp...)

	tmp = gnb.encRANUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encPDUSessionResourceSetupListSURes(c)
	v = append(v, tmp...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)

	pdu = append(pdu, bf.Value...)
	pdu = append(pdu, v...)

	return
}

// PDU Session Resource Setup Response List is defined in
// 9.2.1.2 PDU SESSION RESOURCE SETUP RESPONSE
/*
maxnoofPDUSessions                  INTEGER ::= 256

PDUSessionResourceSetupListSURes ::= SEQUENCE (SIZE(1..maxnoofPDUSessions)) OF PDUSessionResourceSetupItemSURes

PDUSessionResourceSetupItemSURes ::= SEQUENCE {
    pDUSessionID                                            PDUSessionID,
    pDUSessionResourceSetupResponseTransfer                 OCTET STRING (CONTAINING PDUSessionResourceSetupResponseTransfer),
    iE-Extensions       ProtocolExtensionContainer { {PDUSessionResourceSetupItemSURes-ExtIEs} }    OPTIONAL,
    ...
}
*/
func (gnb *GNB) encPDUSessionResourceSetupListSURes(c *Camper) (v []byte) {

	head, _ := encProtocolIE(idPDUSessResSetupListSURes, ignore)

	_, v, _ = per.EncSequenceOf(1, 1, 256, false)
	bf, _ := per.EncSequence(true, 1, 0)
	v = append(v, bf.Value...)

	tmp := gnb.encPDUSessionID(c)
	v = append(v, tmp...)

	tmp = gnb.encPDUSessionResourceSetupResponseTransfer(c)
	bf, tmp, _ = per.EncOctetString(tmp, 0, 0, false)
	v = append(v, bf.Value...)
	v = append(v, tmp...)

	bf, _ = per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)

	return
}

// 9.2.2.2 INITIAL CONTEXT SETUP RESPONSE
/*
InitialContextSetupResponse ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {InitialContextSetupResponseIEs} },
    ...
}

InitialContextSetupResponseIEs NGAP-PROTOCOL-IES ::= {
    { ID id-AMF-UE-NGAP-ID                              CRITICALITY ignore  TYPE AMF-UE-NGAP-ID                                 PRESENCE mandatory  }|
    { ID id-RAN-UE-NGAP-ID                              CRITICALITY ignore  TYPE RAN-UE-NGAP-ID                                 PRESENCE mandatory  }|
    { ID id-PDUSessionResourceSetupListCxtRes           CRITICALITY ignore  TYPE PDUSessionResourceSetupListCxtRes              PRESENCE optional       }|
    { ID id-PDUSessionResourceFailedToSetupListCxtRes   CRITICALITY ignore  TYPE PDUSessionResourceFailedToSetupListCxtRes      PRESENCE optional       }|
    { ID id-CriticalityDiagnostics                      CRITICALITY ignore  TYPE CriticalityDiagnostics                         PRESENCE optional       },
    ...
}
*/
func (gnb *GNB) MakeInitialContextSetupResponse(ue *nas.UE) (pdu []byte) {

	c := gnb.LookupCamperByUE(ue)

	pdu = encNgapPdu(successfulOutcome, idInitialContextSetup, reject)

	v := encProtocolIEContainer(2)

	tmp := gnb.encAMFUENGAPID(c)
	v = append(v, tmp...)

	tmp = gnb.encRANUENGAPID()
	v = append(v, tmp...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)

	pdu = append(pdu, bf.Value...)
	pdu = append(pdu, v...)

	return
}

// 9.2.5.1 INITIAL UE MESSAGE
/*
InitialUEMessage ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {InitialUEMessage-IEs} },
    ...
}

InitialUEMessage-IEs NGAP-PROTOCOL-IES ::= {
    { ID id-RAN-UE-NGAP-ID              CRITICALITY reject  TYPE RAN-UE-NGAP-ID             PRESENCE mandatory  }|
    { ID id-NAS-PDU                     CRITICALITY reject  TYPE NAS-PDU                    PRESENCE mandatory  }|
    { ID id-UserLocationInformation     CRITICALITY reject  TYPE UserLocationInformation    PRESENCE mandatory  }|
    { ID id-RRCEstablishmentCause       CRITICALITY ignore  TYPE RRCEstablishmentCause      PRESENCE mandatory  }|
    { ID id-FiveG-S-TMSI                CRITICALITY reject  TYPE FiveG-S-TMSI               PRESENCE optional   }|
    { ID id-AMFSetID                    CRITICALITY ignore  TYPE AMFSetID                   PRESENCE optional   }|
    { ID id-UEContextRequest            CRITICALITY ignore  TYPE UEContextRequest           PRESENCE optional   }|
    { ID id-AllowedNSSAI                CRITICALITY reject  TYPE AllowedNSSAI               PRESENCE optional   },
    ...
}
*/
func (gnb *GNB) MakeInitialUEMessage(ue *nas.UE) (pdu []byte) {

	c := gnb.LookupCamperByUE(ue)

	pdu = encNgapPdu(initiatingMessage, idInitialUEMessage, ignore)

	v := encProtocolIEContainer(5)

	tmp := gnb.encRANUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encNASPDU(c)
	v = append(v, tmp...)

	tmp, _ = gnb.encUserLocationInformation()
	v = append(v, tmp...)

	tmp, _ = gnb.encRRCEstablishmentCause(rrcMoSignalling)
	v = append(v, tmp...)

	tmp, _ = gnb.encUEContextRequest()
	v = append(v, tmp...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)

	pdu = append(pdu, bf.Value...)
	pdu = append(pdu, v...)

	return
}

// 9.2.5.2 DOWNLINK NAS TRANSPORT
/*
DownlinkNASTransport ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {DownlinkNASTransport-IEs} },
    ...
}

DownlinkNASTransport-IEs NGAP-PROTOCOL-IES ::= {
    { ID id-AMF-UE-NGAP-ID             CRITICALITY reject  TYPE AMF-UE-NGAP-ID            PRESENCE mandatory }|
    { ID id-RAN-UE-NGAP-ID             CRITICALITY reject  TYPE RAN-UE-NGAP-ID            PRESENCE mandatory }|
    { ID id-OldAMF                     CRITICALITY reject  TYPE AMFName                   PRESENCE optional  }|
    { ID id-RANPagingPriority          CRITICALITY ignore  TYPE RANPagingPriority         PRESENCE optional  }|
    { ID id-NAS-PDU                    CRITICALITY reject  TYPE NAS-PDU                   PRESENCE mandatory }|
    { ID id-MobilityRestrictionList    CRITICALITY ignore  TYPE MobilityRestrictionList   PRESENCE optional  }|
    { ID id-IndexToRFSP                CRITICALITY ignore  TYPE IndexToRFSP               PRESENCE optional  }|
    { ID id-UEAggregateMaximumBitRate  CRITICALITY ignore  TYPE UEAggregateMaximumBitRate PRESENCE optional  }|
    { ID id-AllowedNSSAI               CRITICALITY reject  TYPE AllowedNSSAI              PRESENCE optional  },
    ...
}
*/

// 9.2.5.3 UPLINK NAS TRANSPORT
/*
UplinkNASTransport ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container    { {UplinkNASTransport-IEs} },
    ...
}

UplinkNASTransport-IEs NGAP-PROTOCOL-IES ::= {
    { ID id-AMF-UE-NGAP-ID              CRITICALITY reject  TYPE AMF-UE-NGAP-ID                 PRESENCE mandatory  }|
    { ID id-RAN-UE-NGAP-ID              CRITICALITY reject  TYPE RAN-UE-NGAP-ID                 PRESENCE mandatory  }|
    { ID id-NAS-PDU                     CRITICALITY reject  TYPE NAS-PDU                        PRESENCE mandatory  }|
    { ID id-UserLocationInformation     CRITICALITY ignore  TYPE UserLocationInformation        PRESENCE mandatory  },
    ...
}
*/
func (gnb *GNB) MakeUplinkNASTransport(ue *nas.UE) (pdu []byte) {

	c := gnb.LookupCamperByUE(ue)

	pdu = encNgapPdu(initiatingMessage, idUplinkNASTransport, ignore)

	v := encProtocolIEContainer(4)

	tmp := gnb.encAMFUENGAPID(c)
	v = append(v, tmp...)

	tmp = gnb.encRANUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encNASPDU(c)
	v = append(v, tmp...)

	tmp, _ = gnb.encUserLocationInformation()
	v = append(v, tmp...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)

	pdu = append(pdu, bf.Value...)
	pdu = append(pdu, v...)

	return
}

// 9.2.6.1 NG SETUP REQUEST
/*
NGSetupRequest ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {NGSetupRequestIEs} },
    ...
}

NGSetupRequestIEs NGAP-PROTOCOL-IES ::= {
    { ID id-GlobalRANNodeID         CRITICALITY reject  TYPE GlobalRANNodeID        PRESENCE mandatory }|
    { ID id-RANNodeName             CRITICALITY ignore  TYPE RANNodeName            PRESENCE optional  }|
    { ID id-SupportedTAList         CRITICALITY reject  TYPE SupportedTAList        PRESENCE mandatory }|
    { ID id-DefaultPagingDRX        CRITICALITY ignore  TYPE PagingDRX              PRESENCE mandatory }|
    { ID id-UERetentionInformation  CRITICALITY ignore  TYPE UERetentionInformation PRESENCE optional  },
    ...
}
*/
func (gnb *GNB) MakeNGSetupRequest() (pdu []byte) {

	pdu = encNgapPdu(initiatingMessage, idNGSetup, reject)

	v := encProtocolIEContainer(3)

	tmp, _ := gnb.encGlobalRANNodeID(&gnb.GlobalGNBID)
	v = append(v, tmp...)

	tmp, _ = gnb.encSupportedTAList(&gnb.SupportedTAList)
	v = append(v, tmp...)

	tmp, _ = gnb.encPagingDRX(gnb.PagingDRX)
	v = append(v, tmp...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)

	pdu = append(pdu, bf.Value...)
	pdu = append(pdu, v...)

	return
}

// 9.3.1.1 Message Type
/*
ProcedureCode ::= INTEGER (0..255)

NGAP-PDU ::= CHOICE {
    initiatingMessage           InitiatingMessage,
    successfulOutcome           SuccessfulOutcome,
    unsuccessfulOutcome         UnsuccessfulOutcome,
    ...
}

Criticality   ::= ENUMERATED { reject, ignore, notify }

InitiatingMessage ::= SEQUENCE {
    procedureCode   NGAP-ELEMENTARY-PROCEDURE.&procedureCode     ({NGAP-ELEMENTARY-PROCEDURES}),
    criticality     NGAP-ELEMENTARY-PROCEDURE.&criticality       ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode}),
    value           NGAP-ELEMENTARY-PROCEDURE.&InitiatingMessage ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode})
}

SuccessfulOutcome ::= SEQUENCE {
    procedureCode   NGAP-ELEMENTARY-PROCEDURE.&procedureCode        ({NGAP-ELEMENTARY-PROCEDURES}),
    criticality     NGAP-ELEMENTARY-PROCEDURE.&criticality          ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode}),
    value           NGAP-ELEMENTARY-PROCEDURE.&SuccessfulOutcome    ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode})
}

UnsuccessfulOutcome ::= SEQUENCE {
    procedureCode   NGAP-ELEMENTARY-PROCEDURE.&procedureCode        ({NGAP-ELEMENTARY-PROCEDURES}),
    criticality     NGAP-ELEMENTARY-PROCEDURE.&criticality          ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode}),
    value           NGAP-ELEMENTARY-PROCEDURE.&UnsuccessfulOutcome  ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode})
}
*/

const (
	idDownlinkNASTransport = 4
	idInitialContextSetup  = 14
	idInitialUEMessage     = 15
	idNGSetup              = 21
	idPDUSessResSetup      = 29
	idUplinkNASTransport   = 46
)

var procCodeStr = map[int]string{
	idDownlinkNASTransport: "id-DownlinkNASTransport",
	idInitialContextSetup:  "id-InitialContextSetup",
	idInitialUEMessage:     "id-InitialUEMessage",
	idNGSetup:              "id-NGSetup",
	idPDUSessResSetup:      "id-PDUSessionResourceSetup",
	idUplinkNASTransport:   "id-UplinkNASTransport",
}

const (
	initiatingMessage = iota
	successfulOutcome
	unsuccessfulOutcome
)

func encNgapPdu(pduType int, procCode int, criticality int) (pdu []byte) {
	b, _, _ := per.EncChoice(pduType, 0, 2, true)
	_, v, _ := per.EncInteger(int64(procCode), 0, 255, false)
	pdu = append(b.Value, v...)
	b, _, _ = per.EncEnumerated(uint(criticality), 0, 2, false)
	pdu = append(pdu, b.Value...)

	return
}

func decNgapPdu(pdu *[]byte) (
	pduType int, procCode int, criticality int, err error) {

	if len(*pdu) < 3 {
		err = fmt.Errorf("remaining pdu length is too short.")
		return
	}

	readPduByte(pdu) // skip pduType
	procCode = int(readPduByte(pdu))
	readPduByte(pdu) // skip criticality

	return
}

/*
ProtocolIE-Container {NGAP-PROTOCOL-IES : IEsSetParam} ::=
    SEQUENCE (SIZE (0..maxProtocolIEs)) OF
    ProtocolIE-Field {{IEsSetParam}}

maxProtocolIEs                          INTEGER ::= 65535
*/
func encProtocolIEContainer(num uint) (container []byte) {
	const maxProtocolIEs = 65535
	b, _ := per.EncSequence(true, 0, 0)
	_, v, _ := per.EncSequenceOf(num, 0, maxProtocolIEs, false)

	container = append(b.Value, v...)

	return
}

func (gnb *GNB) decProtocolIEContainer(c *Camper, pdu *[]byte) (c2 *Camper, err error) {

	if len(*pdu) < 3 {
		err = fmt.Errorf("remaining pdu length(%d) is too short. expect > %d",
			len(*pdu), 3)
		return
	}

	readPduByte(pdu) // skip sequence
	num := int(readPduUint16(pdu))
	gnb.dprint("Protocol IEs: %d items", num)

	for idx := 0; idx < num; idx++ {
		gnb.indent++
		gnb.dprint("Item %d", idx)
		gnb.indent++
		c, err = gnb.decProtocolIE(c, pdu)
		gnb.indent -= 2
	}
	c2 = c
	return
}

/*
ProtocolIE-ID       ::= INTEGER (0..65535)

ProtocolIE-Field {NGAP-PROTOCOL-IES : IEsSetParam} ::= SEQUENCE {
    id              NGAP-PROTOCOL-IES.&id               ({IEsSetParam}),
    criticality     NGAP-PROTOCOL-IES.&criticality      ({IEsSetParam}{@id}),
    value           NGAP-PROTOCOL-IES.&Value            ({IEsSetParam}{@id})
}
*/
func encProtocolIE(id int64, criticality uint) (v []byte, err error) {

	_, v, _ = per.EncInteger(id, 0, 65535, false)
	bf, _, _ := per.EncEnumerated(criticality, 0, 2, false)
	v = append(v, bf.Value...)

	return
}

func (gnb *GNB) decProtocolIE(c *Camper, pdu *[]byte) (c2 *Camper, err error) {

	if c != nil {
		c2 = c
	}

	if len(*pdu) < 2 {
		err = fmt.Errorf("remaining pdu length(%d) is too short. expect > %d",
			len(*pdu), 2)
		return
	}

	id := int(readPduUint16(pdu))
	if ieID[id] == "" {
		log.Printf("Unsupported Protocol IE: %d", id)
	}

	gnb.dprint("Protocol IE: %s (%d)", ieID[id], id)
	gnb.indent++

	readPduByte(pdu) // skip ciritcality

	length := int(readPduByte(pdu))
	gnb.dprint("IE length: %d", length)
	gnb.indent++

	/*
	if c == nil {
		fmt.Printf("pointer to camper is missing for %d\n", id)
	} else if c.camperType == CAMPER_TYPE_TEMPORARY {
		fmt.Printf("pointer to camper is temporary for %d\n", id)
	} else {
		fmt.Printf("pointer to camper is valid for %d\n", id)
	}
	*/

	switch id {
	case idAMFUENGAPID: //10
		c2, err = gnb.decAMFUENGAPID(pdu, length)
	case idNASPDU: // 38
		gnb.decNASPDU(c, pdu)
	case idPDUSessResSetupListCxtReq: // 71
		gnb.decPDUSessionResourceSetupListCtxReq(c, pdu, length)
	case idPDUSessResSetupListSUReq: // 74
		gnb.decPDUSessionResourceSetupListSUReq(c, pdu, length)
	case idRANUENGAPID: // 85
		c2, err = gnb.decRANUENGAPID(c, pdu, length)
	case idPDUSessionType: // 134
		gnb.decPDUSessionType(pdu, length)
	case idQosFlowSetupRequestList: // 136
		gnb.decQosFlowSetupRequestList(c, pdu, length)
	case idULNGUUPTNLInformation: // 139
		gnb.decUPTransportLayerInformation(pdu, length)
	default:
		dump := readPduByteSlice(pdu, length)
		// gnb.DecodeError = fmt.Errorf("ngap: docoding id(%d) not supported yet.", id)
		gnb.dprint("decoding id(%d) not supported yet.", id)
		gnb.dprint("dump: %02x", dump)
	}
	gnb.indent -= 2
	return
}

// 9.3.1.5 Global RAN Node ID
/*
  It returns only GNB-ID for now.
   GlobalRANNodeID ::= CHOICE {
       globalGNB-ID        GlobalGNB-ID,
       globalNgENB-ID      GlobalNgENB-ID,
       globalN3IWF-ID      GlobalN3IWF-ID,
       choice-Extensions   ProtocolIE-SingleContainer { {GlobalRANNodeID-ExtIEs} }
   }
*/
const (
	globalGNB = iota
	globalNgGNB
	globalN3IWF
)

func (gnb *GNB) encGlobalRANNodeID(id *GlobalGNBID) (v []byte, err error) {

	head, err := encProtocolIE(idGlobalRANNodeID, reject)

	// NG-ENB and N3IWF are not implemented yet...
	b, _, _ := per.EncChoice(globalGNB, 0, 2, false)
	b2, v2 := gnb.encGlobalGNBID(id)
	b = per.MergeBitField(b, b2)
	pv := b.Value
	pv = append(pv, v2...)

	bf, _ := per.EncLengthDeterminant(len(pv), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, pv...)

	return
}

// 9.3.1.6 Global gNB ID
/*
   GlobalGNB-ID ::= SEQUENCE {
       pLMNIdentity        PLMNIdentity,
       gNB-ID              GNB-ID,
       iE-Extensions       ProtocolExtensionContainer { {GlobalGNB-ID-ExtIEs} } OPTIONAL,
       ...
   }
*/
type GlobalGNBID struct {
	MCC   uint16
	MNC   uint16
	GNBID uint32
}

func (gnb *GNB) encGlobalGNBID(id *GlobalGNBID) (
	b per.BitField, v []byte) {

	b, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(id.MCC, id.MNC)...)

	v2 := encGNBID(id.GNBID)
	v = append(v, v2...)
	return
}

/*
   GNB-ID ::= CHOICE {
       gNB-ID                  BIT STRING (SIZE(22..32)),
       choice-Extensions       ProtocolIE-SingleContainer { {GNB-ID-ExtIEs} }
   }
*/
const (
	minGNBIDSize = 22
	maxGNBIDSize = 32
)

func encGNBID(gnbid uint32) (v []byte) {

	const min = minGNBIDSize
	const max = maxGNBIDSize
	const extmark = false

	bitlen := bits.Len32(gnbid)
	if bitlen < min {
		bitlen = min
	}

	b, _, _ := per.EncChoice(0, 0, 1, false)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)

	pre, cont, _ := per.EncBitString(tmp, bitlen, min, max, extmark)

	b = per.MergeBitField(b, pre)
	v = append(b.Value, cont...)

	return
}

// 9.3.1.7 NR CGI
/*
NR-CGI ::= SEQUENCE {
    pLMNIdentity        PLMNIdentity,
    nRCellIdentity      NRCellIdentity,
    iE-Extensions       ProtocolExtensionContainer { {NR-CGI-ExtIEs} } OPTIONAL,
    ...
}
NRCellIdentity ::= BIT STRING (SIZE(36))
*/
type NRCGI struct {
	PLMN     PLMN
	NRCellID uint64
}

const (
	nrCellIDSize = 36
)

func (gnb *GNB) encNRCGI(nrcgi *NRCGI) (
	pre per.BitField, cont per.BitField, err error) {

	pre, _ = per.EncSequence(true, 1, 0)

	v := gnb.encPLMNIdentity(nrcgi.PLMN.MCC, nrcgi.PLMN.MNC)
	bitlen := len(v) * 8
	b2 := gnb.encNRCellIdentity(nrcgi.NRCellID)

	v = append(v, b2.Value...)
	cont.Value = v
	cont.Len = bitlen + b2.Len

	return
}

func (gnb *GNB) encNRCellIdentity(cellid uint64) (b per.BitField) {

	// The leftmost bits of the NR Cell Identity IE correspond to the gNB ID
	// (defined in subclause 9.3.1.6).
	gnbid := gnb.GlobalGNBID.GNBID
	gnbidlen := bits.Len32(gnbid)

	if gnbidlen < minGNBIDSize {
		gnbidlen = minGNBIDSize
	}

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)

	b.Value = tmp
	b.Len = gnbidlen
	b = per.ShiftLeftMost(b)

	cellidlen := nrCellIDSize - gnbidlen
	tmp = make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, cellid)

	var b2 per.BitField
	b2.Value = tmp
	b2.Len = cellidlen
	b2 = per.ShiftLeftMost(b2)

	b = per.MergeBitField(b, b2)
	return
}

// 9.3.1.12 QoS Flow Level QoS Parameters
/*
QosFlowLevelQosParameters ::= SEQUENCE {
    qosCharacteristics                  QosCharacteristics,
    allocationAndRetentionPriority      AllocationAndRetentionPriority,
    gBR-QosInformation                  GBR-QosInformation                                  OPTIONAL,
    reflectiveQosAttribute              ReflectiveQosAttribute                              OPTIONAL,
    additionalQosFlowInformation        AdditionalQosFlowInformation                        OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {QosFlowLevelQosParameters-ExtIEs} }   OPTIONAL,
    ...
}
*/
func (gnb *GNB) decQosFlowLevelQosParameters(item *per.BitField) {
	// 0000 0000
	// ^         extension marker
	//  ^^^ ^    optional bit
	//
	gnb.dprinti("Qos Flow Level Qos Prameters: not supported yet")
	gnb.decQosCharacteristics(item)
	gnb.decAllocationAndRetentionPriority(item)

	return
}

// 9.3.1.16 User Location Information
/*
UserLocationInformation ::= CHOICE {
    userLocationInformationEUTRA    UserLocationInformationEUTRA,
    userLocationInformationNR       UserLocationInformationNR,
    userLocationInformationN3IWF    UserLocationInformationN3IWF,
    choice-Extensions       ProtocolIE-SingleContainer { {UserLocationInformation-ExtIEs} }
}
*/
const (
	ULInfoEUTRA = iota
	ULInfoNR
	ULInfoN3IWF
)

func (gnb *GNB) encUserLocationInformation() (v []byte, err error) {
	head, err := encProtocolIE(idUserLocationInformation, ignore)

	// NG-ENB and N3IWF are not implemented yet...
	b, _, _ := per.EncChoice(ULInfoNR, 0, 2, false)

	b2, v := gnb.encUserLocationInformationNR(&gnb.ULInfoNR)
	b = per.MergeBitField(b, b2)
	pv := b.Value
	pv = append(pv, v...)

	bf, _ := per.EncLengthDeterminant(len(pv), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, pv...)

	return
}

/*
UserLocationInformationNR ::= SEQUENCE {
    nR-CGI              NR-CGI,
    tAI                 TAI,
    timeStamp           TimeStamp                                                           OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {UserLocationInformationNR-ExtIEs} }   OPTIONAL,
    ...
}
*/
type UserLocationInformationNR struct {
	NRCGI NRCGI
	TAI   TAI
}

func (gnb *GNB) encUserLocationInformationNR(info *UserLocationInformationNR) (
	b per.BitField, v []byte) {

	b, _ = per.EncSequence(true, 2, 0)

	pre, cont, _ := gnb.encNRCGI(&info.NRCGI)
	b = per.MergeBitField(b, pre)

	b2, v2, _ := gnb.encTAI(&info.TAI)
	cont = per.MergeBitField(cont, b2)

	v = cont.Value
	v = append(v, v2...)

	return
}

// 9.3.1.19 Allocation and Retention Priority
/*
AllocationAndRetentionPriority ::= SEQUENCE {
    priorityLevelARP                PriorityLevelARP,
    pre-emptionCapability           Pre-emptionCapability,
    pre-emptionVulnerability        Pre-emptionVulnerability,
    iE-Extensions       ProtocolExtensionContainer { {AllocationAndRetentionPriority-ExtIEs} } OPTIONAL,
    ...
}
*/
func (gnb *GNB) decAllocationAndRetentionPriority(item *per.BitField) {
	return
}

// 9.3.1.90 PagingDRX
/*
PagingDRX ::= ENUMERATED {
    v32,
    v64,
    v128,
    v256,
    ...
}
*/
func (gnb *GNB) encPagingDRX(drx string) (v []byte, err error) {

	head, err := encProtocolIE(idDefaultPagingDRX, ignore)

	var n uint = 0

	switch drx {
	case "v32":
		n = 0
	case "v64":
		n = 1
	case "v128":
		n = 2
	case "v256":
		n = 3
	default:
		gnb.dprint("encPagingDRX: no such DRX value(%s)", drx)
		return
	}

	b, _, _ := per.EncEnumerated(n, 0, 3, true)
	v = b.Value
	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)

	return
}

// 9.3.2.2 UP Transport Layer Information
/*
UPTransportLayerInformation ::= CHOICE {
    gTPTunnel               GTPTunnel,
    choice-Extensions       ProtocolIE-SingleContainer { {UPTransportLayerInformation-ExtIEs} }
}

GTPTunnel ::= SEQUENCE {
    transportLayerAddress       TransportLayerAddress,
    gTP-TEID                    GTP-TEID,
    iE-Extensions       ProtocolExtensionContainer { {GTPTunnel-ExtIEs} } OPTIONAL,
    ...
}
*/
func (gnb *GNB) encUPTransportLayerInformation(pre *per.BitField) (pdu []byte) {

	const gTPTunnel = 0
	bf, _, _ := per.EncChoice(gTPTunnel, 0, 1, false)
	if pre != nil { // has inherited preamble
		bf = per.MergeBitField(*pre, bf)
	}
	*pre = bf

	bf, _ = per.EncSequence(true, 1, 0)
	bf = per.MergeBitField(*pre, bf)
	*pre = bf

	tmp := gnb.encTransportLayerAddress(pre)
	pdu = append(pdu, tmp...)

	tmp = gnb.encGTPTEID()
	pdu = append(pdu, tmp...)

	return
}

func (gnb *GNB) decUPTransportLayerInformation(pdu *[]byte, length int) {

	var tli per.BitField
	tli.Value = readPduByteSlice(pdu, length)
	tli.Len = len(tli.Value) * 8
	gnb.dprint("dump: %02x", tli.Value)

	// TODO: generic per decoder.
	// 0000 0000
	// ^         choice
	//  ^        seq extension marker
	//   ^       option
	tli = per.ShiftLeft(tli, 3) // skip the above bits
	tli.Len -= 3

	gnb.decTransportLayerAddress(&tli)
	gnb.decGTPTEID(&tli.Value)

	return
}

// 9.3.2.4 Transport Layer Address
/*
TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))
*/
func (gnb *GNB) encTransportLayerAddress(pre *per.BitField) (pdu []byte) {

	const min = 1
	const max = 160
	const extmark = true

	addr := net.ParseIP(gnb.GTPuLocalAddr)
	ipv4addr := addr.To4()
	bitlen := net.IPv4len * 8
	bf, v, _ := per.EncBitString(ipv4addr, bitlen, min, max, extmark)

	if pre != nil { // has inherited preamble
		bf = per.MergeBitField(*pre, bf)
	}
	pdu = append(bf.Value, v...)

	return
}

func (gnb *GNB) decTransportLayerAddress(tla *per.BitField) {

	gnb.dprint("Transport Layer Address")

	// TODO: generic per decoder.
	// 0 0000 0000
	// ^           bit string extension marker
	//   ^^^^ ^^^^ bit string length
	*tla = per.ShiftLeft(*tla, 1) // skip extension marker
	tla.Len -= 1
	length := readPduByte(&tla.Value) + 1 // bit string size starts from 1.
	gnb.dprinti("bit string length: %d", length)

	*tla = per.ShiftLeft(*tla, tla.Len%8) // skip remaining preamble

	var addr net.IP
	octLen := int((length-1)/8 + 1)
	addr = readPduByteSlice(&tla.Value, octLen)
	gnb.dprinti("address: %v", addr)
	gnb.Recv.GTPuPeerAddr = addr

	return
}

//9.3.2.5 GTP-TEID
/*
GTP-TEID ::= OCTET STRING (SIZE(4))
*/
func (gnb *GNB) encGTPTEID() (pdu []byte) {

	const min = 4
	const max = 4
	const extmark = false

	teid := make([]byte, 4)
	// 999 for now, should be a random value.
	if gnb.GTPuTEID == 0 {
		gnb.GTPuTEID = rand.Uint32()
	}
	binary.BigEndian.PutUint32(teid, gnb.GTPuTEID)
	_, pdu, _ = per.EncOctetString(teid, min, max, extmark)

	return
}

func (gnb *GNB) decGTPTEID(pdu *[]byte) {

	id := readPduUint32(pdu)
	gnb.dprint("GTP TEID: %d", id)
	gnb.Recv.GTPuPeerTEID = id

	return
}

// 9.3.2.8 QoS Flow per TNL Information
/*
QosFlowPerTNLInformation ::= SEQUENCE {
    uPTransportLayerInformation     UPTransportLayerInformation,
    associatedQosFlowList           AssociatedQosFlowList,
    iE-Extensions       ProtocolExtensionContainer { { QosFlowPerTNLInformation-ExtIEs} }   OPTIONAL,
    ...
}
*/
func (gnb *GNB) encQosFlowPerTNLInformation(
	c *Camper, pre *per.BitField) (pdu []byte) {

	bf, _ := per.EncSequence(true, 1, 0)
	if pre != nil { // has inherited preamble
		bf = per.MergeBitField(*pre, bf)
	}
	pre = &bf

	tmp := gnb.encUPTransportLayerInformation(pre)
	pdu = append(pdu, tmp...)

	tmp = gnb.encAssociatedQosFlowList(c)
	pdu = append(pdu, tmp...)

	return
}

// 9.3.3.5 PLMN Identity
/*
PLMNIdentity ::= OCTET STRING (SIZE(3))
*/
type PLMN struct {
	MCC uint16
	MNC uint16
}

func (gnb *GNB) encPLMNIdentity(mcc, mnc uint16) (v []byte) {

	v = make([]byte, 3, 3)
	v[0] = byte(mcc % 1000 / 100)
	v[0] |= byte(mcc%100/10) << 4

	v[1] = byte(mcc % 10)
	v[1] |= 0xf0 // filler digit

	v[2] = byte(mnc % 100 / 10)
	v[2] |= byte(mnc%10) << 4

	_, v, _ = per.EncOctetString(v, 3, 3, false)

	return
}

/*
SliceSupportList ::= SEQUENCE (SIZE(1..maxnoofSliceItems)) OF SliceSupportItem
    maxnoofSliceItems                   INTEGER ::= 1024
*/
func encSliceSupportList(p *[]SliceSupport) (v []byte) {
	_, v, _ = per.EncSequenceOf(1, 1, 1024, false)
	for _, item := range *p {
		v = append(v, encSliceSupportItem(&item)...)
	}
	return
}

/*
SliceSupportItem ::= SEQUENCE {
    s-NSSAI             S-NSSAI,
    iE-Extensions       ProtocolExtensionContainer { {SliceSupportItem-ExtIEs} }    OPTIONAL,
    ...
}
*/
type SliceSupport struct {
	SST uint8
	SD  string
}

func encSliceSupportItem(ss *SliceSupport) (v []byte) {
	/*
		ex.1
		    .    .   .          .    .   .    .   .    .   .
		00 000 00000001	00 010 00000010 00000000 00000011 00001000
		0000 0000 0000 1xxx
		                000 1000 0000 10xx xxxx 00000000 00000011 11101000
		0x00 0x08 0x80 0x80 0x00 0x03 0xe1

		ex.2
		    .    .   .    .        .        .        .
		00 010 00000001 xxx 00000000 00000000 01111011
		0001 0000 0000 1xxx 00000000 00000000 11101000
		0x10 0x08 0x80 0x00 0x00 0x7b
	*/
	b, _ := per.EncSequence(true, 1, 0)

	b2, v := encSNSSAI(ss.SST, ss.SD)
	b = per.MergeBitField(b, b2)
	pv := b.Value

	v = append(pv, v...)
	return
}

// 9.3.1.24 S-NSSAI
/*
S-NSSAI ::= SEQUENCE {
    sST           SST,
    sD            SD                                                  OPTIONAL,
    iE-Extensions ProtocolExtensionContainer { { S-NSSAI-ExtIEs} }    OPTIONAL,
    ...
}

SST ::= OCTET STRING (SIZE(1))
SD ::= OCTET STRING (SIZE(3))
*/
func encSNSSAI(sstInt uint8, sdString string) (b per.BitField, v []byte) {

	b, _ = per.EncSequence(true, 2, 0x02)

	sst := []byte{byte(sstInt)}
	b2, _, _ := per.EncOctetString(sst, 1, 1, false)

	b = per.MergeBitField(b, b2)

	sd, _ := hex.DecodeString(sdString)
	_, v, _ = per.EncOctetString(sd, 3, 3, false)
	return
}

func (gnb *GNB) decSNSSAI(pdu *[]byte) {

	level := gnb.GetDebugLevel()
	defer gnb.SetDebugLevel(level)

	gnb.indent++
	gnb.dprint("S-NSSAI")

	var seq per.BitField
	seq.Value = readPduByteSlice(pdu, 2)
	per.ShiftLeft(seq, 1) // skip extension marker

	option := false
	option = (seq.Value[0] & 0x80) != 0

	per.ShiftLeft(seq, 2) // skip 2 optionss
	sst := int(seq.Value[0])

	gnb.dprinti("SST: %d", sst)

	if option {
		sd := readPduByteSlice(pdu, 3)
		gnb.dprinti("SD: 0x%0x", sd)
	}
	return
}

// 9.3.1.50 PDU Session ID
/*
PDUSessionID ::= INTEGER (0..255)
*/
func (gnb *GNB) encPDUSessionID(c *Camper) (pdu []byte) {
	_, pdu, _ = per.EncInteger(int64(c.PDUSessionID), 0, 255, false)
	return
}

func (gnb *GNB) decPDUSessionID(c *Camper, pdu *[]byte) (val int) {
	val = int(readPduByte(pdu))
	gnb.dprinti("PDU Session ID: %d", val)
	c.PDUSessionID = uint8(val)
	return
}

// 9.3.1.51 QoS Flow Identifier
/*
QosFlowIdentifier ::= INTEGER (0..63, ...)
*/
func (gnb *GNB) encQosFlowIdentifier(c *Camper) (bf per.BitField) {

	const min = 0
	const max = 63
	const extmark = true
	bf, _, _ = per.EncInteger(int64(c.QosFlowID), min, max, extmark)

	return
}

func (gnb *GNB) decQosFlowIdentifier(c *Camper, item *per.BitField) {

	// TODO: generic per decoder.
	// 000 0000
	// ^        extension marker
	//  ^^ ^^^^ integer
	id := item.Value[0]
	id >>= 1
	item.Len -= 7
	gnb.dprinti("Qos Flow Identifier: %d", id)
	c.QosFlowID = id
	return
}

// 9.3.1.52 PDU Session Type
/*
PDUSessionType ::= ENUMERATED {
    ipv4,
    ipv6,
    ipv4v6,
    ethernet,
    unstructured,
    ...
}
*/
const (
	ipv4 = iota
	ipv6
	ipv4v6
	ethernet
	unstructured
)

var PDUSessionTypeStr = map[int]string{
	ipv4:         "ipv4",
	ipv6:         "ipv6",
	ipv4v6:       "ipv4v6",
	ethernet:     "ethernet",
	unstructured: "unstructured",
}

func (gnb *GNB) decPDUSessionType(pdu *[]byte, length int) {

	// TODO: generic per decoder.
	// 0 000 0000
	// ^          extension marker
	//   ^^^      PDU Session Type

	pdutype := int(readPduByte(pdu))
	pdutype &= 0x70
	pdutype >>= 4

	gnb.dprint("PDU Session Type: %s (%d)", PDUSessionTypeStr[pdutype], pdutype)

	return
}

// 9.3.1.99 Associated QoS Flow List
/*
maxnoofQosFlows                     INTEGER ::= 64

AssociatedQosFlowList ::= SEQUENCE (SIZE(1..maxnoofQosFlows)) OF AssociatedQosFlowItem

AssociatedQosFlowItem ::= SEQUENCE {
    qosFlowIdentifier               QosFlowIdentifier,
    qosFlowMappingIndication        ENUMERATED {ul, dl, ...}                            OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {AssociatedQosFlowItem-ExtIEs} }   OPTIONAL,
    ...
}
*/
func (gnb *GNB) encAssociatedQosFlowList(c *Camper) (pdu []byte) {

	const min = 1
	const max = 64
	const extmark = false

	bf, _, _ := per.EncSequenceOf(1, min, max, extmark)
	pdu = gnb.encAssociatedQosFlowItem(c, &bf)

	return
}

func (gnb *GNB) encAssociatedQosFlowItem(
	c *Camper, pre *per.BitField) (pdu []byte) {

	const optnum = 2
	const optflag = 0
	const extmark = true

	bf, _ := per.EncSequence(extmark, optnum, optflag)
	if pre != nil {
		bf = per.MergeBitField(*pre, bf)
	}
	bf2 := gnb.encQosFlowIdentifier(c)
	bf = per.MergeBitField(bf, bf2)
	pdu = bf.Value

	return
}

// 9.3.1.111 RRC Establishment Cause
/*
RRCEstablishmentCause ::= ENUMERATED {
    emergency,
    highPriorityAccess,
    mt-Access,
    mo-Signalling,
    mo-Data,
    mo-VoiceCall,
    mo-VideoCall,
    mo-SMS,
    mps-PriorityAccess,
    mcs-PriorityAccess,
    ...,
    notAvailable
}
*/
const (
	rrcEmergency = iota
	rrcHighPriorityAccess
	rrcMtAccess
	rrcMoSignalling
	rrcMoData
	rrcMoVoiceCall
	rrcMoVideoCall
	rrcMoSMS
	rrcMpsPriorityAccess
	rrcMcsPriorityAccess
)

func (gnb *GNB) encRRCEstablishmentCause(cause uint) (v []byte, err error) {

	head, err := encProtocolIE(idRRCEstablishmentCause, ignore)

	/*
	 * I couldn't find the max value for the Establishment Cause.
	 * Wireshark does parse it as 4 bit field. It means that the number is
	 * from 7 to 14.
	 */
	b, _, _ := per.EncEnumerated(cause, 0, 14, true)
	v = b.Value

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)
	return
}

// 9.3.3.1 AMF UE NGAP ID
/*
AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775) // 20^40 -1
*/
func (gnb *GNB) encAMFUENGAPID(c *Camper) (v []byte) {

	head, _ := encProtocolIE(idAMFUENGAPID, reject)
	_, v, _ = per.EncInteger(int64(c.AmfId), 0, 4294967295, false)
	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)

	return
}

func (gnb *GNB) decAMFUENGAPID(pdu *[]byte, length int) (c *Camper, err error) {

	// need generic per encoder.
	if length != 2 {
		err = fmt.Errorf("unsupported AMF-UE-NGAP-ID length.")
		return
	}
	id := uint32(readPduUint16(pdu))

	var obj Camper
	c = &obj
	c.AmfId = id
	c.camperType = CAMPER_TYPE_TEMPORARY

	return
}

// 9.3.3.2 RAN UE NGAP ID
/*
RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)
*/
func (gnb *GNB) encRANUENGAPID() (v []byte) {

	head, _ := encProtocolIE(idRANUENGAPID, reject)

	_, v, _ = per.EncInteger(int64(gnb.RANUENGAPID), 0, 4294967295, false)
	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)
	return
}

func (gnb *GNB) decRANUENGAPID(
	cTmp *Camper, pdu *[]byte, length int) (c *Camper, err error) {

	if length != 2 {
		err = fmt.Errorf("unsupported AMF-UE-NGAP-ID length.")
		return
	}
	id := uint32(readPduUint16(pdu))
	c = gnb.LookupCamperByRanId(id)

	if c == nil {
		err = fmt.Errorf("cannot find camper for RanId=%d", id)
		fmt.Printf("cannot find camper for RanId=%d\n", id)
		return
	}
	c.AmfId = cTmp.AmfId

	return
}

// 9.3.3.4 NAS-PDU
/*
NAS-PDU ::= OCTET STRING
*/
func (gnb *GNB) encNASPDU(c *Camper) (v []byte) {

	if c.RecvMsg == nil {
		return
	}

	head, _ := encProtocolIE(idNASPDU, reject)

	pdu := *c.RecvMsg
	pre, v, _ := per.EncOctetString(pdu, 0, 0, false)
	v = append(pre.Value, v...)

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)
	c.RecvMsg = nil

	return
}

func (gnb *GNB) decNASPDU(c *Camper, pdu *[]byte) (err error) {

	length := int(readPduByte(pdu))
	naspdu := readPduByteSlice(pdu, length)
	gnb.SendtoUE(c, &naspdu)

	return
}

// 9.3.3.10 TAC
/*
TAC ::= OCTET STRING (SIZE(3))
*/
func (gnb *GNB) encTAC(tacString string) (v []byte) {
	const tacSize = 3
	tmp, _ := strconv.ParseUint(tacString, 0, 32)
	tac := make([]byte, 8)
	binary.BigEndian.PutUint64(tac, tmp)
	tac = tac[len(tac)-3:]

	_, v, _ = per.EncOctetString(tac, tacSize, tacSize, false)
	return
}

// 9.3.3.11 TAI
/*
TAI ::= SEQUENCE {
    pLMNIdentity        PLMNIdentity,
    tAC                 TAC,
    iE-Extensions       ProtocolExtensionContainer { {TAI-ExtIEs} } OPTIONAL,
    ...
}
*/
type TAI struct {
	PLMN PLMN
	TAC  string
}

func (gnb *GNB) encTAI(tai *TAI) (b per.BitField, v []byte, err error) {
	b, _ = per.EncSequence(true, 1, 0)
	v = gnb.encPLMNIdentity(tai.PLMN.MCC, tai.PLMN.MNC)
	v = append(v, gnb.encTAC(tai.TAC)...)
	return
}

// 9.3.4.1 PDU Session Resource Setup Request Transfer
/*
PDUSessionResourceSetupRequestTransfer ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {PDUSessionResourceSetupRequestTransferIEs} },
    ...
}

PDUSessionResourceSetupRequestTransferIEs NGAP-PROTOCOL-IES ::= {
    { ID id-PDUSessionAggregateMaximumBitRate   CRITICALITY reject  TYPE PDUSessionAggregateMaximumBitRate      PRESENCE optional       }|
    { ID id-UL-NGU-UP-TNLInformation            CRITICALITY reject  TYPE UPTransportLayerInformation                PRESENCE mandatory  }|
    { ID id-AdditionalUL-NGU-UP-TNLInformation  CRITICALITY reject  TYPE UPTransportLayerInformationList        PRESENCE optional       }|
    { ID id-DataForwardingNotPossible           CRITICALITY reject  TYPE DataForwardingNotPossible              PRESENCE optional       }|
    { ID id-PDUSessionType                      CRITICALITY reject  TYPE PDUSessionType                             PRESENCE mandatory  }|
    { ID id-SecurityIndication                  CRITICALITY reject  TYPE SecurityIndication                         PRESENCE optional       }|
    { ID id-NetworkInstance                     CRITICALITY reject  TYPE NetworkInstance                            PRESENCE optional       }|
    { ID id-QosFlowSetupRequestList             CRITICALITY reject  TYPE QosFlowSetupRequestList                    PRESENCE mandatory  }|
    { ID id-CommonNetworkInstance               CRITICALITY ignore  TYPE CommonNetworkInstance                      PRESENCE optional   },
    ...
}
*/
func (gnb *GNB) decPDUSessionResourceSetupRequestTransfer(
	c *Camper, pdu *[]byte) {

	gnb.dprint("PDU Session Resource Setup Request Transfer")
	length, _ := per.DecLengthDeterminant(pdu, 0)
	pdu2 := readPduByteSlice(pdu, length)
	gnb.decProtocolIEContainer(c, &pdu2)

	return
}

// 9.3.4.2 PDU Session Resource Setup Response Transfer
/*
PDUSessionResourceSetupResponseTransfer ::= SEQUENCE {
    dLQosFlowPerTNLInformation              QosFlowPerTNLInformation,
    additionalDLQosFlowPerTNLInformation    QosFlowPerTNLInformationList                                        OPTIONAL,
    securityResult                          SecurityResult                                                      OPTIONAL,
    qosFlowFailedToSetupList                QosFlowListWithCause                                                OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {PDUSessionResourceSetupResponseTransfer-ExtIEs} }     OPTIONAL,
    ...
}
*/
func (gnb *GNB) encPDUSessionResourceSetupResponseTransfer(
	c *Camper) (pdu []byte) {

	bf, _ := per.EncSequence(true, 4, 0)
	pre := &bf
	pdu = gnb.encQosFlowPerTNLInformation(c, pre)

	return
}

/*
 * following IEs/Group Names are defined in each message definitions in
 * 9.2, 9.3.
 */

// PDU Session Resource Setup Request List is defined in
// 9.2.2.1 INITIAL CONTEXT SETUP REQUEST
/*
PDUSessionResourceSetupListCxtReq ::= SEQUENCE (SIZE(1..maxnoofPDUSessions)) OF PDUSessionResourceSetupItemCxtReq
1..256
*/
func (gnb *GNB) decPDUSessionResourceSetupListCtxReq(c *Camper, pdu *[]byte, length int) {

	gnb.dprint("PDU Session Resource Setup Request Request List")

	var list per.BitField
	list.Value = readPduByteSlice(pdu, length)
	//gnb.dprinti("dump: %02x", list.Value)

	// TODO: generic per decoder.
	itemNum := int(readPduByte(&list.Value))
	itemNum += 1
	list.Len = len(list.Value) * 8

	for i := 0; i < itemNum; i++ {
		gnb.dprint("Item %d", i)
		gnb.decPDUSessionResourceSetupItemCxtReq(c, &list)
	}

	return
}

/*
PDUSessionResourceSetupItemCxtReq ::= SEQUENCE {
    pDUSessionID                                PDUSessionID,
    nAS-PDU                                     NAS-PDU                                             OPTIONAL,
    s-NSSAI                                     S-NSSAI,
    pDUSessionResourceSetupRequestTransfer      OCTET STRING (CONTAINING PDUSessionResourceSetupRequestTransfer),
    iE-Extensions       ProtocolExtensionContainer { {PDUSessionResourceSetupItemCxtReq-ExtIEs} }   OPTIONAL,
    ...
}
*/
func (gnb *GNB) decPDUSessionResourceSetupItemCxtReq(
	c *Camper, item *per.BitField) {

	// TODO: generic per decoder.
	// 0000 0000
	// ^           extension marker
	//  ^^         options
	opt := item.Value[0]
	hasNasPdu := false
	if opt&0x4 != 0 {
		hasNasPdu = true
	}
	*item = per.ShiftLeft(*item, 8)

	gnb.decPDUSessionID(c, &item.Value)

	gnb.dprinti("NAS-PDU: %v", hasNasPdu)
	if hasNasPdu {
		gnb.decNASPDU(c, &item.Value)
	}
	gnb.decSNSSAI(&item.Value)
	gnb.decPDUSessionResourceSetupRequestTransfer(c, &item.Value)

	return
}

// Broadcast PLMN List is defined in
// 9.2.6.1 NG SETUP REQUEST
/*
BroadcastPLMNList ::= SEQUENCE (SIZE(1..maxnoofBPLMNs)) OF BroadcastPLMNItem
    maxnoofBPLMNs                       INTEGER ::= 12
*/
func (gnb *GNB) encBroadcastPLMNList(bplmn *[]BroadcastPLMN) (v []byte) {

	const maxnoofBPLMNs = 12

	b, _, _ := per.EncSequenceOf(1, 1, maxnoofBPLMNs, false)

	for _, item := range *bplmn {
		b2, v2 := gnb.encBroadcastPLMNItem(&item)
		if b2.Len != 0 {
			b = per.MergeBitField(b, b2)
		}
		v = append(v, b.Value...)
		v = append(v, v2...)
	}
	return
}

// Broadcast PLMN Item is defined in 9.2.6.1 NG SETUP REQUEST
/*
BroadcastPLMNItem ::= SEQUENCE {
    pLMNIdentity            PLMNIdentity,
    tAISliceSupportList     SliceSupportList,
    iE-Extensions           ProtocolExtensionContainer { {BroadcastPLMNItem-ExtIEs} } OPTIONAL,
    ...
}
*/
type BroadcastPLMN struct {
	MCC              uint16
	MNC              uint16
	SliceSupportList []SliceSupport
}

func (gnb *GNB) encBroadcastPLMNItem(bplmn *BroadcastPLMN) (
	b per.BitField, v []byte) {
	b, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(bplmn.MCC, bplmn.MNC)...)
	v = append(v, encSliceSupportList(&bplmn.SliceSupportList)...)
	return
}

// Supported TA List is defined in 9.2.6.1 NG SETUP REQUEST
/*
SupportedTAList ::= SEQUENCE (SIZE(1..maxnoofTACs)) OF SupportedTAItem
maxnoofTACs INTEGER ::= 256
*/
func (gnb *GNB) encSupportedTAList(p *[]SupportedTA) (v []byte, err error) {

	head, err := encProtocolIE(idSupportedTAList, reject)

	const maxnoofTACs = 256
	_, v, _ = per.EncSequenceOf(1, 1, maxnoofTACs, false)

	for _, item := range *p {
		v = append(v, gnb.encSupportedTAItem(&item)...)
	}

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)

	return
}

// Supported TA Item is defined in 9.2.6.1 NG SETUP REQUEST
/*
SupportedTAItem ::= SEQUENCE {
    tAC                     TAC,
    broadcastPLMNList       BroadcastPLMNList,
    iE-Extensions           ProtocolExtensionContainer { {SupportedTAItem-ExtIEs} } OPTIONAL,
    ...
}
*/
type SupportedTA struct {
	TAC               string
	BroadcastPLMNList []BroadcastPLMN
}

func (gnb *GNB) encSupportedTAItem(p *SupportedTA) (v []byte) {

	b, _ := per.EncSequence(true, 1, 0)
	v = append(b.Value, gnb.encTAC(p.TAC)...)
	v = append(v, gnb.encBroadcastPLMNList(&p.BroadcastPLMNList)...)
	return
}

// UE Context Request is defined in 9.2.5.1 INITIAL UE MESSAGE
/*
UEContextRequest ::= ENUMERATED {requested, ...}
*/
func (gnb *GNB) encUEContextRequest() (v []byte, err error) {

	head, err := encProtocolIE(idUEContextRequest, ignore)

	b, _, _ := per.EncEnumerated(0, 0, 0, true)
	v = b.Value

	bf, _ := per.EncLengthDeterminant(len(v), 0, 0)
	head = append(head, bf.Value...)
	v = append(head, v...)
	return
}

// QoS Characteristics is defined in 9.3.1.12 QoS Flow Level QoS Parameters
/*
QosCharacteristics ::= CHOICE {
    nonDynamic5QI       NonDynamic5QIDescriptor,
    dynamic5QI          Dynamic5QIDescriptor,
    choice-Extensions       ProtocolIE-SingleContainer { {QosCharacteristics-ExtIEs} }
}
*/
func (gnb *GNB) decQosCharacteristics(item *per.BitField) {
	return
}

// QoS Flow Setup Request List is defined in
// 9.3.4.1 PDU Session Resource Setup Request Transfer
/*
maxnoofQosFlows                     INTEGER ::= 64

QosFlowSetupRequestList ::= SEQUENCE (SIZE(1..maxnoofQosFlows)) OF QosFlowSetupRequestItem

QosFlowSetupRequestItem ::= SEQUENCE {
    qosFlowIdentifier               QosFlowIdentifier,
    qosFlowLevelQosParameters       QosFlowLevelQosParameters,
    e-RAB-ID                        E-RAB-ID                                            OPTIONAL,
    iE-Extensions       ProtocolExtensionContainer { {QosFlowSetupRequestItem-ExtIEs} } OPTIONAL,
    ...
}
*/
func (gnb *GNB) decQosFlowSetupRequestList(c *Camper, pdu *[]byte, length int) {

	var qoslist per.BitField
	qoslist.Value = readPduByteSlice(pdu, length)
	qoslist.Len = len(qoslist.Value) * 8
	gnb.dprint("dump: %02x", qoslist.Value)

	// TODO: generic per decoder.
	// 0000 00 00
	// ^^^^ ^^    sequence of 1-64
	itemNum := int(qoslist.Value[0])
	itemNum >>= 2
	itemNum += 1

	qoslist = per.ShiftLeft(qoslist, 6)
	qoslist.Len -= 6

	for i := 0; i < itemNum; i++ {
		gnb.dprint("Item %d", i)
		gnb.decQosFlowSetupRequestItem(c, &qoslist)
	}

	return
}

func (gnb *GNB) decQosFlowSetupRequestItem(c *Camper, item *per.BitField) {

	// TODO: generic per decoder.
	// 00 0000 0000
	// ^            extension marker
	//  ^ ^         options
	*item = per.ShiftLeft(*item, 3)
	item.Len -= 3
	gnb.decQosFlowIdentifier(c, item)
	gnb.decQosFlowLevelQosParameters(item)

	return
}

//-----
func readPduByte(pdu *[]byte) (val byte) {
	val = byte((*pdu)[0])
	*pdu = (*pdu)[1:]
	return
}

func readPduUint16(pdu *[]byte) (val uint16) {
	val = binary.BigEndian.Uint16(*pdu)
	*pdu = (*pdu)[2:]
	return
}

func readPduUint32(pdu *[]byte) (val uint32) {
	val = binary.BigEndian.Uint32(*pdu)
	*pdu = (*pdu)[4:]
	return
}

func readPduByteSlice(pdu *[]byte, length int) (val []byte) {
	val = (*pdu)[:length]
	*pdu = (*pdu)[length:]
	return
}

func (gnb *GNB) GetDebugLevel() int {
	return gnb.dbgLevel
}

func (gnb *GNB) SetDebugLevel(level int) {
	gnb.dbgLevel = level
	return
}

func (gnb *GNB) dprint(format string, v ...interface{}) {
	if gnb.dbgLevel == 0 {
		return
	}
	indent := strings.Repeat("  ", gnb.indent)
	fmt.Printf(indent+format+"\n", v...)
	return
}

func (gnb *GNB) dprinti(format string, v ...interface{}) {
	gnb.indent++
	gnb.dprint(format, v...)
	gnb.indent--
}
