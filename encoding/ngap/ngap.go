// Copyright 2019-2020 hhorai. All rights reserved.
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
	"strconv"
	"strings"

	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/per"
)

const (
	reject = iota
	ignore
	notify
)

const (
	initiatingMessage = iota
	successfulOutcome
	unsuccessfulOutcome
)

// Elementary Procedures constants
const (
	idDownlinkNASTransport    = 4
	idInitialContextSetup     = 14
	idInitialUEMessage        = 15
	idNGSetup                 = 21
	idPDUSessionResourceSetup = 29
	idUplinkNASTransport      = 46
)

var procID = map[int]string{
	idDownlinkNASTransport:    "id-DownlinkNASTransport",
	idInitialContextSetup:     "id-InitialContextSetup",
	idInitialUEMessage:        "id-InitialUEMessage",
	idNGSetup:                 "id-NGSetup",
	idPDUSessionResourceSetup: "id-PDUSessionResourceSetup",
	idUplinkNASTransport:      "id-UplinkNASTransport",
}

const (
	idAllowedNSSAI                     = 0
	idAMFName                          = 1
	idAMFUENGAPID                      = 10
	idDefaultPagingDRX                 = 21
	idGlobalRANNodeID                  = 27
	idGUAMI                            = 28
	idMaskedIMEISV                     = 34
	idMobilityRestrictionList          = 36
	idNASPDU                           = 38
	idPDUSessionResourceSetupListSUReq = 74
	idPLMNSupportList                  = 80
	idRANUENGAPID                      = 85
	idRelativeAMFCapacity              = 86
	idRRCEstablishmentCause            = 90
	idSecurityKey                      = 94
	idServedGUAMIList                  = 96
	idSupportedTAList                  = 102
	idUEContextRequest                 = 112
	idUESecurityCapabilities           = 119
	idUserLocationInformation          = 121
	idPDUSessionType                   = 134
	idQosFlowSetupRequestList          = 136
	idULNGUUPTNLInformation            = 139
)

var ieID = map[int]string{
	idAllowedNSSAI:                     "id-AllowedNSSAI",
	idAMFName:                          "id-AMFName",
	idAMFUENGAPID:                      "id-AMF-UE-NGAP-ID",
	idDefaultPagingDRX:                 "",
	idGlobalRANNodeID:                  "",
	idGUAMI:                            "id-GUAMI",
	idMaskedIMEISV:                     "id-MaskedIMEISV",
	idMobilityRestrictionList:          "id-MobilityRestrictionList",
	idNASPDU:                           "id-NAS-PDU",
	idPDUSessionResourceSetupListSUReq: "id-PDUSessionResourceSetupListSUReq",
	idPLMNSupportList:                  "id-PLMNSupportList",
	idRANUENGAPID:                      "id-RAN-UE-NGAP-ID",
	idRelativeAMFCapacity:              "id-RelativeAMFCapacity",
	idRRCEstablishmentCause:            "",
	idSecurityKey:                      "id-SecurityKey",
	idServedGUAMIList:                  "id-ServedGUAMIList",
	idSupportedTAList:                  "",
	idUEContextRequest:                 "",
	idUESecurityCapabilities:           "id-UESecurityCapabilities",
	idUserLocationInformation:          "",
	idPDUSessionType:                   "id-PDUSessionType",
	idQosFlowSetupRequestList:          "id-QosFlowSetupRequestList",
	idULNGUUPTNLInformation:            "id-UL-NGU-UP-TNLInformation",
}

type GNB struct {
	GlobalGNBID     GlobalGNBID
	SupportedTAList []SupportedTA
	PagingDRX       string
	RANUENGAPID     uint32
	UE              nas.UE
	ULInfoNR        UserLocationInformationNR

	recv struct {
		AMFUENGAPID []byte
	}

	SendNasMsg *[]byte
	RecvNasMsg *[]byte

	dbgLevel int
	indent   int // indent for debug print.
}

func NewNGAP(filename string) (p *GNB) {

	log.SetPrefix("[ngap]")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

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

func (gnb *GNB) SendtoUE(pdu *[]byte) {

	if pdu != nil {
		gnb.UE.SetIndent(gnb.indent)
		gnb.UE.Receive(pdu)
	}
	return
}

func (gnb *GNB) RecvfromUE(pdu *[]byte) {
	gnb.RecvNasMsg = pdu
	return
}

func (gnb *GNB) Decode(pdu *[]byte) {

	_, procCode, _, _ := decNgapPdu(pdu)

	procIdStr := procID[procCode]
	if procIdStr == "" {
		log.Printf("unsupported procedure: %d", procCode)
	}
	gnb.dprint("Procedure Code: %s (%d)", procID[procCode], procCode)

	length, _ := per.DecLengthDeterminant(pdu, 0)
	gnb.dprint("PDU Length: %d", length)

	gnb.decProtocolIEContainer(pdu)

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

func (gnb *GNB) decPDUSessionResourceSetupListSUReq(pdu *[]byte, length int) {

	seqNum := int(readPduByte(pdu)) + 1
	gnb.dprint("number of sequence: %d", seqNum)

	for i := 0; i < seqNum; i++ {
		seq := readPduByte(pdu)
		gnb.decPDUSessionID(pdu)

		seq <<= 1 // skip extension marker

		option := false
		option = (seq & 0x80) != 0
		if option {
			gnb.decNASPDU(pdu)
		}
		gnb.decSNSSAI(pdu)
		gnb.decPDUSessionResourceSetupRequestTransfer(pdu)
	}
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
func (gnb *GNB) MakeInitialContextSetupResponse() (pdu []byte) {

	pdu = encNgapPdu(successfulOutcome, idInitialContextSetup, reject)

	v := encProtocolIEContainer(2)

	tmp := gnb.encAMFUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encRANUENGAPID()
	v = append(v, tmp...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
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
func (gnb *GNB) MakeInitialUEMessage() (pdu []byte) {

	pdu = encNgapPdu(initiatingMessage, idInitialUEMessage, ignore)

	v := encProtocolIEContainer(4)

	tmp := gnb.encRANUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encNASPDU()
	v = append(v, tmp...)

	tmp, _ = gnb.encUserLocationInformation()
	v = append(v, tmp...)

	tmp, _ = gnb.encRRCEstablishmentCause(rrcMoSignalling)
	v = append(v, tmp...)

	tmp, _ = gnb.encUEContextRequest()
	v = append(v, tmp...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
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
func (gnb *GNB) MakeUplinkNASTransport() (pdu []byte) {

	// Authentiation Response only for now.

	pdu = encNgapPdu(initiatingMessage, idUplinkNASTransport, ignore)

	v := encProtocolIEContainer(4)

	tmp := gnb.encAMFUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encRANUENGAPID()
	v = append(v, tmp...)

	tmp = gnb.encNASPDU()
	v = append(v, tmp...)

	tmp, _ = gnb.encUserLocationInformation()
	v = append(v, tmp...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
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

	length, _, _ := per.EncLengthDeterminant(len(v), 0)

	pdu = append(pdu, length...)
	pdu = append(pdu, v...)

	return
}

/*
NGAP-PDU ::= CHOICE {
    initiatingMessage           InitiatingMessage,
    successfulOutcome           SuccessfulOutcome,
    unsuccessfulOutcome         UnsuccessfulOutcome,
    ...
}
ProcedureCode ::= INTEGER (0..255)
Criticality   ::= ENUMERATED { reject, ignore, notify }

InitiatingMessage ::= SEQUENCE {
    procedureCode   NGAP-ELEMENTARY-PROCEDURE.&procedureCode     ({NGAP-ELEMENTARY-PROCEDURES}),
    criticality     NGAP-ELEMENTARY-PROCEDURE.&criticality       ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode}),
    value           NGAP-ELEMENTARY-PROCEDURE.&InitiatingMessage ({NGAP-ELEMENTARY-PROCEDURES}{@procedureCode})
}
*/
func encNgapPdu(pduType int, procCode int, criticality int) (pdu []byte) {
	pdu, _, _ = per.EncChoice(pduType, 0, 2, true)
	v, _, _ := per.EncInteger(int64(procCode), 0, 255, false)
	pdu = append(pdu, v...)
	v, _, _ = per.EncEnumerated(uint(criticality), 0, 2, false)
	pdu = append(pdu, v...)

	return
}

func decNgapPdu(pdu *[]byte) (
	pduType int, procCode int, criticality int, err error) {

	if len(*pdu) < 3 {
		err = fmt.Errorf("remaining pdu length is too short.")
		return
	}

	offset := 0
	offset += 1 // skip pduType

	procCode = int((*pdu)[offset])
	offset += 1
	offset += 1 // skip criticality

	*pdu = (*pdu)[offset:]
	return
}

/*
NGSetupRequest ::= SEQUENCE {
    protocolIEs     ProtocolIE-Container        { {NGSetupRequestIEs} },
    ...
}
ProtocolIE-Container {NGAP-PROTOCOL-IES : IEsSetParam} ::=
    SEQUENCE (SIZE (0..maxProtocolIEs)) OF
    ProtocolIE-Field {{IEsSetParam}}

maxProtocolIEs                          INTEGER ::= 65535
*/
func encProtocolIEContainer(num uint) (container []byte) {
	const maxProtocolIEs = 65535
	container, _, _ = per.EncSequence(true, 0, 0)
	v, _, _ := per.EncSequenceOf(num, 0, maxProtocolIEs, false)
	container = append(container, v...)

	return
}

func (gnb *GNB) decProtocolIEContainer(pdu *[]byte) (err error) {

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
		gnb.decProtocolIE(pdu)
		gnb.indent -= 2
	}
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

	v1, _, _ := per.EncInteger(id, 0, 65535, false)
	v2, _, _ := per.EncEnumerated(criticality, 0, 2, false)
	v = append(v1, v2...)

	return
}

func (gnb *GNB) decProtocolIE(pdu *[]byte) (err error) {

	if len(*pdu) < 2 {
		err = fmt.Errorf("remaining pdu length(%d) is too short. expect > %d",
			len(*pdu), 2)
		return
	}
	offset := 0
	id := int(binary.BigEndian.Uint16((*pdu)[offset:]))
	offset += 2
	if ieID[id] == "" {
		log.Printf("unsupported Protocol IE: %d", id)
	}

	gnb.dprint("Protocol IE: %s (%d)", ieID[id], id)
	gnb.indent++

	offset += 1 // skip ciritcality

	length := int((*pdu)[offset])
	gnb.dprint("IE length: %d", length)
	gnb.indent++
	offset += 1
	*pdu = (*pdu)[offset:]

	switch id {
	case idAMFUENGAPID: //10
		gnb.decAMFUENGAPID(pdu, length)
	case idNASPDU: // 38
		gnb.decNASPDU(pdu)
	case idPDUSessionResourceSetupListSUReq: // 74
		gnb.decPDUSessionResourceSetupListSUReq(pdu, length)
	default:
		gnb.dprint("decoding id(%d) not supported yet.", id)
		gnb.dprint("dump: %02x", (*pdu)[:length])
		*pdu = (*pdu)[length:]
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

func (gnb *GNB) encGlobalRANNodeID(p *GlobalGNBID) (v []byte, err error) {

	head, err := encProtocolIE(idGlobalRANNodeID, reject)

	// NG-ENB and N3IWF are not implemented yet...
	pv, plen, _ := per.EncChoice(globalGNB, 0, 2, false)
	pv2, plen2, v2 := gnb.encGlobalGNBID(p)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	pv = append(pv, v2...)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
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

func (gnb *GNB) encGlobalGNBID(p *GlobalGNBID) (pv []byte, plen int, v []byte) {

	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(p.MCC, p.MNC)...)

	pv2, _ := encGNBID(p.GNBID)
	v = append(v, pv2...)
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

func encGNBID(gnbid uint32) (pv []byte, plen int) {

	bitlen := bits.Len32(gnbid)
	if bitlen < minGNBIDSize {
		bitlen = minGNBIDSize
	}

	pv, plen, _ = per.EncChoice(0, 0, 1, false)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)
	pv2, plen2, v, _ := per.EncBitString(tmp, bitlen,
		minGNBIDSize, maxGNBIDSize, false)

	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	pv = append(pv, v...)

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

func (gnb *GNB) encNRCGI(nrcgi *NRCGI) (pv []byte, plen int,
	v []byte, bitlen int, err error) {

	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = gnb.encPLMNIdentity(nrcgi.PLMN.MCC, nrcgi.PLMN.MNC)
	bitlen = len(v) * 8
	v2, bitlen2 := gnb.encNRCellIdentity(nrcgi.NRCellID)

	v = append(v, v2...)
	bitlen += bitlen2

	return
}

func (gnb *GNB) encNRCellIdentity(cellid uint64) (v []byte, bitlen int) {

	// The leftmost bits of the NR Cell Identity IE correspond to the gNB ID
	// (defined in subclause 9.3.1.6).
	gnbid := gnb.GlobalGNBID.GNBID
	gnbidlen := bits.Len32(gnbid)

	if gnbidlen < minGNBIDSize {
		gnbidlen = minGNBIDSize
	}

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, gnbid)
	pv, plen := per.ShiftLeftMost(tmp, gnbidlen)

	cellidlen := nrCellIDSize - gnbidlen
	tmp = make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, cellid)
	pv2, plen2 := per.ShiftLeftMost(tmp, cellidlen)

	v, bitlen = per.MergeBitField(pv, plen, pv2, plen2)
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
	head, err := encProtocolIE(idUserLocationInformation, reject)

	// NG-ENB and N3IWF are not implemented yet...
	pv, plen, _ := per.EncChoice(ULInfoNR, 0, 2, false)

	pv2, plen2, v := gnb.encUserLocationInformationNR(&gnb.ULInfoNR)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)

	pv = append(pv, v...)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
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

func (gnb *GNB) encUserLocationInformationNR(info *UserLocationInformationNR) (pv []byte, plen int, v []byte) {

	pv, plen, _ = per.EncSequence(true, 2, 0)
	pv2, plen2, v, bitlen, _ := gnb.encNRCGI(&info.NRCGI)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)

	pv2, plen2, v2, _ := gnb.encTAI(&info.TAI)
	v, bitlen = per.MergeBitField(v, bitlen, pv2, plen2)

	v = append(v, v2...)

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
	pv, _, _ := per.EncEnumerated(n, 0, 3, true)

	length, _, _ := per.EncLengthDeterminant(len(pv), 0)
	head = append(head, length...)
	v = append(head, pv...)

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

	_, _, v, _ = per.EncOctetString(v, 3, 3, false)

	return
}

/*
SliceSupportList ::= SEQUENCE (SIZE(1..maxnoofSliceItems)) OF SliceSupportItem
    maxnoofSliceItems                   INTEGER ::= 1024
*/
func encSliceSupportList(p *[]SliceSupport) (v []byte) {
	v, _, _ = per.EncSequenceOf(1, 1, 1024, false)
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

func encSliceSupportItem(p *SliceSupport) (v []byte) {
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
	pv, plen, _ := per.EncSequence(true, 1, 0)

	pv2, plen2, v := encSNSSAI(p.SST, p.SD)
	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
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
func encSNSSAI(sstInt uint8, sdString string) (pv []byte, plen int, v []byte) {
	pv, plen, _ = per.EncSequence(true, 2, 0x02)

	sst := []byte{byte(sstInt)}
	pv2, plen2, _, _ := per.EncOctetString(sst, 1, 1, false)

	pv, plen = per.MergeBitField(pv, plen, pv2, plen2)
	sd, _ := hex.DecodeString(sdString)
	_, _, v, _ = per.EncOctetString(sd, 3, 3, false)
	return
}

func (gnb *GNB) decSNSSAI(pdu *[]byte) {

	gnb.dprint("S-NSSAI")
	seq := readPduByteSlice(pdu, 2)

	per.ShiftLeft(seq, 1) // skip extension marker

	option := false
	option = (seq[0] & 0x80) != 0

	per.ShiftLeft(seq, 2) // skip 2 optionss
	sst := int(seq[0])

	gnb.dprinti("SST: %d", sst)

	if option {
		sd := readPduByteSlice(pdu, 3)
		gnb.dprinti("SST: 0x%0x", sd)
	}
	return
}

// 9.3.1.50 PDU Session ID
/*
PDUSessionID ::= INTEGER (0..255)
*/
func (gnb *GNB) decPDUSessionID(pdu *[]byte) (val int) {
	val = int(readPduByte(pdu))
	gnb.dprinti("PDU Session ID: %d", val)
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
	v, _, _ = per.EncEnumerated(cause, 0, 14, true)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

// 9.3.3.1 AMF UE NGAP ID
/*
AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775) // 20^40 -1
*/
func (gnb *GNB) encAMFUENGAPID() (v []byte) {
	head, _ := encProtocolIE(idAMFUENGAPID, reject)
	v = gnb.recv.AMFUENGAPID

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

func (gnb *GNB) decAMFUENGAPID(pdu *[]byte, length int) {
	// just storing the received value for now.
	gnb.recv.AMFUENGAPID = (*pdu)[:length]
	*pdu = (*pdu)[length:]
	return
}

// 9.3.3.2 RAN UE NGAP ID
/*
RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)
*/
func (gnb *GNB) encRANUENGAPID() (v []byte) {
	head, _ := encProtocolIE(idRANUENGAPID, reject)
	v, _, _ = per.EncInteger(int64(gnb.RANUENGAPID), 0, 4294967295, false)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	return
}

// 9.3.3.4 NAS-PDU
/*
NAS-PDU ::= OCTET STRING
*/
func (gnb *GNB) encNASPDU() (v []byte) {

	if gnb.RecvNasMsg == nil {
		return
	}

	head, _ := encProtocolIE(idNASPDU, reject)

	pdu := *gnb.RecvNasMsg
	pv, _, v, _ := per.EncOctetString(pdu, 0, 0, false)
	v = append(pv, v...)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
	gnb.RecvNasMsg = nil

	return
}

func (gnb *GNB) decNASPDU(pdu *[]byte) (err error) {

	gnb.dprint("pseudo DecOctetString")
	readPduByte(pdu)
	gnb.SendtoUE(pdu)

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

	_, _, v, _ = per.EncOctetString(tac, tacSize, tacSize, false)
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

func (gnb *GNB) encTAI(tai *TAI) (pv []byte, plen int, v []byte, err error) {
	pv, plen, _ = per.EncSequence(true, 1, 0)
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
func (gnb *GNB) decPDUSessionResourceSetupRequestTransfer(pdu *[]byte) {

	gnb.dprint("PDU Session Resource Setup Request Transfer")
	length, _ := per.DecLengthDeterminant(pdu, 0)
	pdu2 := readPduByteSlice(pdu, length)
	gnb.decProtocolIEContainer(&pdu2)

	return
}

/*
 * following IEs/Group Names are defined in each message definitions in 9.2.
 * alphabetical order
 */

// Broadcast PLMN List is defined in 9.2.6.1 NG SETUP REQUEST
/*
BroadcastPLMNList ::= SEQUENCE (SIZE(1..maxnoofBPLMNs)) OF BroadcastPLMNItem
    maxnoofBPLMNs                       INTEGER ::= 12
*/
func (gnb *GNB) encBroadcastPLMNList(p *[]BroadcastPLMN) (v []byte) {
	const maxnoofBPLMNs = 12
	pv, plen, _ := per.EncSequenceOf(1, 1, maxnoofBPLMNs, false)

	for _, item := range *p {
		pv2, plen2, v2 := gnb.encBroadcastPLMNItem(&item)
		if plen != 0 {
			pv, _ = per.MergeBitField(pv, plen, pv2, plen2)
		}
		v = append(v, pv...)
		v = append(v, v2...)
		plen = 0
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

func (gnb *GNB) encBroadcastPLMNItem(p *BroadcastPLMN) (pv []byte, plen int, v []byte) {
	pv, plen, _ = per.EncSequence(true, 1, 0)
	v = append(v, gnb.encPLMNIdentity(p.MCC, p.MNC)...)
	v = append(v, encSliceSupportList(&p.SliceSupportList)...)
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
	v, _, _ = per.EncSequenceOf(1, 1, maxnoofTACs, false)

	for _, item := range *p {
		v = append(v, gnb.encSupportedTAItem(&item)...)
	}

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
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

	pv, _, _ := per.EncSequence(true, 1, 0)
	v = append(pv, gnb.encTAC(p.TAC)...)
	v = append(v, gnb.encBroadcastPLMNList(&p.BroadcastPLMNList)...)
	return
}

// UE Context Request is defined in 9.2.5.1 INITIAL UE MESSAGE
/*
UEContextRequest ::= ENUMERATED {requested, ...}
*/
func (gnb *GNB) encUEContextRequest() (v []byte, err error) {

	head, err := encProtocolIE(idUEContextRequest, ignore)

	v, _, _ = per.EncEnumerated(0, 0, 0, true)

	length, _, _ := per.EncLengthDeterminant(len(v), 0)
	head = append(head, length...)
	v = append(head, v...)
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

func readPduByteSlice(pdu *[]byte, length int) (val []byte) {
	val = (*pdu)[:length]
	*pdu = (*pdu)[length:]
	return
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
