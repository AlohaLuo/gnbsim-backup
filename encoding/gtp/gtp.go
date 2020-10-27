// Copyright 2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package gtp is implementation for GTPv1-U in the 5GS Sytem.
// document version: 3GPP TS 29.281 v16.1.0 (2020-09)

package gtp

import (
	"net"
)

const (
	Port = 2152
)

type GTP struct {
	IFname    string
	LocalAddr net.IP
	PeerAddr  net.IP
	LocalTEID uint32
	PeerTEID  uint32

	hasExtensionHeader bool
	hasSequenceNumber  bool
	hasNPDUNumber      bool
}

func NewGTP() (p *GTP) {

	var gtp GTP
	p = &gtp

	return
}

// 5 GTP-U header
// 5.1 General format
type Header struct {
	versAndFlags   uint8
	protocolType   uint8
	messageType    uint8
	length         uint16
	teid           uint32
	seq            uint16
	npduNumber     uint8
	nextHeaderType uint8
}

// 5.2 GTP-U Extension Header
// 5.2.1 General format of the GTP-U Extension Header
const (
	extHeaderTypeNone                = 0x00
	extHeaderTypePDUSessionContainer = 0x85
)

type ExtensionHeader struct {
	headerLength   uint8
	content        []byte
	nextHeaderType uint8
}

// 5.2.2.7 PDU Session Container
// x.x.x.x. in TS 38.415

func (gtp *GTP) Encap(pdu *[]byte) {
	return
}

func (gtp *GTP) Decap(pdu *[]byte) {
	return
}
