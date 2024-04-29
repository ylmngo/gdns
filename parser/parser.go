package parser

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
)

var (
	ARecords    = [2]byte{0b0000_0000, 0b0000_0001}
	NSRecord    = [2]byte{0b0000_0000, 0b0000_0010}
	AAAARecords = [2]byte{0b0000_0000, 0b0001_1100}
)

var (
	IPAddr = [2]byte{0b0000_0000, 0b0000_0001}
)

type DNSPacket struct {
	Header     DNSHeader
	Question   []DNSQuestion
	Answer     []DNSAnswer
	NSRecord   []DNSAnswer
	Additional []DNSAnswer
	offset     int
	buff       []byte
}

type DNSHeader struct {
	ID      uint16 // random 16 bit number generated for each request and copied to the response
	QR      bool   // specifies whether the message is a query(false) or response(true)
	OPCODE  byte   // specifies the kind of query in the message, standard query - 0
	AA      byte   // specifies that the responding name server is an authority for the domain name in question
	TC      byte   // specifies that this message was truncated
	RD      byte   // directs the name server to pursue the query recursively
	RA      byte   // denotes whether recursive query support is available in the name server. Exit and return error if the server does not support recursion
	Z       byte   // reserved for future use
	RCODE   byte   // response code, 0 No error condition, 1 - format error, 2 - server failure, 3 - name error, 4 - not implemented, 5 - refused
	QDCOUNT uint16 // number of entries in the question section
	ANCOUNT uint16 // number of resource records in the answer section
	NSCOUNT uint16 // number of name server resource records in the authority records section
	ARCOUNT uint16 // number of resource records in teh additional records section
}

type DNSQuestion struct {
	QNAME  [][]string
	QTYPE  [2]byte
	QCLASS [2]byte
}

type DNSAnswer struct {
	NAME     [][]string
	TYPE     [2]byte
	CLASS    [2]byte
	TTL      [4]byte
	RDLENGTH [2]byte
	RDATA    string
}

func NewQuestion(qname string, qtype [2]byte, qclass [2]byte) DNSQuestion {
	var qn string
	if strings.EqualFold(qname[:4], "www.") {
		qn = qname[4:]
	} else {
		qn = qname
	}

	return DNSQuestion{
		QNAME:  [][]string{strings.Split(qn, ".")},
		QTYPE:  qtype,
		QCLASS: qclass,
	}
}

func NewQueryPacket(question DNSQuestion) *DNSPacket {
	nheader := DNSHeader{
		ID:      uint16(rand.Uint32()),
		QR:      false,
		OPCODE:  0,
		QDCOUNT: 1,
	}

	return &DNSPacket{
		Header:   nheader,
		Question: []DNSQuestion{question},
	}
}

func NewPacketFromBuffer(buff []byte) (*DNSPacket, error) {
	packet := &DNSPacket{}
	packet.buff = buff

	header := packet.parseDNSHeader(buff[:12])
	packet.Header = *header
	packet.offset = 12

	questions, err := packet.GetQuestions()
	if err != nil {
		return nil, err
	}
	packet.Question = questions

	answers := packet.GetAnswers()
	packet.Answer = answers

	nsrecords := packet.GetNSRecords()
	packet.NSRecord = nsrecords

	additionals := packet.GetAddtionals()
	packet.Additional = additionals

	return packet, nil
}

func (packet *DNSPacket) Pack() []byte {
	buff := make([]byte, 512)
	offset := 0

	offset = packet.packDNSHeader(buff, offset)
	offset = packet.packDNSQuestion(buff, offset)

	return buff[:offset]
}

func (packet *DNSPacket) packDNSHeader(buff []byte, offset int) int {
	binary.BigEndian.PutUint16(buff[offset:offset+2], packet.Header.ID)
	offset += 2

	if packet.Header.QR {
		buff[offset] |= 1
		buff[offset] <<= 7
	}

	buff[offset] |= packet.Header.OPCODE
	buff[offset] |= packet.Header.AA
	buff[offset] |= packet.Header.TC
	buff[offset] |= packet.Header.RD

	offset += 1

	buff[offset] |= packet.Header.RA
	buff[offset] |= packet.Header.RA
	buff[offset] |= packet.Header.Z
	buff[offset] |= packet.Header.RCODE

	offset += 1

	binary.BigEndian.PutUint16(buff[offset:offset+2], packet.Header.QDCOUNT)
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], packet.Header.ANCOUNT)
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], packet.Header.NSCOUNT)
	offset += 2

	binary.BigEndian.PutUint16(buff[offset:offset+2], packet.Header.ARCOUNT)

	return offset + 2
}

func (packet *DNSPacket) packDNSQuestion(buff []byte, offset int) int {
	for _, qns := range packet.Question[0].QNAME {
		for _, qn := range qns {
			buff[offset] = uint8(len(qn))
			copy(buff[offset+1:], []byte(qn))
			offset += len(qn) + 1
		}
	}
	buff[offset] = 0
	offset += 1

	copy(buff[offset:], packet.Question[0].QTYPE[:])
	offset += 2
	copy(buff[offset:], packet.Question[0].QCLASS[:])
	offset += 2

	return offset
}

func (packet *DNSPacket) parseDNSHeader(buff []byte) *DNSHeader {
	header := &DNSHeader{}

	header.ID = binary.BigEndian.Uint16(buff[:2])
	header.QR = (buff[2] & 0b1000_0000) == 0b1000_0000
	header.OPCODE = buff[2] & 0b0111_1000
	header.AA = buff[2] & 0b0000_0100
	header.TC = buff[2] & 0b0000_0010
	header.RD = buff[2] & 0b0000_0001
	header.RA = buff[3] & 0b1000_0000
	header.Z = buff[3] & 0b0111_0000
	header.RCODE = buff[3] & 0b0000_1111
	header.QDCOUNT = binary.BigEndian.Uint16(buff[4:6])
	header.ANCOUNT = binary.BigEndian.Uint16(buff[6:8])
	header.NSCOUNT = binary.BigEndian.Uint16(buff[8:10])
	header.ARCOUNT = binary.BigEndian.Uint16(buff[10:12])

	return header
}

// parses the buffer for DNS Question and returns the number of bytes parsed
func (packet *DNSPacket) parseDNSQuestion(buff []byte) (*DNSQuestion, int, error) {
	question := &DNSQuestion{}
	rd := bufio.NewReader(bytes.NewReader(buff))
	builder := strings.Builder{}

	for i := 0; i < int(packet.Header.QDCOUNT); i++ {
		qn := make([]string, 0)
		for {
			octlen, err := rd.ReadByte()
			if err != nil {
				return nil, 0, err
			}
			if int(octlen) == 0 {
				break
			}
			for j := 0; j < int(octlen); j++ {
				x, err := rd.ReadByte()
				if err != nil {
					return nil, 0, err
				}
				builder.WriteByte(x)
			}
			qn = append(qn, builder.String())
			builder.Reset()
		}
		question.QNAME = append(question.QNAME, qn)
	}

	rd.Read(question.QTYPE[:])
	rd.Read(question.QCLASS[:])

	return question, (len(buff) - rd.Buffered()), nil
}

func (packet *DNSPacket) GetQuestions() ([]DNSQuestion, error) {
	questions := make([]DNSQuestion, 0)
	for i := 0; i < int(packet.Header.QDCOUNT); i++ {
		question, n, err := packet.parseDNSQuestion(packet.buff[packet.offset:])
		if err != nil {
			return nil, err
		}
		packet.offset += n
		questions = append(questions, *question)
	}

	return questions, nil
}

func (packet *DNSPacket) GetAnswers() []DNSAnswer {
	answers := make([]DNSAnswer, 0)
	for i := 0; i < int(packet.Header.ANCOUNT); i++ {
		answer := packet.parseDNSRecord()
		answers = append(answers, answer)
	}

	return answers
}

func (packet *DNSPacket) GetNSRecords() []DNSAnswer {
	nsrecords := make([]DNSAnswer, 0)
	for i := 0; i < int(packet.Header.NSCOUNT); i++ {
		nsrecord := packet.parseDNSRecord()
		nsrecords = append(nsrecords, nsrecord)
	}

	return nsrecords
}

func (packet *DNSPacket) GetAddtionals() []DNSAnswer {
	additionals := make([]DNSAnswer, 0)
	for i := 0; i < int(packet.Header.ARCOUNT); i++ {
		additional := packet.parseDNSRecord()
		additionals = append(additionals, additional)
	}

	// a1 := packet.parseDNSRecord()
	// a2 := packet.parseDNSRecord()
	return additionals
}

func (packet *DNSPacket) parseDNSRecord() DNSAnswer {
	record := &DNSAnswer{}

	// The first two bytes contain the pointer to a prior occurrence of the domain name
	// thus the first two bytes can be skipped

	record.NAME = packet.Question[0].QNAME
	packet.offset += 2

	copy(record.TYPE[:], packet.buff[packet.offset:packet.offset+2])
	packet.offset += 2

	copy(record.CLASS[:], packet.buff[packet.offset:packet.offset+2])
	packet.offset += 2

	copy(record.TTL[:], packet.buff[packet.offset:packet.offset+2])
	packet.offset += 4

	copy(record.RDLENGTH[:], packet.buff[packet.offset:packet.offset+2])
	packet.offset += 2

	rdlen := int(binary.BigEndian.Uint16(record.RDLENGTH[:]))

	switch record.TYPE {
	case ARecords, AAAARecords:
		rdata := make([]byte, rdlen)
		copy(rdata, packet.buff[packet.offset:packet.offset+rdlen])
		record.RDATA = net.IP(rdata).String()
		packet.offset += rdlen
	case NSRecord:
		nameserver := make([]string, 0)
		var save int = packet.offset
		for {
			octlen := int(packet.buff[packet.offset])
			packet.offset += 1

			if octlen == 0 {
				break
			}

			if (byte(octlen) & 0xC0) == 0xC0 {
				jmp := int(packet.buff[packet.offset])
				for {
					noctlen := int(packet.buff[jmp])
					jmp += 1
					if noctlen == 0 {
						break
					}
					pt := make([]byte, noctlen)
					copy(pt, packet.buff[jmp:jmp+noctlen])
					jmp += noctlen
					nameserver = append(nameserver, string(pt))
				}
				break
			}

			part := make([]byte, octlen)
			copy(part, packet.buff[packet.offset:packet.offset+octlen])
			packet.offset += octlen
			nameserver = append(nameserver, string(part))
		}
		packet.offset = save + rdlen
		record.RDATA = strings.Join(nameserver, ".")
	}

	return *record
}

func (packet *DNSPacket) IsAuthority() bool {
	return !(packet.Header.AA == 0)
}
