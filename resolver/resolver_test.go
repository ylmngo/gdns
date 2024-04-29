package resolver

import (
	"gdns/parser"
	"testing"
)

// func TestHandleDNSPacket(t *testing.T) {
// 	packet, _ := net.ListenPacket("udp", ":53")
// 	defer packet.Close()
// 	for {
// 		buff := make([]byte, 512)
// 		n, addr, _ := packet.ReadFrom(buff)
// 		t.Log(addr)
// 		dnsPacket, err := parser.NewPacketFromBuffer(buff[:n])
// 		if err != nil {
// 			fmt.Printf("unable to create new packet from buffer: %v\n", err)
// 			return
// 		}
// 		if err = HandleDNSPacket(dnsPacket); err != nil {
// 			t.Fatalf("unable to handle dns packet: %v\n", err)
// 		}
// 	}
// }

func TestHandleDNSPacket(t *testing.T) {
	question := parser.NewQuestion("www.youtube.com", parser.ARecords, parser.IPAddr)
	sendPacket := parser.NewQueryPacket(question)
	t.Logf("Send Packet: %+v\n", sendPacket.Header)
	t.Logf("Send Packet: %+v\n", sendPacket.Question)
	t.Logf("Send Packet: %+v\n", sendPacket.Answer)
	if recvPacket, err := HandleDNSPacket(MoreServers, sendPacket); err != nil {
		t.Fatalf("error while handling dns packet: %v\n", err)
	} else {
		t.Logf("Recieve Packet Header: %+v\n", recvPacket.Header)
		t.Logf("Recieve Packet Question: %+v\n", recvPacket.Question)
		t.Logf("Recieve Packet Answer: %+v\n", recvPacket.Answer)
		for i := 0; i < len(recvPacket.NSRecord); i++ {
			t.Logf("Recieve Packet NSRecord: %+v\n", recvPacket.NSRecord[i])
		}
		for i := 0; i < len(recvPacket.Additional); i++ {
			t.Logf("Recieve Packet Additional: %+v\n", recvPacket.Additional[i])
		}

		for i := 0; i < len(recvPacket.Additional); i++ {
			t.Logf("New Servers: %v\n", recvPacket.Additional[i].RDATA)
		}

		// buff := bytes.NewBuffer(recvPacket.Answer.RDATA)
		// nameservers := make([]string, 0)
		// for {
		// 	octlen, _ := buff.ReadByte()
		// 	if int(octlen) == 0 {
		// 		break
		// 	}
		// 	ns := make([]byte, octlen)
		// 	n, _ := buff.Read(ns)
		// 	nameservers = append(nameservers, string(ns[:n]))
		// }
		// t.Log(strings.Join(nameservers, "."))
	}

}

func TestResolveDNS(t *testing.T) {
	if ip, err := ResolveDNS("www.amazon.com"); err != nil {
		t.Fatalf("unable to resolve dns: %v\n", err)
	} else {
		t.Log(ip)
	}
}
