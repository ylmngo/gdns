package resolver

import (
	"errors"
	"fmt"
	"gdns/parser"
	"net"
)

var RootServers []string = []string{
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
}

var NewServers []string = []string{
	"192.12.94.30",
	"2001:502:1ca1::30",
	"192.33.14.30",
	"2001:503:231d::2:30",
	"192.48.79.30",
	"2001:502:7094::30",
	"192.55.83.30",
	"2001:501:b1f9::30",
	"192.43.172.30",
	"2001:503:39c1::30",
	"192.35.51.30",
}

var MoreServers []string = []string{
	"2001:4860:4802:34::a",
	"216.239.34.10",
	"2001:4860:4802:32::a",
	"216.239.32.10",
	"2001:4860:4802:36::a",
	"216.239.36.10",
	"2001:4860:4802:38::a",
	"216.239.38.10",
}

func HandleDNSPacket(rootServers []string, packet *parser.DNSPacket) (*parser.DNSPacket, error) {
	var conn net.Conn
	var err error
	for _, server := range rootServers {
		conn, err = net.Dial("udp", server+":53")
		if err == nil {
			break
		}
	}
	fmt.Println("Using server: " + conn.RemoteAddr().String())
	_, err = conn.Write(packet.Pack())
	if err != nil {
		fmt.Printf("unable to write packet to connection: %v\n", err)
		return nil, err
	}

	buff := make([]byte, 512)
	n, err := conn.Read(buff)
	if err != nil {
		fmt.Printf("unable to read from connection: %v\n", err)
		return nil, err
	}

	conn.Close()

	if n == 0 {
		return nil, errors.New("buffer length emtpy")
	}

	recvPacket, err := parser.NewPacketFromBuffer(buff[:n])
	if err != nil {
		fmt.Printf("unable to create new packet from buffer: %v\n", err)
		return nil, err
	}

	return recvPacket, nil
}

func ResolveDNS(domain string) (string, error) {
	servers := RootServers
	question := parser.NewQuestion(domain, parser.ARecords, parser.IPAddr)
	queryPacket := parser.NewQueryPacket(question)
	for {
		fmt.Printf("%s searched in: \n", domain)
		for i := 0; i < len(servers); i++ {
			fmt.Println(servers[i])
		}
		respPacket, err := HandleDNSPacket(servers, queryPacket)
		if err != nil {
			return "", err
		}
		if respPacket.IsAuthority() {
			return respPacket.Answer[0].RDATA, nil
		}
		if len(respPacket.Additional) > 0 {
			newServers := make([]string, 0)
			for i := 0; i < len(respPacket.Additional); i++ {
				newServers = append(newServers, respPacket.Additional[i].RDATA)
			}
			servers = newServers
		}
		fmt.Println("-------------------------------------")
	}
}
