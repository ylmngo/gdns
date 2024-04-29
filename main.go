package main

import (
	"bufio"
	"fmt"
	"gdns/resolver"
	"log"
	"os"
)

func main() {
	// packet, err := net.ListenPacket("udp", ":53")
	// if err != nil {
	// 	fmt.Printf("unable to get packet from port 53: %v\n", err)
	// 	return
	// }
	// defer packet.Close()
	// for {
	// 	buff := make([]byte, 512)
	// 	n, addr, err := packet.ReadFrom(buff)
	// 	if err != nil {
	// 		fmt.Printf("unable to read from packet connection: %v\n", err)
	// 		return
	// 	}
	// 	fmt.Println(addr)
	// 	dnsPacket, err := parser.NewPacketFromBuffer(buff[:n])
	// 	if err != nil {
	// 		fmt.Printf("unable to create new packet from buffer: %v\n", err)
	// 		return
	// 	}
	// 	resolver.HandleDNSPacket(resolver.RootServers, dnsPacket)
	// }

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter domain name to be resolved: ")
	for scanner.Scan() {
		domain := scanner.Text()
		fmt.Print("--------------------------------------\n\n\n")
		ip, err := resolver.ResolveDNS(domain)
		if err != nil {
			log.Fatalf("Unable to resolve dns: %v\n", err)
		}
		fmt.Printf("\n\nIP of %s: %s\n", domain, ip)
	}
}
