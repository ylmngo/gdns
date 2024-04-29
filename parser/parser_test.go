package parser

import (
	"bytes"
	"os"
	"testing"
)

func TestNewPacketFromBuffer(t *testing.T) {
	var TEST_FILES = []string{"query_packet.txt", "response_packet.txt"}
	for i := 0; i < len(TEST_FILES); i++ {
		data, err := os.ReadFile(TEST_FILES[i])
		if err != nil {
			t.Fatalf("unable to open file %s: %v\n", TEST_FILES[i], err)
		}

		buff := make([]byte, 512)
		n := copy(buff, data)

		packet, err := NewPacketFromBuffer(buff[:n])
		if err != nil {
			t.Fatalf("unable to create new dns packet: %v\n", err)
		}

		t.Logf("%+v\n", packet.Header)
		t.Logf("%+v\n", packet.Question)
		t.Logf("%+v\n", packet.Answer)

		if TEST_FILES[i] == "query_packet.txt" {
			t.Run("Test Pack", func(t *testing.T) {
				packedBytes := packet.Pack()
				if !bytes.Equal(buff[:n], packedBytes) {
					t.Fatal("data and packed bytes are not same")
				}
			})
		}

		// t.Log(net.IP(packet.Answer.RDATA).String())
	}

	t.Log("tests passed succesfully\n")
}

func TestNewQuestion(t *testing.T) {
	var testCases []string = []string{"www.google.com", "google.com"}
	for _, test := range testCases {
		question := NewQuestion(test, ARecords, IPAddr)
		t.Logf("%v\n", question)
	}
}
