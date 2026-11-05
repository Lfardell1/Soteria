//go:build linux

package network

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsResponseFixture() dnsmessage.Message {
	question := resolverQuestion(42)
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: question.ID, Response: true, RecursionAvailable: true},
		Questions: question.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.root-servers.net.")},
		}},
	}
}

func packDNS(t *testing.T, message dnsmessage.Message) []byte {
	t.Helper()
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestConfiguredResolverResponseValidation(t *testing.T) {
	question := resolverQuestion(42)
	if truncated, err := validateDNSResponse(packDNS(t, dnsResponseFixture()), question, true); err != nil || truncated {
		t.Fatal("valid configured-resolver root NS response rejected")
	}
	for _, edit := range []func(*dnsmessage.Message){
		func(message *dnsmessage.Message) { message.ID++ },
		func(message *dnsmessage.Message) { message.Response = false },
		func(message *dnsmessage.Message) { message.RCode = dnsmessage.RCodeServerFailure },
		func(message *dnsmessage.Message) { message.OpCode = 1 },
		func(message *dnsmessage.Message) { message.Questions = nil },
		func(message *dnsmessage.Message) { message.Questions[0].Type = dnsmessage.TypeA },
		func(message *dnsmessage.Message) {
			message.Questions[0].Name = dnsmessage.MustNewName("other.example.")
		},
		func(message *dnsmessage.Message) { message.Answers = nil },
		func(message *dnsmessage.Message) { message.Answers[0].Header.Class = dnsmessage.ClassCHAOS },
		func(message *dnsmessage.Message) {
			message.Answers[0].Header.Name = dnsmessage.MustNewName("other.example.")
		},
	} {
		message := dnsResponseFixture()
		edit(&message)
		if _, err := validateDNSResponse(packDNS(t, message), question, true); err == nil {
			t.Fatal("accepted DNS response not matching the configured probe")
		}
	}
	for _, data := range [][]byte{nil, make([]byte, 11), make([]byte, maxDNSMessage+1), {0, 1, 2, 3}} {
		if _, err := validateDNSResponse(data, question, true); err == nil {
			t.Fatal("accepted malformed or unbounded DNS response")
		}
	}
}

func TestTruncatedUDPRequiresBoundedTCPResponse(t *testing.T) {
	question := resolverQuestion(42)
	message := dnsResponseFixture()
	message.Truncated, message.Answers = true, nil
	data := packDNS(t, message)
	// A truncated packet can advertise an answer whose bytes did not fit.
	binary.BigEndian.PutUint16(data[6:8], 1)
	if truncated, err := validateDNSResponse(data, question, true); err != nil || !truncated {
		t.Fatal("valid UDP truncation did not request TCP fallback")
	}
	if _, err := validateDNSResponse(data, question, false); err == nil {
		t.Fatal("accepted truncated TCP response")
	}
	data[0]++
	if _, err := validateDNSResponse(data, question, true); err == nil {
		t.Fatal("accepted an unrelated truncated UDP response")
	}
}

func FuzzDNSResponseParser(f *testing.F) {
	message := dnsResponseFixture()
	data, err := message.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = validateDNSResponse(data, resolverQuestion(42), false)
	})
}
