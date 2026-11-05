//go:build linux

package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

const (
	resolverTimeout = 2 * time.Second
	maxDNSMessage   = 4096
)

// A root NS query needs no third-party probe hostname or health service. Only
// the literal configured resolver receives traffic, through the owned link.
func resolverQuestion(id uint16) dnsmessage.Message {
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}},
	}
}

func probeResolvers(ctx context.Context, linkName string, profile Profile) error {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return errors.New("generate resolver query identifier failed")
	}
	question := resolverQuestion(binary.BigEndian.Uint16(idBytes[:]))
	query, err := question.Pack()
	if err != nil {
		return errors.New("construct resolver query failed")
	}
	var last error
	for _, server := range profile.DNS {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := probeResolver(ctx, linkName, profile.Address.Addr(), server, query, question); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return errors.Join(errors.New("none of the configured IPv4 resolvers answered a valid DNS probe"), last)
}

func probeResolver(ctx context.Context, linkName string, source, server netip.Addr, query []byte, question dnsmessage.Message) error {
	response, err := exchangeDNS(ctx, "udp4", linkName, source, server, query)
	if err != nil {
		return err
	}
	truncated, err := validateDNSResponse(response, question, true)
	if err != nil {
		return err
	}
	if !truncated {
		return nil
	}
	response, err = exchangeDNS(ctx, "tcp4", linkName, source, server, query)
	if err != nil {
		return err
	}
	_, err = validateDNSResponse(response, question, false)
	return err
}

func exchangeDNS(ctx context.Context, network, linkName string, source, server netip.Addr, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, resolverTimeout)
	defer cancel()
	dialer := net.Dialer{
		Timeout: resolverTimeout,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, linkName)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	if network == "udp4" {
		dialer.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
	} else if network == "tcp4" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
	} else {
		return nil, errors.New("unsupported resolver transport")
	}
	connection, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(server, 53).String())
	if err != nil {
		return nil, fmt.Errorf("dial configured resolver: %w", err)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if network == "udp4" {
		if _, err := connection.Write(query); err != nil {
			return nil, err
		}
		response := make([]byte, 513)
		n, err := connection.Read(response)
		if err != nil {
			return nil, err
		}
		if n > 512 {
			return nil, errors.New("oversized UDP DNS response")
		}
		return response[:n], nil
	}
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 || n > maxDNSMessage {
		return nil, errors.New("TCP DNS response exceeds the permitted bound")
	}
	response := make([]byte, n)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func validateDNSResponse(data []byte, question dnsmessage.Message, allowTruncated bool) (bool, error) {
	if len(data) < 12 || len(data) > maxDNSMessage || len(question.Questions) != 1 {
		return false, errors.New("invalid DNS response size or question")
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(data)
	if err != nil {
		return false, errors.New("malformed configured-resolver DNS response")
	}
	questions, err := parser.AllQuestions()
	if err != nil || !header.Response || header.ID != question.ID || header.OpCode != 0 || header.RCode != dnsmessage.RCodeSuccess ||
		len(questions) != 1 || questions[0] != question.Questions[0] {
		return false, errors.New("configured-resolver DNS response does not match the query")
	}
	if header.Truncated {
		if allowTruncated {
			return true, nil
		}
		return false, errors.New("configured resolver returned a truncated TCP DNS response")
	}
	var response dnsmessage.Message
	if err := response.Unpack(data); err != nil {
		return false, errors.New("malformed configured-resolver DNS response")
	}
	for _, answer := range response.Answers {
		if answer.Header.Name == question.Questions[0].Name && answer.Header.Type == dnsmessage.TypeNS && answer.Header.Class == dnsmessage.ClassINET {
			if _, ok := answer.Body.(*dnsmessage.NSResource); ok {
				return false, nil
			}
		}
	}
	return false, errors.New("configured resolver did not answer the root NS query")
}
