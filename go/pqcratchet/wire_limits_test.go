package pqcratchet_test

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/go/pqcratchet"
)

// A message well over the old 1 MiB cap goes through Seal and Open.
func TestSealOpenLargeMessage(t *testing.T) {
	alice, bob := setupSessions(t)
	plaintext := bytes.Repeat([]byte{0xA5}, 2<<20)

	wire, err := alice.Seal(plaintext)
	must(t, err, "Seal")
	got, err := bob.Open(wire)
	must(t, err, "Open")
	if !bytes.Equal(got, plaintext) {
		t.Fatal("the large message did not round-trip")
	}
}

// allocatedDuring reports the bytes allocated while f runs.
func allocatedDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// setLength overwrites the 4-byte big-endian length field that ends at the given offset from the end.
func setLength(wire []byte, fromEnd int, n uint32) {
	binary.BigEndian.PutUint32(wire[len(wire)-fromEnd-4:], n)
}

// A short message claiming a huge ciphertext fails without allocating what it claims.
func TestUnmarshalMessageForgedLengthDoesNotAllocate(t *testing.T) {
	alice, _ := setupSessions(t)
	enc, err := alice.EncryptMessage([]byte("hi"))
	must(t, err, "EncryptMessage")
	inner := pqc.MarshalMessageProtocol(&pqc.ParsedMessageProtocol{
		Counter:          uint32(enc.Counter),
		SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT:        enc.RatchetCT,
		CipherText:       enc.Ciphertext,
	})
	ctLen := len(enc.Ciphertext)

	var parseErr error
	allocated := allocatedDuring(func() {
		forged := append([]byte(nil), inner...)
		setLength(forged, ctLen, 100<<20)
		_, parseErr = pqc.UnmarshalMessageProtocol(forged)
	})
	if parseErr == nil {
		t.Fatal("a ciphertext length past the end of the message was accepted")
	}
	if allocated > 1<<20 {
		t.Fatalf("a forged length cost %d bytes of allocation", allocated)
	}

	over := append([]byte(nil), inner...)
	setLength(over, ctLen, 128<<20+1)
	if _, err := pqc.UnmarshalMessageProtocol(over); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("a length over the cap was not refused as such: %v", err)
	}
}

// The same holds for the message bundled in a PreKeyMessage, parsed before anything is authenticated.
func TestUnmarshalPreKeyMessageForgedLengthDoesNotAllocate(t *testing.T) {
	msg := &pqc.PreKeyMessageWire{SignedMessageBytes: []byte{1, 2, 3}}
	wire := pqc.MarshalPreKeyMessageWire(msg)

	var parseErr error
	allocated := allocatedDuring(func() {
		forged := append([]byte(nil), wire...)
		setLength(forged, len(msg.SignedMessageBytes), 100<<20)
		_, parseErr = pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(forged))
	})
	if parseErr == nil {
		t.Fatal("a bundled message length past the end of the input was accepted")
	}
	if allocated > 1<<20 {
		t.Fatalf("a forged length cost %d bytes of allocation", allocated)
	}
}
