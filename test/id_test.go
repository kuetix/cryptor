package uuid_test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	kuuid "github.com/kuetix/uuid"
)

func TestIdV5_DeterministicAndDistinct(t *testing.T) {
	id1 := kuuid.IdV5("test")
	id2 := kuuid.IdV5("test")
	if id1 != id2 {
		t.Fatalf("IdV5 should be deterministic: %s vs %s", id1, id2)
	}

	idA := kuuid.IdV5("A")
	idB := kuuid.IdV5("B")
	if idA == idB {
		t.Fatalf("IdV5 should differ for different identities: %s vs %s", idA, idB)
	}

	// Version should be 5
	if v := id1.Version(); v != 5 {
		t.Fatalf("expected version 5, got %d", v)
	}
}

func TestBase64Id_RoundTrip(t *testing.T) {
	b64 := kuuid.Base64Id("test")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("invalid base64 produced: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("uuid binary should be 16 bytes, got %d", len(raw))
	}
}

func TestUUId_Format(t *testing.T) {
	s := kuuid.UUId("test")
	if len(s) != 36 {
		t.Fatalf("expected canonical uuid string of length 36, got %d (%s)", len(s), s)
	}
	if strings.Count(s, "-") != 4 {
		t.Fatalf("expected 4 dashes in canonical uuid string: %s", s)
	}
}

func TestId_FormatAndConsistency(t *testing.T) {
	// Id returns a 32-char hex string without dashes
	s := kuuid.Id("test")
	if len(s) != 32 {
		t.Fatalf("expected 32-char hex string without dashes, got %d (%s)", len(s), s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Fatalf("Id should be hex-only: %v", err)
	}

	// Consistency: Id(identity) == UId(UUId(identity))
	s2 := kuuid.UId(kuuid.UUId("test"))
	if s != s2 {
		t.Fatalf("Id should equal UId(UUId(identity)): %s vs %s", s, s2)
	}
}

func TestUId_RemovesDashes(t *testing.T) {
	canonical := kuuid.UUId("test")
	noDash := kuuid.UId(canonical)
	if strings.Contains(noDash, "-") {
		t.Fatalf("UId should remove dashes: %s", noDash)
	}
	if len(noDash) != 32 {
		t.Fatalf("UId should return 32-char hex without dashes, got %d (%s)", len(noDash), noDash)
	}
}

func TestParsed_Normalizes(t *testing.T) {
	canonical := kuuid.UUId("test")
	upper := strings.ToUpper(canonical)
	normalized := kuuid.Parsed(upper)
	if normalized != canonical {
		t.Fatalf("Parsed should return canonical-lowercase form: %s vs %s", normalized, canonical)
	}
}

func TestUUIDToInt_BytesMatchMarshalBinary(t *testing.T) {
	u := kuuid.IdV5("test")
	b1 := kuuid.UUIDToInt(u)
	b2, err := u.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}
	if len(b1) != 16 || len(b2) != 16 {
		t.Fatalf("uuid bytes must be 16; got %d and %d", len(b1), len(b2))
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			t.Fatalf("byte mismatch at %d: %d vs %d", i, b1[i], b2[i])
		}
	}
}

func BenchmarkIdV5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = kuuid.IdV5("test")
	}
}
