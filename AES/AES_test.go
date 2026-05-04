package AES

import (
	"bytes"
	"strings"
	"testing"
)

// =============================================================================
// F-MED-013 (audit cycle 2026-05-04, v4.0.2): AES package behavior tests.
// =============================================================================
//
// Pre-v4.0.2 the AES/ package had only `BitStringToHex_doc_test.go` —
// a documentation lock for the AES-4 / F-ERR-004 odd-nibble truncation
// edge case. The core encrypt/decrypt/KDF/scrub surface
// (`EncryptBitString`, `DecryptBitString`, `MakeKeyFromPassword`,
// `ZeroBytes`) had no direct tests. Correctness was gated only by
// `keystore_test.go`'s indirect roundtrip through ExportPrivateKey →
// ImportPrivateKey, which runs the full wallet ceremony — masking
// regressions in any individual primitive.
//
// This file closes the gap with five test families:
//
//   1. Round-trip integrity. Encrypt then decrypt with the same password
//      must return the exact input bitstring. Run across the size
//      spectrum the production code exercises (1600-bit Genesis scalars,
//      shorter and longer payloads).
//
//   2. Wrong-password rejection. AES-256-GCM is authenticated: a
//      tampered nonce, ciphertext, or wrong-password decrypt MUST
//      return a non-nil error rather than silent garbage. The v2.1.0
//      AES-3 hardening installed this short-circuit; this test locks
//      it in place.
//
//   3. KDF determinism. MakeKeyFromPassword is a pure function of its
//      input — same password, same key, every time. Critical because
//      the wallet decrypt path re-derives the key from the user's
//      password on every invocation; non-determinism would break
//      decryption.
//
//   4. Nonce randomness (statistical sanity). Two encrypts of the same
//      plaintext with the same password MUST produce different
//      ciphertexts (because the GCM nonce is random per call). A
//      regression that re-uses a fixed nonce across calls would
//      silently break GCM's confidentiality guarantee.
//
//   5. ZeroBytes scrub. ZeroBytes is a security primitive: it MUST
//      overwrite every byte. A zero-length or nil input must not
//      panic. The v2.1.0 KG-3 hardening relies on this.
//
// The existing `BitStringToHex_doc_test.go` in this package locks the
// AES-4 / F-ERR-004 documented odd-nibble behavior — keep it; this
// file tests are complementary.

// encryptDecryptRetry wraps EncryptBitString + DecryptBitString in a
// retry loop to handle the documented AES-1 / AES-2 round-trip edge
// case (NOT-FIXED-BY-DESIGN per CLAUDE.md "Hardening catalogue"). When
// EncryptBitString happens to produce a ciphertext whose canonical
// `bigInt.Text(2)` strips leading zero bits, the binary→bigint→hex
// round-trip on the decrypt side loses bytes and AES-GCM tag
// verification fails. Per-call probability ~1/16; the keystore test
// suite uses the same retry pattern (see keystore/import_test.go's
// roundTripFixture, max 100 attempts).
//
// Returns the FIRST successfully-round-tripped (cipher, plain) pair
// or fails the test if 100 consecutive attempts hit the edge case
// (probability ~1e-117 — a real bug, not a flake).
func encryptDecryptRetry(t *testing.T, bits, password string) (cipher, plain string) {
	t.Helper()
	const maxAttempts = 100
	for attempt := 0; attempt < maxAttempts; attempt++ {
		c := EncryptBitString(bits, password)
		if c == "" {
			t.Fatalf("EncryptBitString unexpectedly returned empty (attempt %d)", attempt+1)
		}
		p, err := DecryptBitString(c, password)
		if err == nil && p == bits {
			return c, p
		}
	}
	t.Fatalf("could not produce a round-trip-stable ciphertext for %d-bit input in %d attempts (AES-1/AES-2 retry budget exhausted; suggests a real bug, not the documented edge case)", len(bits), maxAttempts)
	return "", ""
}

// genesisLikeBitString returns a bitstring shaped like a real DALOS
// Genesis scalar (1600 bits, leading 1 + cofactor-4 tail = ends in
// "00"). The middle is a deterministic pattern so test failures are
// reproducible. Not derived from any real key — the bit-shape is what
// matters for exercising the production-sized payload through
// EncryptBitString / DecryptBitString.
func genesisLikeBitString() string {
	var b strings.Builder
	b.Grow(1600)
	b.WriteByte('1')                     // clamping bit
	for i := 0; i < 1597; i++ {          // 1597 middle bits
		if i%3 == 0 {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	b.WriteString("00") // cofactor-4 tail
	return b.String()
}

// TestEncryptDecrypt_RoundTrip locks the round-trip integrity contract:
// for any password, EncryptBitString followed by DecryptBitString with
// the SAME password returns the original bitstring byte-for-byte.
//
// Run across short / Genesis-sized / long inputs to exercise the size
// spectrum. The Genesis-sized case is the production-critical one —
// every wallet write/read cycle in the field hits this path.
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	const password = "test-password-1234567" // 21 chars, satisfies the F-MED-004 16-char minimum imposed at the CLI layer

	// Inputs are deliberately chosen to be even-hex-aligned: their bigint
	// representation has an even number of hex characters, so the
	// BitStringToHex AES-4 / F-ERR-004 odd-nibble truncation does NOT
	// fire and the round-trip is bit-exact. The odd-nibble drop has
	// its own dedicated test in BitStringToHex_doc_test.go — testing
	// the documented quirk through the AES path here would conflate
	// what each test file is responsible for.
	//
	// Even-hex-aligned check: bigint(bits).Text(16) must have len%2 == 0.
	// "10101010" → 0xaa (2 chars, even ✓). "1" → "1" (1 char, odd — would fail).
	// "11111111" → 0xff (2 chars, even ✓). The 1600-bit Genesis pattern is
	// constructed so its bigint hex is exactly 400 chars (even).
	cases := []struct {
		name string
		bits string
	}{
		{"byte-aligned-tiny", "10101010"},
		{"two-bytes-aligned", "1111111100000000"},
		{"genesis-1600bit", genesisLikeBitString()},
		{"long-3200bit", genesisLikeBitString() + genesisLikeBitString()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cipher, plain := encryptDecryptRetry(t, tc.bits, password)
			if cipher == tc.bits {
				// Astronomically improbable but worth catching: a regression
				// where Encrypt becomes a no-op would silently break key
				// confidentiality.
				t.Fatalf("EncryptBitString returned the input unchanged — encryption is a no-op!")
			}
			if plain != tc.bits {
				// encryptDecryptRetry already enforces equality before
				// returning, so reaching this point with a mismatch would
				// indicate a logic bug in the helper itself.
				t.Fatalf("encryptDecryptRetry returned mismatched (cipher, plain) pair — helper invariant violated")
			}
		})
	}
}

// TestDecrypt_WrongPassword locks the v2.1.0 AES-3 hardening: a wrong
// password MUST return a non-nil error from DecryptBitString. Pre-v2.1.0
// this printed an error and returned garbage; that produced silent
// corruption further down the pipeline.
func TestDecrypt_WrongPassword(t *testing.T) {
	const correctPassword = "correct-password-1234"
	const wrongPassword = "wrong-password-12345678"
	bits := genesisLikeBitString()

	// Use the retry helper to first lock down a known-good ciphertext
	// (avoids interleaving the AES-1/AES-2 round-trip flake with the
	// wrong-password assertion this test is actually about).
	cipher, _ := encryptDecryptRetry(t, bits, correctPassword)

	plain, err := DecryptBitString(cipher, wrongPassword)
	if err == nil {
		t.Fatalf("DecryptBitString with wrong password returned err=nil — AES-GCM authentication failure is being swallowed! Plaintext returned: %q (len=%d)", plain[:min(80, len(plain))], len(plain))
	}
	if plain != "" {
		t.Fatalf("DecryptBitString with wrong password returned non-empty plaintext alongside error — should return ('', err) per the v2.1.0 short-circuit contract. Got plain=%q", plain[:min(80, len(plain))])
	}

	// Sanity: error message should mention the failure mode (the v2.1.0
	// fix wrapped the GCM Open error with explicit context). Don't lock
	// the exact wording — just confirm the wrapper is in place.
	if !strings.Contains(err.Error(), "AES DecryptBitString") {
		t.Errorf("DecryptBitString error missing context wrapper: %q (expected substring 'AES DecryptBitString' from the v2.1.0 fmt.Errorf wrap)", err.Error())
	}
}

// TestDecrypt_TamperedCiphertext locks GCM authentication on the
// ciphertext path: flipping a bit in the ciphertext MUST cause the
// AEAD tag to fail verification. Catches regressions where GCM is
// downgraded to a non-authenticated mode or the tag check is bypassed.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	const password = "test-password-1234567"
	bits := genesisLikeBitString()
	cipher, _ := encryptDecryptRetry(t, bits, password)

	// Flip a bit in the middle of the ciphertext bitstring. The middle
	// is past the nonce (12 bytes = 96 bits) and well inside the
	// ciphertext+tag region.
	mid := len(cipher) / 2
	tamperedRunes := []byte(cipher)
	if tamperedRunes[mid] == '0' {
		tamperedRunes[mid] = '1'
	} else {
		tamperedRunes[mid] = '0'
	}
	tampered := string(tamperedRunes)

	plain, err := DecryptBitString(tampered, password)
	if err == nil {
		t.Fatalf("DecryptBitString accepted tampered ciphertext (GCM authentication is broken!) Plaintext returned: %q", plain[:min(80, len(plain))])
	}
	if plain != "" {
		t.Fatalf("DecryptBitString returned non-empty plaintext on tampered ciphertext: %q", plain[:min(80, len(plain))])
	}
}

// TestMakeKeyFromPassword_Deterministic locks the KDF determinism
// contract. The wallet decrypt path re-derives the AES key from the
// password on every invocation; a non-deterministic KDF would break
// decryption entirely.
func TestMakeKeyFromPassword_Deterministic(t *testing.T) {
	cases := []string{
		"",                                              // empty (edge)
		"a",                                             // 1 byte
		"test-password-1234567",                         // typical
		strings.Repeat("password", 100),                 // long
		"\x00\x01\x02\x03\xff\xfe",                      // non-printable bytes
		"パスワード",                                       // unicode
	}
	for _, pwd := range cases {
		// Don't subtest by password content — empty / unicode would
		// produce ugly subtest names. Just iterate.
		k1 := MakeKeyFromPassword(pwd)
		k2 := MakeKeyFromPassword(pwd)
		if !bytes.Equal(k1, k2) {
			t.Fatalf("MakeKeyFromPassword non-deterministic for password %q:\n  k1: %x\n  k2: %x", pwd, k1, k2)
		}
		if len(k1) != 32 {
			t.Errorf("MakeKeyFromPassword for password %q produced key of len %d, expected 32", pwd, len(k1))
		}
	}
}

// TestMakeKeyFromPassword_DifferentPasswordsDifferentKeys locks that the
// KDF actually depends on the input. Catches regressions where the KDF
// silently returns a constant key (would be catastrophic for security).
func TestMakeKeyFromPassword_DifferentPasswordsDifferentKeys(t *testing.T) {
	pairs := []struct{ a, b string }{
		{"password1", "password2"},
		{"a", "b"},
		{"", "x"},
		{"correct horse battery staple", "correct horse battery stapla"}, // 1-char diff
	}
	for _, p := range pairs {
		ka := MakeKeyFromPassword(p.a)
		kb := MakeKeyFromPassword(p.b)
		if bytes.Equal(ka, kb) {
			t.Fatalf("MakeKeyFromPassword collision for distinct passwords %q vs %q:\n  key: %x", p.a, p.b, ka)
		}
	}
}

// TestEncrypt_NonceRandomness locks that two encrypts of the same
// plaintext with the same password produce DIFFERENT ciphertexts. AES-GCM
// requires unique nonces per key; the implementation uses crypto/rand
// for the nonce. A regression that fixed the nonce (e.g., reused a zero
// nonce) would break GCM's confidentiality guarantee — same-plaintext
// encryptions would be visibly identical, and an attacker observing
// two such pairs could XOR them to recover plaintext XORs.
func TestEncrypt_NonceRandomness(t *testing.T) {
	const password = "test-password-1234567"
	bits := genesisLikeBitString()

	// We deliberately do NOT round-trip these ciphertexts (the AES-1/2
	// edge case would make this test flaky). The nonce-randomness
	// property is observable directly from the ciphertext bitstring:
	// same input + same password + different runs MUST produce
	// distinguishable outputs. Round-trip integrity is locked
	// independently by TestEncryptDecrypt_RoundTrip via the retry helper.
	c1 := EncryptBitString(bits, password)
	c2 := EncryptBitString(bits, password)
	c3 := EncryptBitString(bits, password)

	if c1 == "" || c2 == "" || c3 == "" {
		t.Fatalf("EncryptBitString returned empty unexpectedly")
	}
	if c1 == c2 || c1 == c3 || c2 == c3 {
		t.Fatalf("EncryptBitString produced identical ciphertexts for same input — nonce is NOT random!\n  c1 == c2: %v\n  c1 == c3: %v\n  c2 == c3: %v", c1 == c2, c1 == c3, c2 == c3)
	}
}

// TestZeroBytes locks the contract for the KG-3 (v2.1.0) memory hygiene
// helper. Every byte of the input slice MUST become 0; nil and empty
// inputs MUST not panic.
func TestZeroBytes(t *testing.T) {
	t.Run("non-empty", func(t *testing.T) {
		b := []byte{0x01, 0x02, 0x03, 0xff, 0xaa, 0x55}
		ZeroBytes(b)
		for i, v := range b {
			if v != 0 {
				t.Errorf("ZeroBytes left non-zero at index %d: %#x", i, v)
			}
		}
	})

	t.Run("empty", func(t *testing.T) {
		// Should not panic.
		ZeroBytes([]byte{})
	})

	t.Run("nil", func(t *testing.T) {
		// Should not panic — Go's range loop on nil slice is a no-op.
		ZeroBytes(nil)
	})

	t.Run("aliasing", func(t *testing.T) {
		// ZeroBytes operates in-place; the original slice header sees
		// the zeros immediately. A regression that copied internally
		// would break the security guarantee.
		key := MakeKeyFromPassword("test-password-1234567")
		ZeroBytes(key)
		for i, v := range key {
			if v != 0 {
				t.Errorf("MakeKeyFromPassword output not zeroed at index %d: %#x", i, v)
			}
		}
	})
}

// min returns the smaller of two ints. Local helper — Go 1.19 doesn't
// have the builtin min.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
