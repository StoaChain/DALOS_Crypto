package Elliptic

import (
	aux "DALOS_Crypto/Auxilliary"
	"DALOS_Crypto/Blake3"
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

// ============================================================================
// Schnorr v2.0.0 hardened constants  (Phase 0d, Cat-B fixes)
// ============================================================================
//
// SC-1: length-prefixed Fiat–Shamir transcript (fixes leading-zero
//       ambiguity of big.Int.Text(2) concatenation)
// SC-2: RFC-6979-style deterministic nonce derivation adapted for
//       Blake3 (removes dependency on crypto/rand at sign time)
// SC-3: domain-separation tags on both the challenge hash and the
//       nonce derivation (eliminates hash-reuse across protocols)
//
// Output format: NOT backward-compatible with pre-v2.0.0 signatures.
//                Pre-v2.0.0 signatures fail to verify under v2.0.0.
//                v2.0.0 signatures fail to verify under pre-v2.0.0.
//                This is intentional and safe: no DALOS Schnorr
//                signatures are used on-chain today.
//
// Security upgrade: signatures become deterministic (sign(k, m) twice
//                   yields identical bytes), closing the Sony-PS3
//                   random-nonce-reuse attack family. s is now
//                   canonically reduced to [0, Q-1].
const (
	schnorrHashDomainTag  = "DALOS-gen1/SchnorrHash/v1"
	schnorrNonceDomainTag = "DALOS-gen1/SchnorrNonce/v1"
)

// F-PERF-001 (audit cycle 2026-05-04, v4.0.1): the cofactor check
// (small-subgroup rejection, F-SEC-001 / REQ-16) is now performed via
// two HWCD doublings (`noErrDoubling(noErrDoubling(X))` ≡ [4]·X)
// instead of the previous `ScalarMultiplier(big.NewInt(4), X)` call.
//
// Old path built a 48-element PrecomputeMatrix (24 doublings + 24
// additions of internal work) and walked the base-49 digits of the
// scalar — way over-engineered for the trivial scalar 4. Two HWCD
// doublings produce the same projective point with ~16x less work;
// equivalence pinned by TestCofactor4_DoublingEquivalence and
// TestCofactor4_InfinityPreserved in Schnorr_strict_parser_test.go.
//
// Math: legitimate R = [k]·G and P = [k']·G satisfy [4]·R ≠ O and
// [4]·P ≠ O because gcd(4, Q) = 1 and the scalars lie in [1, Q-1].
// Order-4 small-subgroup attack points (the 4-torsion subgroup of
// E(F_p)) collapse to infinity under [4]·_ and are caught here.

// F-MED-017 (audit cycle 2026-05-04, v4.0.2): the cofactor check is
// now generalised via a hybrid dispatch helper. The h=4 fast path
// (two HWCD doublings) is preserved byte-identically for all current
// curves (DALOS, LETO, ARTEMIS, APOLLO — all h=4). Future curves with
// other cofactors are supported transparently:
//
//   h = 1                  → trivial passthrough (no small-subgroup attack vector)
//   h = 2                  → 1 doubling
//   h = 4                  → 2 doublings (FAST PATH, current behavior)
//   h = 8                  → 3 doublings (Ed25519 / Curve25519 family)
//   h = 2^k for any k ≥ 1  → k chained doublings
//   h = non-power-of-2     → fallback to ScalarMultiplier(h, X)
//
// CRITICAL: the dispatch helper is necessary BUT NOT SUFFICIENT for
// adding a non-h=4 curve. See docs/COFACTOR_GENERALIZATION.md for the
// full procedure (gcd(h, Q) verification, h-torsion adversarial vector
// construction, corpus byte-identity re-pinning, TS-port mirror,
// security threat model documentation).
//
// cofactorCheckRejects returns true iff [h]·X is the identity point —
// i.e., X is in the h-torsion subgroup and must be rejected as a
// small-subgroup attack point. Returns false for legitimate points.
//
// log2 helper for power-of-2 cofactors. Returns (k, true) if h = 2^k
// for some k ≥ 0; (0, false) otherwise. Used by the dispatch to
// determine the doubling-chain length. Examples:
//   isPowerOfTwo(1) = (0, true)
//   isPowerOfTwo(2) = (1, true)
//   isPowerOfTwo(4) = (2, true)
//   isPowerOfTwo(8) = (3, true)
//   isPowerOfTwo(6) = (0, false)
func isPowerOfTwo(n int64) (int, bool) {
	if n < 1 {
		return 0, false
	}
	if n&(n-1) != 0 {
		return 0, false
	}
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k, true
}

// cofactorCheckRejects performs the small-subgroup membership check.
// Returns true if X is in the h-torsion subgroup (must be rejected),
// false if X is a legitimate point (passes the check).
//
// Dispatch on h (= e.R.Int64()):
//   h = 1               → trivial: [1]·X = X. Reject only if X is already
//                         infinity. Upstream IsInfinityPoint already
//                         handles this; the cofactor check is degenerate
//                         for h=1 curves (which have no small-subgroup
//                         attack vector by construction).
//   h = 2^k for k ≥ 1   → k chained doublings. Includes the h=4 FAST PATH
//                         which preserves the v4.0.1 byte-identity for
//                         all current production curves.
//   h = non-power-of-2  → fallback to general ScalarMultiplier(h, X).
//                         ~16x slower than the doubling chain but
//                         mathematically equivalent. See
//                         docs/COFACTOR_GENERALIZATION.md for the
//                         performance trade-off discussion.
func (e *Ellipse) cofactorCheckRejects(X CoordExtended) bool {
	h := e.R.Int64()
	k, isPow2 := isPowerOfTwo(h)

	if isPow2 {
		// k chained doublings produces [2^k]·X = [h]·X.
		Y := X
		for i := 0; i < k; i++ {
			Y = e.noErrDoubling(Y)
		}
		return e.IsInfinityPoint(Y)
	}

	// Non-power-of-2 cofactor — use general scalar multiplication.
	// This path is documented but never exercised by current curves
	// (DALOS, LETO, ARTEMIS, APOLLO all have h=4). Adding a non-power-
	// of-2 cofactor curve requires the procedure in
	// docs/COFACTOR_GENERALIZATION.md.
	hScalar := new(big.Int).Set(&e.R)
	Y := e.ScalarMultiplier(hScalar, X)
	return e.IsInfinityPoint(Y)
}

// writeLenPrefixed appends a 4-byte big-endian length followed by data.
// Fixed width length prefix eliminates the leading-zero ambiguity that
// plain concatenation of variable-width binary strings has.
func writeLenPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}

// bigIntBytesCanon returns the canonical big-endian byte encoding of x.
// For non-negative x this is x.Bytes(). Nil and zero produce a single
// 0x00 byte so the length prefix remains well-defined.
func bigIntBytesCanon(x *big.Int) []byte {
	if x == nil || x.Sign() == 0 {
		return []byte{0x00}
	}
	return x.Bytes()
}

type SchnorrSignature struct {
	R CoordAffine
	S *big.Int
}

func ConvertSchnorrSignatureToString(Input SchnorrSignature) string {
	ErInPublicKeyFormat := AffineToPublicKey(Input.R)
	EsInBase49 := Input.S.Text(49)
	Output := ErInPublicKeyFormat + "|" + EsInBase49
	return Output
}

func ConvertSchnorrSignatureAsStringToStructure(SchnorrSignatureString string) (SchnorrSignature, error) {
	var signature SchnorrSignature

	// Step 1: Split the string into two parts - R part (Er - in Public Key Format) and the S part (Es in base 49)
	Parts := strings.Split(SchnorrSignatureString, "|")
	if len(Parts) != 2 {
		return signature, fmt.Errorf("invalid Schnorr signature format")
	}

	// Step 2: Convert the public key part (Er) back to CoordAffine (R)
	publicKeyPart := Parts[0]
	Coords, err := ConvertPublicKeyToAffineCoords(publicKeyPart)
	if err != nil {
		return signature, fmt.Errorf("error converting the stored string (in public key format) to affine coordinates: %v", err)
	}

	// Step 3: Convert Base 49 string to base 10 big.Int
	// F-ERR-002 (v4.0.1): ConvertBase49toBase10 now returns an error on
	// malformed input instead of silently producing an undefined big.Int.
	SValue, err := ConvertBase49toBase10(Parts[1])
	if err != nil {
		return signature, fmt.Errorf("error parsing s component (base-49): %w", err)
	}

	// Step 4: Assign Coords and SValue to Schnorr Signature Structure
	signature.R = Coords
	signature.S = SValue
	return signature, nil
}

// ConvertBase49toBase10 parses a base-49 string into a non-negative big.Int.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-ERR-002): the pre-v4.0.1
// helper discarded the (*big.Int).SetString `ok` return — per Go docs,
// the result value is undefined on parse failure but the pointer was
// still returned, producing garbage that flowed unchecked into SchnorrSign,
// AESDecrypt, and the Schnorr signature parser. This was a Go ↔ TS parity
// gap: the TS port's `parseBigIntInBase` (`ts/src/gen1/hashing.ts`) was
// hardened in REQ-21 to throw on invalid base-49 chars; the Go side
// never received the matching fix until now.
//
// Post-v4.0.1 contract:
//   - Empty input → error.
//   - Any byte outside the base-49 alphabet (`IsValidBase49Char` false)
//     → error, naming the offending byte. Matches TS `parseBigIntInBase`
//     all-or-nothing semantics.
//   - SetString failure (defense-in-depth; should never trigger after the
//     alphabet validator passes) → error.
//   - Otherwise: returns the parsed big.Int and nil error.
func ConvertBase49toBase10(NumberBase49 string) (*big.Int, error) {
	if len(NumberBase49) == 0 {
		return nil, fmt.Errorf("ConvertBase49toBase10: empty input")
	}
	for i := 0; i < len(NumberBase49); i++ {
		if !IsValidBase49Char(NumberBase49[i]) {
			return nil, fmt.Errorf("ConvertBase49toBase10: invalid base-49 character %q at index %d", NumberBase49[i], i)
		}
	}
	result := new(big.Int)
	if _, ok := result.SetString(NumberBase49, 49); !ok {
		return nil, fmt.Errorf("ConvertBase49toBase10: big.Int.SetString rejected %q (alphabet check passed; this should not happen)", NumberBase49)
	}
	return result, nil
}

// ConvertPublicKeyToAffineCoords converts a public key in the described format into CoordAffine.
//
// HARDENING (Phase 6, T6.5, F-SEC-002 / F-ERR-006):
//   - xLength prefix < 1 is rejected explicitly. Pre-fix, an empty or zero
//     prefix produced a silent zero-valued X coordinate that flowed
//     unchecked into Schnorr verification.
//   - Both (*big.Int).SetString calls now check the ok return. Pre-fix,
//     non-decimal content in either coordinate silently left the big.Int
//     in whatever state SetString happened to produce on failure.
//   - All error paths return CoordAffine{} (nil AX, nil AY) so downstream
//     callers cannot read a partially-constructed coords value (STK-003).
func ConvertPublicKeyToAffineCoords(publicKey string) (CoordAffine, error) {
	// Step 1: Split the prefix and the body of the key.
	//
	// REQ-22 (F-BUG-005): use strings.Split (not SplitN(_,_,2)) so that
	// inputs containing 2+ dots are rejected at the same boundary as the
	// TypeScript port. SplitN(_,_,2) silently collapsed extra dots into
	// parts[1], which then either threaded through the rest of the parser
	// or tripped a downstream guard with a misleading message.
	parts := strings.Split(publicKey, ".")
	if len(parts) != 2 {
		return CoordAffine{}, fmt.Errorf("invalid public key format: expected exactly 1 \".\", got %d", len(parts)-1)
	}

	// Step 2: Convert the entire key body after the dot from base 49 to a big.Int
	// F-ERR-002 (v4.0.1): propagate the new error return from
	// ConvertBase49toBase10 so malformed bodies are rejected explicitly
	// instead of producing a downstream-propagated garbage big.Int.
	keyBody := parts[1]
	totalValue, err := ConvertBase49toBase10(keyBody)
	if err != nil {
		return CoordAffine{}, fmt.Errorf("invalid public key body: %w", err)
	}

	// Step 3: Extract the length prefix from the first part (base 49)
	xLengthBase49 := parts[0]
	xLengthInt, err := ConvertBase49toBase10(xLengthBase49)
	if err != nil {
		return CoordAffine{}, fmt.Errorf("invalid public key xLength prefix: %w", err)
	}

	// Convert the length to an int
	xLength := int(xLengthInt.Int64())

	// F-SEC-002 / F-ERR-006: reject xLength < 1 (catches empty / zero / negative
	// prefix that would produce a silent zero-valued X coordinate downstream).
	if xLength < 1 {
		return CoordAffine{}, fmt.Errorf("invalid xLength prefix: %d", xLength)
	}

	// Step 4: Split the total value into X and Y coordinates
	// Convert the total value to string to manipulate its digits
	totalValueStr := totalValue.String()
	if len(totalValueStr) < xLength {
		return CoordAffine{}, fmt.Errorf("invalid key body length")
	}

	xString := totalValueStr[:xLength]
	yString := totalValueStr[xLength:]

	// Step 5: Convert X and Y from base 10 string to big.Int
	var coords CoordAffine
	coords.AX = new(big.Int)
	coords.AY = new(big.Int)
	if _, ok := coords.AX.SetString(xString, 10); !ok {
		return CoordAffine{}, fmt.Errorf("failed to parse X coordinate: %q", xString)
	}
	if _, ok := coords.AY.SetString(yString, 10); !ok {
		return CoordAffine{}, fmt.Errorf("failed to parse Y coordinate: %q", yString)
	}

	// Return the filled CoordAffine struct and nil error
	return coords, nil
}

// SchnorrHash computes the Fiat–Shamir challenge e = H(domain || R_x || P.x || P.y || m).
//
// v2.0.0 transcript format (SC-1, SC-3):
//
//   domain = "DALOS-gen1/SchnorrHash/v1"
//   transcript =  len32(domain) || domain
//              || len32(R_x)    || R_x
//              || len32(P.x)    || P.x
//              || len32(P.y)    || P.y
//              || len32(m)      || m
//   digest = Blake3_SumCustom(transcript, e.S / 8)
//   e = bigint(digest) mod Q           // canonicalised to (0, Q)
//
// Each component has a 4-byte big-endian length prefix, eliminating the
// leading-zero ambiguity that arose in the pre-v2.0.0 code from
// concatenating variable-width big.Int.Text(2) strings.
//
// Returns nil only on catastrophic internal failure (pubkey parse);
// callers treat nil as a verification rejection.
func (e *Ellipse) SchnorrHash(R *big.Int, PublicKey string, Message string) *big.Int {
	PublicKeyAffine, err := ConvertPublicKeyToAffineCoords(PublicKey)
	if err != nil {
		return nil
	}
	if PublicKeyAffine.AX == nil || PublicKeyAffine.AY == nil {
		return nil
	}

	var buf bytes.Buffer
	writeLenPrefixed(&buf, []byte(schnorrHashDomainTag))
	writeLenPrefixed(&buf, bigIntBytesCanon(R))
	writeLenPrefixed(&buf, bigIntBytesCanon(PublicKeyAffine.AX))
	writeLenPrefixed(&buf, bigIntBytesCanon(PublicKeyAffine.AY))
	writeLenPrefixed(&buf, []byte(Message))

	outputSize := aux.CeilDiv8(int(e.S))
	digest := Blake3.SumCustom(buf.Bytes(), outputSize)

	hashInt := new(big.Int).SetBytes(digest)
	hashInt.Mod(hashInt, &e.Q)
	return hashInt
}

// deterministicNonce derives a scalar z ∈ [1, Q-1] from (k, messageHash)
// via a tagged Blake3 expansion. SC-2 replacement for the crypto/rand
// nonce: same (k, m) always yields the same z, eliminating the Sony-PS3
// random-nonce-reuse attack family.
//
// Construction:
//
//   seed = tag || 0x00 || canonical(k) || canonical(msgHash)
//   expansion = Blake3_SumCustom(seed, 2 * e.S / 8)   // double-width
//   candidate = bigint(expansion) mod Q
//   if candidate == 0: return 1 (negligibly rare; 1 is a valid nonce)
//
// Doubled-width expansion minimises the modular bias — with 2·1600 bits
// of hash reduced mod the 1604-bit Q, the bias is ≤ 2^-(1596), well
// below any practical cryptanalytic threshold.
func (e *Ellipse) deterministicNonce(k *big.Int, messageHash []byte) *big.Int {
	var seed bytes.Buffer
	seed.WriteString(schnorrNonceDomainTag)
	seed.WriteByte(0x00)
	seed.Write(bigIntBytesCanon(k))
	seed.Write(messageHash)

	// 2x safe-scalar bytes of expansion, for bias-free modular reduction.
	expansionSize := aux.CeilDiv8(2 * int(e.S))
	expansion := Blake3.SumCustom(seed.Bytes(), expansionSize)

	z := new(big.Int).SetBytes(expansion)
	z.Mod(z, &e.Q)
	if z.Sign() == 0 {
		z.SetInt64(1) // negligibly rare; 1 is a valid in-range nonce
	}
	return z
}

// SchnorrSign Schnorr Signature Creation:
//
//          Private key :             k            (integer)
//          Public key :              P = k*G      (curve point)
//          Message hash:             m            (integer)
//
//          Generate a random number: z            (integer)
//          Calculate:                R = z*G      (curve point)
//
//          Calculate: s = z + Hash(r||P||m)*k     (integer)
//                     s = (random integer) +
//                         (integer resulted from hashed message) * (integer representing the private key)
//
//          where: r = X-coordinate of curve point R
//          and || denotes binary concatenation
//          Signature = (R, s)     (curve point, integer)
//==================================================================
// SchnorrSign produces a Schnorr signature (R, s) over Message using
// KeyPair's private scalar k.
//
// v2.0.0 changes from pre-v2.0.0:
//   SC-2: nonce z is now deterministic — derived from (k, H(message))
//         via the tagged Blake3 KDF in deterministicNonce(). Same
//         (k, message) always yields the same (R, s). Eliminates the
//         random-nonce-reuse attack family.
//   SC-3: the transcript tag in SchnorrHash isolates this signature
//         from any other protocol using Blake3.
//   SC-4 (full): s = z + e·k is now reduced mod Q → canonical (0, Q).
//         Older s values could exceed Q; v2.0.0 rejects those. Both
//         signer and verifier agree on the canonical range.
//
// Output format: "R-in-public-key-form | s-in-base49" — encoding
//                itself is unchanged; only the byte values of R and s
//                differ from pre-v2.0.0.
//
// HARDENING (v4.0.1, audit cycle 2026-05-04, F-API-005): the pre-v4.0.1
// signature was `string`; three internal failure modes (parse-base49
// failure, k out of [1, Q-1], nil Fiat-Shamir challenge) all silently
// returned "" — a magic-empty-string sentinel that consumers had no
// principled way to distinguish from a real signature. The CLI driver
// at Dalos.go would print "Signature: <blank>" with no failure detection
// and downstream pipe consumers wrote literal empty signatures to disk.
//
// The TS port's schnorrSign (ts/src/gen1/schnorr.ts) throws SchnorrSignError
// on the same conditions. Post-v4.0.1 this function returns
// (string, error) so cross-language consumers get symmetric failure
// contracts and the empty-string sentinel class is removed permanently.
func (e *Ellipse) SchnorrSign(KeyPair DalosKeyPair, Message string) (string, error) {
	var Signature SchnorrSignature

	// Parse private key. Malformed PRIV (corrupt wallet, serialization
	// bug, etc.) is rejected loudly via F-ERR-002's alphabet-validated
	// helper.
	k, err := ConvertBase49toBase10(KeyPair.PRIV)
	if err != nil {
		return "", fmt.Errorf("SchnorrSign: malformed private key: %w", err)
	}

	// F-ERR-007 (v4.0.1): range-check the parsed private key. The math
	// in s = (z + e·k) mod Q produces a structurally-valid signature for
	// any k, but k = 0 yields R = 0·G = O (infinity) and s = z + 0 = z —
	// the signer's nonce is now public, embedded in s. k outside [1, Q-1]
	// is meaningless cryptography. Mirrors the TS port's REQ-21/REQ-22
	// range validation in parseBigIntInBase.
	if k.Sign() <= 0 || k.Cmp(&e.Q) >= 0 {
		return "", fmt.Errorf("SchnorrSign: private key scalar out of range [1, Q-1]")
	}

	// Hash the message (separately from the Fiat–Shamir challenge) for
	// nonce derivation. Tagged, Blake3, fixed-width output.
	msgHashInput := append([]byte(schnorrNonceDomainTag+"/msg"), []byte(Message)...)
	msgDigest := Blake3.SumCustom(msgHashInput, 64)

	// Derive deterministic nonce z in [1, Q-1]
	z := e.deterministicNonce(k, msgDigest)

	// R = z * G
	RExtended := e.ScalarMultiplierWithGenerator(z)
	RAffine := e.Extended2Affine(RExtended)
	r := RAffine.AX

	// Fiat–Shamir challenge e = H(domain || r || P || message) mod Q.
	// SchnorrHash returns nil when the public key cannot be parsed
	// (an internal-consistency violation: a well-formed KeyPair has
	// a parseable PUBL). Mirrors TS schnorr.ts:349-353 which throws
	// SchnorrSignError on the same condition.
	challenge := e.SchnorrHash(r, KeyPair.PUBL, Message)
	if challenge == nil {
		return "", fmt.Errorf("SchnorrSign: Fiat-Shamir challenge produced nil — likely caused by an unparseable public key in KeyPair.PUBL")
	}

	// s = (z + e * k) mod Q  — canonically reduced.
	s := new(big.Int).Mul(challenge, k)
	s.Add(s, z)
	s.Mod(s, &e.Q)

	Signature.R = RAffine
	Signature.S = s
	return ConvertSchnorrSignatureToString(Signature), nil
}

//SchnorrVerify  Schnorr Signature Verification
//
//          obtain the signature: (R,s)
//          Obtain public key : P
//          Obtain message: m
//
//          Verify: s*G =   R + Hash(r||P||m) *   P is true because
//                  s*G = z*G + Hash(r||P||m) * k*G
//
// HARDENING (v1.3.0):
//   SC-4: range check on s ∈ (0, Q) rejects malformed signatures
//   SC-5: on-curve validation of R and P rejects invalid points,
//         closing small-subgroup and off-curve attack surfaces
//   SC-6: all errors produce explicit false returns; no nil dereferences
//         on malformed input
//==================================================================
func (e *Ellipse) SchnorrVerify(Signature, Message, PublicKey string) bool {
	// Step 0 — parse the signature. SC-6: treat any parse error as
	// a hard rejection (previously the code would proceed with a
	// zero-valued R and nil s, risking nil dereferences downstream).
	Schnorr, err := ConvertSchnorrSignatureAsStringToStructure(Signature)
	if err != nil {
		return false
	}

	// SC-6: defence against nil components sneaking through a
	// well-formed-looking signature string.
	if Schnorr.R.AX == nil || Schnorr.R.AY == nil || Schnorr.S == nil {
		return false
	}

	// SC-4 (full, v2.0.0): reject s outside the canonical range (0, Q).
	// v2.0.0 sign reduces s mod Q; any signature with s ≥ Q or s ≤ 0
	// is malformed and must be rejected. (Pre-v2.0.0 signatures often
	// have s ≥ Q and will correctly fail verification here —
	// intentional format break.)
	if Schnorr.S.Cmp(Zero) <= 0 || Schnorr.S.Cmp(&e.Q) >= 0 {
		return false
	}

	// Step 1 — Get R point (already parsed) and its extended form.
	R := Schnorr.R
	RExtend := e.Affine2Extended(R)

	// SC-5: on-curve validation of R. Without this, a prepared
	// off-curve point could interact with the addition formulas in
	// undefined ways, creating a signature-forgery avenue.
	onCurveR, _ := e.IsOnCurve(RExtend)
	if !onCurveR {
		return false
	}

	// F-SEC-001: cofactor subgroup-membership check on R.
	// Legitimate R = [k]·G has [h]·R = [hk]·G ≠ O since gcd(h, Q)=1
	// and k ∈ [1, Q-1]. h-torsion small-subgroup attack points yield [h]·R = O.
	// F-PERF-001 (v4.0.1): two doublings on the h=4 fast path.
	// F-MED-017 (v4.0.2): generalised via cofactorCheckRejects dispatch.
	if e.cofactorCheckRejects(RExtend) {
		return false
	}

	// Step 2 — Parse the public key. SC-6: error from parsing is
	// also a hard rejection.
	PAffine, err := ConvertPublicKeyToAffineCoords(PublicKey)
	if err != nil {
		return false
	}
	if PAffine.AX == nil || PAffine.AY == nil {
		return false
	}
	PExtend := e.Affine2Extended(PAffine)

	// SC-5 (symmetric): on-curve validation of the public key P.
	// Defence-in-depth; a correctly-constructed public key is always
	// on-curve, but an attacker-controlled P should not cause
	// undefined behaviour.
	onCurveP, _ := e.IsOnCurve(PExtend)
	if !onCurveP {
		return false
	}

	// F-SEC-001: cofactor subgroup-membership check on P (public key).
	// Same rationale as R — rejects h-torsion small-subgroup attack public keys.
	// F-PERF-001 (v4.0.1): two doublings on the h=4 fast path.
	// F-MED-017 (v4.0.2): generalised via cofactorCheckRejects dispatch.
	if e.cofactorCheckRejects(PExtend) {
		return false
	}

	// Step 3 — Compute the Fiat–Shamir challenge m = H(r || P || m).
	r := R.AX
	m := e.SchnorrHash(r, PublicKey, Message)
	if m == nil {
		return false
	}

	// Step 4 — Compute R + m * P (the "right" term).
	Multiplication := e.ScalarMultiplier(m, PExtend)
	RightTerm, err := e.Addition(RExtend, Multiplication)
	if err != nil {
		return false
	}

	// Step 5 — Compute s * G (the "left" term).
	LeftTerm := e.ScalarMultiplierWithGenerator(Schnorr.S)

	// Valid iff left == right.
	return e.ArePointsEqual(LeftTerm, RightTerm)
}
