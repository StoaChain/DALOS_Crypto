package Elliptic

import (
    "DALOS_Crypto/Blake3"
    "bytes"
    "encoding/binary"
    "fmt"
    "math/big"
    "strconv"
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
    SValue := ConvertBase49toBase10(Parts[1])
    
    // Step 4: Assign Coords and SValue to Schnorr Signature Structure
    signature.R = Coords
    signature.S = SValue
    return signature, nil
}

//BinaryStringToBytes converts a binary string to its []byte representation.
//With this syntax, each group of 8 binary digits is converted to a single byte.
//If the string is not multiple of 8 in length, it is padded with zeros in the begining.
func BinaryStringToBytes(binaryStr string) ([]byte, error) {
    var bytes []byte
    
    // Calculate how many bits need to be padded
    padding := len(binaryStr) % 8
    if padding != 0 {
        padding = 8 - padding
        // Add leading zeros to pad the binary string
        binaryStr = strings.Repeat("0", padding) + binaryStr
    }
    
    // Iterate through the string 8 characters at a time (1 byte)
    for i := 0; i < len(binaryStr); i += 8 {
        byteStr := binaryStr[i : i+8]
        
        // Convert the 8-bit string into an integer value (byte)
        parsedByte, err := strconv.ParseUint(byteStr, 2, 8)
        if err != nil {
            return nil, err
        }
        
        // Append the result to the bytes slice
        bytes = append(bytes, byte(parsedByte))
    }
    
    return bytes, nil
}

func ConvertBase49toBase10(NumberBase49 string) *big.Int {
    var result = new(big.Int)
    result.SetString(NumberBase49, 49)
    return result
}

func Hash2BigInt(Hash []byte) *big.Int {
    //Converts directly a slice of bytes to a big.Int
    result := new(big.Int)
    result.SetBytes(Hash)
    return result
}

// ConvertPublicKeyToAffineCoords converts a public key in the described format into CoordAffine.
func ConvertPublicKeyToAffineCoords(publicKey string) (CoordAffine, error) {
    var coords CoordAffine
    
    // Step 1: Split the prefix and the body of the key
    parts := strings.SplitN(publicKey, ".", 2)
    if len(parts) != 2 {
        return coords, fmt.Errorf("invalid public key format")
    }
    
    // Step 2: Convert the entire key body after the dot from base 49 to a big.Int
    keyBody := parts[1]
    totalValue := ConvertBase49toBase10(keyBody)
    
    // Step 3: Extract the length prefix from the first part (base 49)
    xLengthBase49 := parts[0]
    xLengthInt := ConvertBase49toBase10(xLengthBase49)
    
    // Convert the length to an int
    xLength := int(xLengthInt.Int64())
    
    // Step 4: Split the total value into X and Y coordinates
    // Convert the total value to string to manipulate its digits
    totalValueStr := totalValue.String()
    if len(totalValueStr) < xLength {
        return coords, fmt.Errorf("invalid key body length")
    }
    
    xString := totalValueStr[:xLength]
    yString := totalValueStr[xLength:]
    
    // Step 5: Convert X and Y from base 10 string to big.Int
    coords.AX = new(big.Int)
    coords.AY = new(big.Int)
    coords.AX.SetString(xString, 10)
    coords.AY.SetString(yString, 10)
    
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

    outputSize := int(e.S) / 8
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
    expansionSize := 2 * int(e.S) / 8
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
func (e *Ellipse) SchnorrSign(KeyPair DalosKeyPair, Message string) string {
    var Signature SchnorrSignature

    // Parse private key
    k := ConvertBase49toBase10(KeyPair.PRIV)

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

    // Fiat–Shamir challenge e = H(domain || r || P || message) mod Q
    challenge := e.SchnorrHash(r, KeyPair.PUBL, Message)
    if challenge == nil {
        return ""
    }

    // s = (z + e * k) mod Q  — canonically reduced.
    s := new(big.Int).Mul(challenge, k)
    s.Add(s, z)
    s.Mod(s, &e.Q)

    Signature.R = RAffine
    Signature.S = s
    return ConvertSchnorrSignatureToString(Signature)
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
