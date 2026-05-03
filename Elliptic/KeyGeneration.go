package Elliptic

import (
    "DALOS_Crypto/Bitmap"
    "DALOS_Crypto/Blake3"
    aux "DALOS_Crypto/Auxilliary"
    "crypto/rand"
    "errors"
    "fmt"
    "math/big"
    "strings"
)

type DalosKeyPair struct {
    PRIV string
    PUBL string
}

type DalosPrivateKey struct {
    BitString string
    Int10     string
    Int49     string
}

// Phase 10 (REQ-31, v4.0.0): PrintKeys + PrintPrivateKey moved to
// `print.go` at repo root (package main). This file retains pure-crypto
// only — see ../keystore/ for wallet I/O and ../process.go for CLI
// orchestration.

func DalosAddressMaker(PublicKey string, SmartOrStandard bool) string {
    //Creates either a Standard Dalos Account Address or a Smart Dalor Account Address
    Matrix := CharacterMatrix()
    Standard := string(Matrix[0][10]) // Get the rune at [0][10]
    Smart := string(Matrix[11][9])    // Get the rune at [11][9]
    Address := PublicKeyToAddress(PublicKey)
    
    if SmartOrStandard {
        return Smart + "." + Address
    } else {
        return Standard + "." + Address
    }
}

func PublicKeyToAddress(PublicKey string) string {
    //From the PublicKey string, the Prefix is removed in order to obtain the PublicKeyInt
    //as in integer in Base49
    var PublicKeyIntDecimal = new(big.Int)
    SplitString := strings.Split(PublicKey, ".")
    PublicKeyIntStr := SplitString[1] //Public Key as a Number in Base 49 in the form of a string
    
    PublicKeyIntDecimal.SetString(PublicKeyIntStr, 49)
    Address := DalosAddressComputer(PublicKeyIntDecimal)
    return Address
}

func DalosAddressComputer(PublicKeyInt *big.Int) string {
    PublicKeyIntAsString := PublicKeyInt.String()
    Hash0 := []byte(PublicKeyIntAsString)
    
    //Seven Fold Hash
    Hash1 := Blake3.SumCustom(Hash0, 160)
    Hash2 := Blake3.SumCustom(Hash1, 160)
    Hash3 := Blake3.SumCustom(Hash2, 160)
    Hash4 := Blake3.SumCustom(Hash3, 160)
    Hash5 := Blake3.SumCustom(Hash4, 160)
    Hash6 := Blake3.SumCustom(Hash5, 160)
    Hash7 := Blake3.SumCustom(Hash6, 160)
    
    //Converting To Letters
    Account := ConvertToLetters(Hash7)
    return Account
}

func ConvertToLetters(hash []byte) string {
    var SliceStr []string
    Matrix := CharacterMatrix()
    
    for _, value := range hash {
        // Calculate row and column index for the Matrix
        row := value / 16 // Each row has 16 elements
        col := value % 16 // Column index within the row
        
        // Append the corresponding character from the Matrix to the SliceStr
        SliceStr = append(SliceStr, string(Matrix[row][col]))
    }
    
    // Join the SliceStr to form the resulting string
    return strings.Join(SliceStr, "")
}

func AffineToPublicKey(Input CoordAffine) string {
    XString := Input.AX.String()                             //X Coordinates as string
    XStringLength := int64(len(XString))                     //Length of the XString
    XStringLengthBig := new(big.Int).SetInt64(XStringLength) //Length of the XString as big.Int
    PublicKeyPrefix := XStringLengthBig.Text(49)             //Converted to Base 49
    //The Public-Key PublicKeyPrefix in Baase 49 is needed to reconstruct
    //The Public Key Affine Coordinates from the PublicKey String
    
    YString := Input.AY.String()
    XYString := XString + YString
    PublicKeyInteger, _ := new(big.Int).SetString(XYString, 10)
    PublicKey := PublicKeyInteger.Text(49)
    PrefixedPublicKey := PublicKeyPrefix + "." + PublicKey
    return PrefixedPublicKey
}

// VI Key Generation
//
// REQ-10 (T4.1): replaced the prior per-bit `rand.Int(rand.Reader, Two)` loop
// (e.S calls into crypto/rand for a one-bit BigInt each) with a single bulk
// `rand.Read` of ceil(e.S / 8) bytes followed by an MSB-first bit-render loop.
// For DALOS S=1600 this is one 200-byte syscall instead of 1600 BigInt ops.
// crypto/rand.Read is documented to never return a short read on success, and
// any error is unrecoverable (entropy source failure) so we panic — consistent
// with the existing key-gen invariants where partial randomness would silently
// corrupt the generated private key.
//
// Output API unchanged: returns a string of length exactly e.S consisting of
// '0' and '1' runes. Genesis byte-identity is preserved because the testvector
// generator uses a separate seeded math/rand path (testvectors/generator/main.go
// randomBitString), not this function.
func (e *Ellipse) GenerateRandomBitsOnCurve() string {
    var (
        bitLength     = e.S
        binaryBuilder strings.Builder
    )
    binaryBuilder.Grow(int(bitLength))

    byteLen := (int(bitLength) + 7) / 8
    buf := make([]byte, byteLen)
    if _, err := rand.Read(buf); err != nil {
        panic(fmt.Sprintf("GenerateRandomBitsOnCurve: rand.Read failed: %v", err))
    }

    for i := 0; i < int(bitLength); i++ {
        byteIdx := i / 8
        bitIdx := 7 - (i % 8)
        if (buf[byteIdx]>>bitIdx)&1 == 1 {
            binaryBuilder.WriteByte('1')
        } else {
            binaryBuilder.WriteByte('0')
        }
    }
    return binaryBuilder.String()
}

func (e *Ellipse) SeedWordsToBitString(SeedWords []string) string {
    JoinedSeeds := strings.Join(SeedWords, " ")
    JoinedSeedsToByteSlice := []byte(JoinedSeeds)
    //Compute the Blake3 SumCustom output size. The safe-scalar size is NOT
    //required to be a multiple of eight — `aux.CeilDiv8` enforces ceiling
    //semantics so byte-aligned curves (DALOS S=1600, APOLLO S=1024) and
    //non-byte-aligned curves (LETO S=545, ARTEMIS S=1023) all produce a valid byte-count.
    OutputSize := aux.CeilDiv8(int(e.S))
    //SevenFoldHash
    Hash1 := Blake3.SumCustom(JoinedSeedsToByteSlice, OutputSize)
    Hash2 := Blake3.SumCustom(Hash1, OutputSize)
    Hash3 := Blake3.SumCustom(Hash2, OutputSize)
    Hash4 := Blake3.SumCustom(Hash3, OutputSize)
    Hash5 := Blake3.SumCustom(Hash4, OutputSize)
    Hash6 := Blake3.SumCustom(Hash5, OutputSize)
    Hash7 := Blake3.SumCustom(Hash6, OutputSize)
    return e.ConvertHashToBitString(Hash7)
}

// ConvertHashToBitString renders Hash as a big-endian bitstring of e.S bits, mirroring
// the TypeScript canonical at ts/src/gen1/hashing.ts:108-129 (convertHashToBitString).
// XCURVE-4: replaces the prior hex->big.Int->Text(2) pipeline that elided leading zeros.
func (e *Ellipse) ConvertHashToBitString(Hash []byte) string {
    var full string
    for _, b := range Hash {
        full += fmt.Sprintf("%08b", b)
    }
    bitLength := int(e.S)
    if len(full) == bitLength {
        return full
    }
    if len(full) > bitLength {
        return full[:bitLength]
    }
    return strings.Repeat("0", bitLength-len(full)) + full
}

func (e *Ellipse) ValidateBitString(BitString string) (bool, bool, bool) {
    // Check if the length of the string matches k.S
    var (
        LengthBoolean, StructureBoolean, TotalBoolean bool
    )
    if uint32(len(BitString)) == e.S {
        LengthBoolean = true
    }
    // Check if the string contains only '0' and '1'
    StructureBoolean = true // Start by assuming it's true
    for _, char := range BitString {
        if char != '0' && char != '1' {
            StructureBoolean = false
            break
        }
    }
    // Overall truth depends on both length and structure
    TotalBoolean = LengthBoolean && StructureBoolean
    return TotalBoolean, LengthBoolean, StructureBoolean
}

// ValidatePrivateKey checks if the given private key as big.Int string meets the specified conditions.
// The input can be in either base 10 (when isBase10 is true) or base 49 (when isBase10 is false).
// It returns a boolean indicating validity and its BitString.
func (e *Ellipse) ValidatePrivateKey(privateKey string, isBase10 bool) (bool, string) {
    var binaryKey string
    PK := new(big.Int)
    
    // Convert the private key to binary string representation
    if isBase10 {
        PK.SetString(privateKey, 10)
        binaryKey = PK.Text(2) // Convert the Big.Int to binary string
    } else {
        PK.SetString(privateKey, 49)
        binaryKey = PK.Text(2) // Convert the Big.Int to binary string
    }
    
    // Check if the first character is '1'
    if len(binaryKey) == 0 || binaryKey[0] != '1' {
        fmt.Println("Invalid Private Key: Its Binary Representation does not have 1 as first Digit")
        return false, ""
    }
    
    // Get the binary representation of the cofactor
    cofactorBinary := e.R.Text(2)
    
    // Check if the last two digits match the last two digits of the cofactor's binary representation
    if len(binaryKey) < 2 || binaryKey[len(binaryKey)-2:] != cofactorBinary[len(cofactorBinary)-2:] {
        fmt.Println("Invalid Private Key: Its binary representation does not match the Ellipse Cofactor with its last ", len(cofactorBinary)-1, " digits, which must be zero")
        return false, ""
    }
    
    // Check the length of the middle part
    middleLength := len(binaryKey) - len(cofactorBinary) // Exclude first and last digits
    if uint32(middleLength) != e.S {
        fmt.Println("Invalid Private Key: Its Core Binary representation must be ", e.S, " digits long.")
        return false, ""
    }
    
    // Extract and return the BitString (the middle part)
    bitString := binaryKey[1 : len(binaryKey)-(len(cofactorBinary)-1)] // Trim the first and last parts
    return true, bitString
}

//Private Key can be represented as:
//  A BitString, 1600 digits long. This must be clamped, according to curve cofactor to generate the Int(base10) or INT(base49)
//  Clamping According to Dalos Curve, means adding a prefix of 1(before the BitString), and a Suffix of 00 (after the bitstring)
//  The resulted BitString 1603 digits long is converted to Big.Int(base10) or BigInt(base49)
//      Note: The Bits displayed when generating a Key Pair, are alredy clamped 1603 digits long.
//      To use them to regenerate Key pair, remove the first bit and the last 2 bits, to get the Original BitString
//
//  A BigInt(base10), created as depicted above from the BitString 1600 Digits Long. This is the Scalar.
//  A BigInt(base49), created as depicted above from the BitString 1600 Digits Long. This is the Scalar.

func (e *Ellipse) GenerateScalarFromBitString(BitString string) (*big.Int, error) {
    //Clamps a BitString according to Curve Cofactor, generating a Scalar from it.
    //Throws an error if the BitString is not a Valid String of Bits, equal in length the Curves Safe Scalar size
    // Validates the BitString
    if isValid, _, _ := e.ValidateBitString(BitString); !isValid {
        return nil, errors.New("the bitstring is invalid for the " + e.Name + " Curve")
    }
    // Get the binary representation of the cofactor
    BinaryCofactor := e.R.Text(2)
    if len(BinaryCofactor) > 0 {
        // Trim the first rune of the binary cofactor
        BinaryCofactor = aux.TrimFirstRune(BinaryCofactor)
    }
    // Construct the final binary string
    BinaryString := "1" + BitString + BinaryCofactor
    // Convert the final binary string to a big.Int
    Scalar := new(big.Int)
    Scalar.SetString(BinaryString, 2)
    return Scalar, nil
}

func (e *Ellipse) ScalarToKeys(Scalar *big.Int) (DalosKeyPair, error) {
    var Output DalosKeyPair
    
    // Attempt to convert the scalar to a private key
    PrivateKey, err := e.ScalarToPrivateKey(Scalar)
    if err != nil {
        return Output, err // Return an error if the private key is invalid
    }
    
    // Set the private key and compute the public key
    Output.PRIV = PrivateKey.Int49
    Output.PUBL = e.ScalarToPublicKey(Scalar)
    
    return Output, nil // Return the key pair and nil error
}

func (e *Ellipse) ScalarToPrivateKey(Scalar *big.Int) (DalosPrivateKey, error) {
    var Output DalosPrivateKey
    ScalarAsStringAkaPrivateKeyInDecimal := Scalar.Text(10)
    
    // Validate the private key
    isValid, BitString := e.ValidatePrivateKey(ScalarAsStringAkaPrivateKeyInDecimal, true)
    
    // Only proceed if the key is valid
    if isValid {
        Output.BitString = BitString   // Middle part of the representation
        Output.Int10 = Scalar.Text(10) // Base 10 representation
        Output.Int49 = Scalar.Text(49) // Base 49 representation
        return Output, nil             // Success case
    }
    
    // Return an error if validation fails
    return Output, fmt.Errorf("invalid private key: does not meet validation criteria")
}

func (e *Ellipse) ScalarToPublicKey(Scalar *big.Int) string {
    PublicKeyPointsExtended := e.ScalarMultiplierWithGenerator(Scalar)
    PublicKeyPointsAffine := e.Extended2Affine(PublicKeyPointsExtended)
    PrefixedPublicKey := AffineToPublicKey(PublicKeyPointsAffine)
    return PrefixedPublicKey
}

// GenerateFromBitmap is the 6th key-generation input path (added in v1.2.0).
//
// A 40x40 black/white Bitmap encodes exactly 1600 bits — the DALOS safe-scalar
// size. The bitmap is converted to a bitstring via row-major top-to-bottom,
// left-to-right scan (black=1, white=0), then the standard pipeline produces
// the scalar, private key and public key.
//
// This function is pure input reshaping — no new cryptographic operations are
// introduced. It is equivalent to:
//
//     bits := Bitmap.BitmapToBitString(b)
//     scalar, err := e.GenerateScalarFromBitString(bits)
//     keys, err := e.ScalarToKeys(scalar)
//
// Returns the computed key pair or an error if the intermediate bitstring
// fails validation (which cannot happen for a structurally valid Bitmap).
func (e *Ellipse) GenerateFromBitmap(b Bitmap.Bitmap) (DalosKeyPair, error) {
    var zero DalosKeyPair
    if err := Bitmap.ValidateBitmap(b); err != nil {
        return zero, fmt.Errorf("invalid bitmap: %w", err)
    }
    bits := Bitmap.BitmapToBitString(b)
    scalar, err := e.GenerateScalarFromBitString(bits)
    if err != nil {
        return zero, fmt.Errorf("bitmap produced invalid bitstring: %w", err)
    }
    return e.ScalarToKeys(scalar)
}

// Phase 10 (REQ-31, v4.0.0): The following symbols moved out of this
// package to enforce the pure-crypto invariant on Elliptic/ —
//   - PrintKeys, PrintPrivateKey            -> ../print.go (package main)
//   - ProcessIntegerFlag,
//     ProcessPrivateKeyConversion,
//     ProcessKeyGeneration,
//     SaveBitString                          -> ../process.go (package main)
//   - ExportPrivateKey, ImportPrivateKey,
//     AESDecrypt,
//     GenerateFilenameFromPublicKey          -> ../keystore/ (NEW package)
// All retain output-preserving behaviour; the receivers were rewritten
// from `(e *Ellipse)` methods to free functions taking `e *el.Ellipse`
// because Go forbids defining methods on types from external packages.
// See ../.bee/specs/2026-05-02-unified-audit-2026-04-29/phases/
// 10-elliptic-package-carve-out/MIGRATION.md for the full migration table.

// characterMatrixCache holds the 16x16 rune matrix used for Demiourgos address
// derivation. It is built exactly once at package init via makeCharacterMatrix
// because the matrix is immutable and rebuilding 256 rune literals on every
// CharacterMatrix() call is wasted work. Option (a) — eager package-level var,
// not sync.Once — was chosen because the matrix is small (~1 KB) and used
// unconditionally during every key-gen / address-derive pass.
var characterMatrixCache = makeCharacterMatrix()

// CharacterMatrix returns the cached 16x16 Unicode rune matrix used for
// Demiourgos address derivation. The matrix is constructed once at package
// init; this accessor returns the cached value.
func CharacterMatrix() [16][16]rune {
    return characterMatrixCache
}

func makeCharacterMatrix() [16][16]rune {
    //Digits Block 10 runes
    C000 := '0' //U+0030    [48] Digit Zero
    C001 := '1' //U+0031    [49] Digit One
    C002 := '2' //U+0032    [50] Digit Two
    C003 := '3' //U+0033    [51] Digit Three
    C004 := '4' //U+0034    [52] Digit Four
    C005 := '5' //U+0035    [53] Digit Five
    C006 := '6' //U+0036    [54] Digit Six
    C007 := '7' //U+0037    [55] Digit Seven
    C008 := '8' //U+0038    [56] Digit Eight
    C009 := '9' //U+0039    [57] Digit Nine
    
    //Currencies Block 10 runes
    C010 := 'Ѻ' //U+047A    [209 186] Cyrillic Capital Letter Round Omega (Ourobos Currency)
    C011 := '₿' //U+20BF    [226 130 191] Bitcoin Sign
    C012 := '$' //U+0024    [36] Dollar Sign
    C013 := '¢' //U+00A2    [194 162] Cent Sign
    C014 := '€' //U+20AC    [226 130 172] Euro Sign
    C015 := '£' //U+00A3    [194 163] Pound Sign
    C016 := '¥' //U+00A5    [194 165] Yen Sign
    C017 := '₱' //U+20B1    [226 130 177] Peso Sign
    C018 := '₳' //U+20B3    [226 130 179] Austral Sign (AURYN Currency)
    C019 := '∇' //U+2207    [226 136 135] Nabla (TALOS Currency)
    
    //Latin Capital Letters 26 runes
    C020 := 'A' //U+0041    [65] Latin Capital Letter A
    C021 := 'B' //U+0042    [66] Latin Capital Letter B
    C022 := 'C' //U+0043    [67] Latin Capital Letter C
    C023 := 'D' //U+0044    [68] Latin Capital Letter D
    C024 := 'E' //U+0045    [69] Latin Capital Letter E
    C025 := 'F' //U+0046    [70] Latin Capital Letter F
    C026 := 'G' //U+0047    [71] Latin Capital Letter G
    C027 := 'H' //U+0048    [72] Latin Capital Letter G
    C028 := 'I' //U+0049    [73] Latin Capital Letter I
    C029 := 'J' //U+004A    [74] Latin Capital Letter J
    C030 := 'K' //U+004B    [75] Latin Capital Letter K
    C031 := 'L' //U+004C    [76] Latin Capital Letter L
    C032 := 'M' //U+004D    [77] Latin Capital Letter M
    C033 := 'N' //U+004E    [78] Latin Capital Letter N
    C034 := 'O' //U+004F    [79] Latin Capital Letter O
    C035 := 'P' //U+0050    [80] Latin Capital Letter P
    C036 := 'Q' //U+0051    [81] Latin Capital Letter Q
    C037 := 'R' //U+0052    [82] Latin Capital Letter R
    C038 := 'S' //U+0053    [83] Latin Capital Letter S
    C039 := 'T' //U+0054    [84] Latin Capital Letter T
    C040 := 'U' //U+0055    [85] Latin Capital Letter U
    C041 := 'V' //U+0056    [86] Latin Capital Letter V
    C042 := 'W' //U+0057    [87] Latin Capital Letter W
    C043 := 'X' //U+0058    [88] Latin Capital Letter X
    C044 := 'Y' //U+0059    [89] Latin Capital Letter Y
    C045 := 'Z' //U+005A    [90] Latin Capital Letter Z
    
    //Latin Small Letters 26 runes
    C046 := 'a' //U+0061    [97] Latin Small Letter A
    C047 := 'b' //U+0062    [98] Latin Small Letter B
    C048 := 'c' //U+0063    [99] Latin Small Letter C
    C049 := 'd' //U+0064    [100] Latin Small Letter D
    C050 := 'e' //U+0065    [101] Latin Small Letter E
    C051 := 'f' //U+0066    [102] Latin Small Letter F
    C052 := 'g' //U+0067    [103] Latin Small Letter G
    C053 := 'h' //U+0068    [104] Latin Small Letter H
    C054 := 'i' //U+0069    [105] Latin Small Letter I
    C055 := 'j' //U+006A    [106] Latin Small Letter J
    C056 := 'k' //U+006B    [107] Latin Small Letter K
    C057 := 'l' //U+006C    [108] Latin Small Letter L
    C058 := 'm' //U+006D    [108] Latin Small Letter M
    C059 := 'n' //U+006E    [110] Latin Small Letter N
    C060 := 'o' //U+006F    [111] Latin Small Letter O
    C061 := 'p' //U+0070    [112] Latin Small Letter P
    C062 := 'q' //U+0071    [113] Latin Small Letter Q
    C063 := 'r' //U+0072    [114] Latin Small Letter R
    C064 := 's' //U+0073    [115] Latin Small Letter S
    C065 := 't' //U+0074    [116] Latin Small Letter T
    C066 := 'u' //U+0075    [117] Latin Small Letter U
    C067 := 'v' //U+0076    [118] Latin Small Letter V
    C068 := 'w' //U+0077    [119] Latin Small Letter W
    C069 := 'x' //U+0078    [120] Latin Small Letter X
    C070 := 'y' //U+0079    [121] Latin Small Letter Y
    C071 := 'z' //U+007A    [122] Latin Small Letter Z
    
    //Latin Extended Capital Letters 53 runes
    C072 := 'Æ' //U+00C6    [195 134] Latin Capital Letter Ae                   French, Danish, Norwegian, Latin, Icelanding (missing thorn)
    C073 := 'Œ' //U+0152    [197 146] Latin Capital Letter Oe                   French, Latin
    C074 := 'Á' //U+00C1    [195 129] Latin Capital Letter A with Acute         Spanish, Czech, Portuguese, Icelanding (missing thorn),
    C075 := 'Ă' //U+0102    [196 130] Latin Capital Letter A with Breve         Romanian
    C076 := 'Â' //U+00C2    [195 130] Latin Capital Letter A with Circumflex    French, Romanian, Portuguese, Czech,
    C077 := 'Ä' //U+00C4    [195 132] Latin Capital Letter A with Diaeresis     German, Swedish, Finnish, Estonian
    C078 := 'À' //U+00C0    [195 128] Latin Capital Letter A with Grave         French, Portuguese, Italian
    C079 := 'Ą' //U+0104    [196 132] Latin Capital Letter A with Ogonek        Polish
    C080 := 'Å' //U+00C5    [195 133] Latin Capital Letter A with Ring Above    Danish, Norwegian, Swedish, Finnish
    C081 := 'Ã' //U+00C3    [195 131] Latin Capital Letter A with Tilde         Portuguese
    C082 := 'Ć' //U+0106    [196 134] Latin Capital Letter C with Acute         Polish, Croatian, Serbian-Bosnian(latinized)
    C083 := 'Č' //U+010C    [196 140] Latin Capital Letter C with Caron         Czech, Croatian, Serbian-Bosnian(latinized), Slovenian
    C084 := 'Ç' //U+00C7    [195 135] Latin Capital Letter C with Cedilla       French, Kurmanji, Portuguese, Kurdish, Albanian, Turkish
    C085 := 'Ď' //U+010E    [196 142] Latin Capital Letter D with Caron         Czech, Serbian(latinized)
    C086 := 'Đ' //U+0110    [196 144] Latin Capital Letter D with Stroke        Croatian, Serbian-Bosnian(latinized)
    C087 := 'É' //U+00C9    [195 137] Latin Capital Letter E with Acute         Kurmanji, Icelanding (missing thorn), Spanish, Czech, Portuguese, Italian
    C088 := 'Ě' //U+011A    [196 154] Latin Capital Letter E with Caron         Czech
    C089 := 'Ê' //U+00CA    [195 138] Latin Capital Letter E with Circumflex    French, Kurmanji, Kurdish
    C090 := 'Ë' //U+00CB    [195 139] Latin Capital Letter E with Diaeresis     French, Albanian
    C091 := 'È' //U+00C8    [195 136] Latin Capital Letter E with Grave         French, Portuguese, Italian
    C092 := 'Ę' //U+0118    [196 152] Latin Capital Letter E with Ogonek        Polish
    C093 := 'Ğ' //U+011E    [196 158] Latin Capital Letter G with Breve         Turkish
    C094 := 'Í' //U+00CD    [195 141] Latin Capital Letter I with Acute         Icelanding (missing thorn), Spanish, Czech, Portuguese, Italian
    C095 := 'Î' //U+00CE    [195 142] Latin Capital Letter I with Circumflex    French, Kurmanji, Romanian, Kurdish, Italian
    C096 := 'Ï' //U+00CF    [195 143] Latin Capital Letter I with Diaeresis     French
    C097 := 'Ì' //U+00CC    [195 140] Latin Capital Letter I with Grave         Portuguese, Italian
    C098 := 'Ł' //U+0141    [197 129] Latin Capital Letter L with Stroke        Polish
    C099 := 'Ń' //U+0143    [197 131] Latin Capital Letter N with Acute         Polish
    C100 := 'Ñ' //U+00D1    [195 145] Latin Capital Letter N with Tilde         Spanish, Czech
    C101 := 'Ó' //U+00D3    [195 147] Latin Capital Letter O with Acute         Icelanding (missing thorn), Spanish, Czech, Portuguese, Italian, Polish
    C102 := 'Ô' //U+00D4    [195 148] Latin Capital Letter O with Circumflex    French, Portuguese
    C103 := 'Ö' //U+00D6    [195 150] Latin Capital Letter O with Diaeresis     Icelanding (missing thorn), German, Swedish, Finnish, Turkish
    C104 := 'Ò' //U+00D2    [195 146] Latin Capital Letter O with Grave         Portuguese, Italian
    C105 := 'Ø' //U+00D8    [195 152] Latin Capital Letter O with Stroke        Danish, Norwegian
    C106 := 'Õ' //U+00D5    [195 149] Latin Capital Letter O with Tilde         Portuguese
    C107 := 'Ř' //U+0158    [197 152] Latin Capital Letter R with Caron         Czech
    C108 := 'Ś' //U+015A    [197 154] Latin Capital Letter S with Acute         Polish
    C109 := 'Š' //U+0160    [197 160] Latin Capital Letter S with Caron         Czech, Estonian, Croatian, Serbian-Bosnian(latinized), Slovenian
    C110 := 'Ş' //U+015E    [197 158] Latin Capital Letter S with Cedilla       Kurdish, Turkish
    C111 := 'Ș' //U+0218    [200 152] Latin Capital Letter S with Comma Below   Kurmanji, Romanian
    C112 := 'Þ' //U+00DE    [195 158] Latin Capital Letter Thorn                Icelandic
    C113 := 'Ť' //U+0164    [197 164] Latin Capital Letter T with Caron         Czech
    C114 := 'Ț' //U+021A    [200 154] Latin Capital Letter T with Comma Below   Romanian
    C115 := 'Ú' //U+00DA    [195 154] Latin Capital Letter U with Acute         Icelanding (missing thorn), Spanish, Czech, Portuguese, Italian
    C116 := 'Û' //U+00DB    [195 155] Latin Capital Letter U with Circumflex    French, Kurmanji, Kurdish
    C117 := 'Ü' //U+00DC    [195 156] Latin Capital Letter U with Diaeresis     French, Spanish, German, Estonian, Turkish
    C118 := 'Ù' //U+00D9    [195 153] Latin Capital Letter U with Grave         French, Portuguese, Italian
    C119 := 'Ů' //U+016E    [197 174] Latin Capital Letter U with Ring Above    Czech
    C120 := 'Ý' //U+00DD    [195 157] Latin Capital Letter Y with Acute         Icelanding (missing thorn), Czech
    C121 := 'Ÿ' //U+00DC    [195 184] Latin Capital Letter U with Diaeresis     French
    C122 := 'Ź' //U+0179    [197 185] Latin Capital Letter Z with Acute         Polish
    C123 := 'Ž' //U+017D    [197 189] Latin Capital Letter Z with Caron         Czech, Estonian, Croatian, Serbian-Bosnian(latinized), Slovenian
    C124 := 'Ż' //U+017B    [197 187] Latin Capital Letter Z with Dot Above     Polish
    
    //Latin Extended Small Letters 54 runes
    C125 := 'æ' //U+00E6    [195 166] Latin Small Letter Ae
    C126 := 'œ' //U+0153    [197 147] Latin Small Letter Oe
    C127 := 'á' //U+00E1    [195 161] Latin Small Letter A with Acute
    C128 := 'ă' //U+0103    [196 131] Latin Small Letter A with Breve
    C129 := 'â' //U+00E2    [195 162] Latin Small Letter A with Circumflex
    C130 := 'ä' //U+00E4    [195 164] Latin Small Letter A with Diaeresis
    C131 := 'à' //U+00E0    [195 160] Latin Small Letter A with Grave
    C132 := 'ą' //U+0105    [196 133] Latin Small Letter A with Ogonek
    C133 := 'å' //U+00E5    [195 165] Latin Small Letter A with Ring Above
    C134 := 'ã' //U+00E3    [195 163] Latin Small Letter A with Tilde
    C135 := 'ć' //U+0107    [196 135] Latin Small Letter C with Acute
    C136 := 'č' //U+010D    [196 141] Latin Small Letter C with Caron
    C137 := 'ç' //U+00E7    [195 167] Latin Small Letter C with Cedilla
    C138 := 'ď' //U+010F    [196 143] Latin Small Letter D with Caron
    C139 := 'đ' //U+0111    [196 145] Latin Small Letter D with Stroke
    C140 := 'é' //U+00E9    [195 169] Latin Small Letter E with Acute
    C141 := 'ě' //U+011B    [196 155] Latin Small Letter E with Caron
    C142 := 'ê' //U+00EA    [195 170] Latin Small Letter E with Circumflex
    C143 := 'ë' //U+00EB    [195 171] Latin Small Letter E with Diaeresis
    C144 := 'è' //U+00E8    [195 168] Latin Small Letter E with Grave
    C145 := 'ę' //U+0119    [196 153] Latin Small Letter E with Ogonek
    C146 := 'ğ' //U+011F    [196 159] Latin Small Letter G with Breve
    C147 := 'í' //U+00ED    [195 173] Latin Small Letter I with Acute
    C148 := 'î' //U+00EE    [195 174] Latin Small Letter I with Circumflex
    C149 := 'ï' //U+00EF    [195 175] Latin Small Letter I with Diaeresis
    C150 := 'ì' //U+00EC    [195 172] Latin Small Letter I with Grave
    C151 := 'ł' //U+0142    [197 130] Latin Small Letter L with Stroke
    C152 := 'ń' //U+0144    [197 132] Latin Small Letter N with Acute
    C153 := 'ñ' //U+00F1    [195 177] Latin Small Letter N with Tilde
    C154 := 'ó' //U+00F3    [195 179] Latin Small Letter O with Acute
    C155 := 'ô' //U+00F4    [195 180] Latin Small Letter O with Circumflex
    C156 := 'ö' //U+00F6    [195 182] Latin Small Letter O with Diaeresis
    C157 := 'ò' //U+00F2    [195 178] Latin Small Letter O with Grave
    C158 := 'ø' //U+00F8    [195 184] Latin Small Letter O with Stroke
    C159 := 'õ' //U+00F5    [195 181] Latin Small Letter O with Tilde
    C160 := 'ř' //U+0159    [197 153] Latin Small Letter R with Caron
    C161 := 'ś' //U+015B    [197 155] Latin Small Letter S with Acute
    C162 := 'š' //U+0161    [197 161] Latin Small Letter S with Caron
    C163 := 'ş' //U+015F    [197 159] Latin Small Letter S with Cedilla
    C164 := 'ș' //U+0219    [200 153] Latin Small Letter S with Comma Below
    C165 := 'þ' //U+00FE    [195 190] Latin Small Letter Thorn
    C166 := 'ť' //U+0165    [197 165] Latin Small Letter T with Caron
    C167 := 'ț' //U+021B    [200 155] Latin Small Letter T with Comma Below
    C168 := 'ú' //U+00FA    [195 186] Latin Small Letter U with Acute
    C169 := 'û' //U+00FB    [195 187] Latin Small Letter U with Circumflex
    C170 := 'ü' //U+00FC    [195 188] Latin Small Letter U with Diaeresis
    C171 := 'ù' //U+00F9    [195 185] Latin Small Letter U with Grave
    C172 := 'ů' //U+016F    [197 175] Latin Small Letter U with Ring Above
    C173 := 'ý' //U+00FD    [195 189] Latin Small Letter Y with Acute
    C174 := 'ÿ' //U+00FF    [195 191] Latin Small Letter Y with Diaeresis
    C175 := 'ź' //U+017A    [197 186] Latin Small Letter Z with Acute
    C176 := 'ž' //U+017E    [197 190] Latin Small Letter Z with Caron
    C177 := 'ż' //U+017C    [197 188] Latin Small Letter Z with Dot Above
    C178 := 'ß' //U+00DF    [195 159] Latin Small Letter Sharp S
    
    //Greek Capital Letters 10 runes
    C179 := 'Γ' //U+0393    [206 147] Greek Capital Letter Gamma
    C180 := 'Δ' //U+0394    [206 148] Greek Capital Letter Delta
    C181 := 'Θ' //U+0398    [206 152] Greek Capital Letter Theta
    C182 := 'Λ' //U+039B    [206 155] Greek Capital Letter Lambda
    C183 := 'Ξ' //U+039E    [206 158] Greek Capital Letter Xi
    C184 := 'Π' //U+03A0    [206 160] Greek Capital Letter Pi
    C185 := 'Σ' //U+03A3    [206 163] Greek Capital Letter Sigma
    C186 := 'Φ' //U+03A6    [206 166] Greek Capital Letter Phi
    C187 := 'Ψ' //U+03A8    [206 168] Greek Capital Letter Psi
    C188 := 'Ω' //U+03A9    [206 169] Greek Capital Letter Omega
    
    //Greek Small Letters 23 runes
    C189 := 'α' //U+03B1    [206 177] Greek Small Letter Alpha
    C190 := 'β' //U+03B2    [206 178] Greek Small Letter Beta
    C191 := 'γ' //U+03B3    [206 179] Greek Small Letter Gamma
    C192 := 'δ' //U+03B4    [206 180] Greek Small Letter Delta
    C193 := 'ε' //U+03B5    [206 181] Greek Small Letter Epsilon
    C194 := 'ζ' //U+03B6    [206 182] Greek Small Letter Zeta
    C195 := 'η' //U+03B7    [206 183] Greek Small Letter Eta
    C196 := 'θ' //U+03B8    [206 184] Greek Small Letter Theta
    C197 := 'ι' //U+03B9    [206 185] Greek Small Letter Iota
    C198 := 'κ' //U+03BA    [206 186] Greek Small Letter Kappa
    C199 := 'λ' //U+03BB    [206 187] Greek Small Letter Lambda
    C200 := 'μ' //U+03BC    [206 188] Greek Small Letter Mu
    C201 := 'ν' //U+03BD    [206 189] Greek Small Letter Nu
    C202 := 'ξ' //U+03BE    [206 190] Greek Small Letter Xi
    C203 := 'π' //U+03C0    [206 192] Greek Small Letter Pi
    C204 := 'ρ' //U+03C1    [206 193] Greek Small Letter Rho
    C205 := 'σ' //U+03C3    [206 195] Greek Small Letter Sigma
    C206 := 'ς' //U+03C2    [206 194] Greek Small Letter Final Sigma
    C207 := 'τ' //U+03C4    [206 196] Greek Small Letter Tau
    C208 := 'φ' //U+03C6    [206 198] Greek Small Letter Phi
    C209 := 'χ' //U+03C7    [206 199] Greek Small Letter Chi
    C210 := 'ψ' //U+03C8    [206 200] Greek Small Letter Psi
    C211 := 'ω' //U+03C9    [206 201] Greek Small Letter Omega
    
    //Cyrillic Capital Letters 19 runes
    C212 := 'Б' //U+0411    [208 145] Cyrillic Capital Letter Be
    C213 := 'Д' //U+0414    [208 148] Cyrillic Capital Letter De
    C214 := 'Ж' //U+0416    [208 150] Cyrillic Capital Letter Zhe
    C215 := 'З' //U+0417    [208 151] Cyrillic Capital Letter Ze
    C216 := 'И' //U+0418    [208 152] Cyrillic Capital Letter I
    C217 := 'Й' //U+0419    [208 153] Cyrillic Capital Letter Short I
    C218 := 'Л' //U+041B    [208 155] Cyrillic Capital Letter El
    C219 := 'П' //U+041F    [208 159] Cyrillic Capital Letter Pe
    C220 := 'У' //U+0423    [208 163] Cyrillic Capital Letter U
    C221 := 'Ц' //U+0426    [208 166] Cyrillic Capital Letter Tse
    C222 := 'Ч' //U+0427    [208 167] Cyrillic Capital Letter Che
    C223 := 'Ш' //U+0428    [208 168] Cyrillic Capital Letter Sha
    C224 := 'Щ' //U+0429    [208 169] Cyrillic Capital Letter Shcha
    C225 := 'Ъ' //U+042A    [208 170] Cyrillic Capital Letter Hard Sign
    C226 := 'Ы' //U+042B    [208 171] Cyrillic Capital Letter Yeru
    C227 := 'Ь' //U+042C    [208 172] Cyrillic Capital Letter Soft Sign
    C228 := 'Э' //U+042D    [208 173] Cyrillic Capital Letter E
    C229 := 'Ю' //U+042E    [208 174] Cyrillic Capital Letter Yu
    C230 := 'Я' //U+042F    [208 175] Cyrillic Capital Letter Ya
    
    //Cyrillic Small Letters 25 runes
    C231 := 'б' //U+0431    [208 177] Cyrillic Small Letter Be
    C232 := 'в' //U+0432    [208 178] Cyrillic Small Letter Ve
    C233 := 'д' //U+0434    [208 180] Cyrillic Small Letter De
    C234 := 'ж' //U+0436    [208 182] Cyrillic Small Letter Zhe
    C235 := 'з' //U+0437    [208 183] Cyrillic Small Letter Ze
    C236 := 'и' //U+0438    [208 184] Cyrillic Small Letter I
    C237 := 'й' //U+0439    [208 185] Cyrillic Small Letter Short I
    C238 := 'к' //U+043A    [208 186] Cyrillic Small Letter Ka
    C239 := 'л' //U+043B    [208 187] Cyrillic Small Letter El
    C240 := 'м' //U+043C    [208 188] Cyrillic Small Letter Em
    C241 := 'н' //U+043D    [208 189] Cyrillic Small Letter En
    C242 := 'п' //U+043F    [208 191] Cyrillic Small Letter Pe
    C243 := 'т' //U+0442    [209 130] Cyrillic Small Letter Te
    C244 := 'у' //U+0443    [209 131] Cyrillic Small Letter U
    C245 := 'ф' //U+0444    [209 132] Cyrillic Small Letter Ef
    C246 := 'ц' //U+0446    [209 134] Cyrillic Small Letter Tse
    C247 := 'ч' //U+0447    [209 135] Cyrillic Small Letter Che
    C248 := 'ш' //U+0448    [209 136] Cyrillic Small Letter Sha
    C249 := 'щ' //U+0449    [209 137] Cyrillic Small Letter Shcha
    C250 := 'ъ' //U+044A    [209 138] Cyrillic Small Letter Hard Sign
    C251 := 'ы' //U+044B    [209 139] Cyrillic Small Letter Yeru
    C252 := 'ь' //U+044C    [209 140] Cyrillic Small Letter Soft Sign
    C253 := 'э' //U+044D    [209 141] Cyrillic Small Letter E
    C254 := 'ю' //U+044E    [209 142] Cyrillic Small Letter Yu
    C255 := 'я' //U+044F    [209 143] Cyrillic Small Letter Ya
    
    Row00 := [...]rune{C000, C001, C002, C003, C004, C005, C006, C007, C008, C009, C010, C011, C012, C013, C014, C015}
    Row01 := [...]rune{C016, C017, C018, C019, C020, C021, C022, C023, C024, C025, C026, C027, C028, C029, C030, C031}
    Row02 := [...]rune{C032, C033, C034, C035, C036, C037, C038, C039, C040, C041, C042, C043, C044, C045, C046, C047}
    Row03 := [...]rune{C048, C049, C050, C051, C052, C053, C054, C055, C056, C057, C058, C059, C060, C061, C062, C063}
    Row04 := [...]rune{C064, C065, C066, C067, C068, C069, C070, C071, C072, C073, C074, C075, C076, C077, C078, C079}
    Row05 := [...]rune{C080, C081, C082, C083, C084, C085, C086, C087, C088, C089, C090, C091, C092, C093, C094, C095}
    Row06 := [...]rune{C096, C097, C098, C099, C100, C101, C102, C103, C104, C105, C106, C107, C108, C109, C110, C111}
    Row07 := [...]rune{C112, C113, C114, C115, C116, C117, C118, C119, C120, C121, C122, C123, C124, C125, C126, C127}
    Row08 := [...]rune{C128, C129, C130, C131, C132, C133, C134, C135, C136, C137, C138, C139, C140, C141, C142, C143}
    Row09 := [...]rune{C144, C145, C146, C147, C148, C149, C150, C151, C152, C153, C154, C155, C156, C157, C158, C159}
    Row10 := [...]rune{C160, C161, C162, C163, C164, C165, C166, C167, C168, C169, C170, C171, C172, C173, C174, C175}
    Row11 := [...]rune{C176, C177, C178, C179, C180, C181, C182, C183, C184, C185, C186, C187, C188, C189, C190, C191}
    Row12 := [...]rune{C192, C193, C194, C195, C196, C197, C198, C199, C200, C201, C202, C203, C204, C205, C206, C207}
    Row13 := [...]rune{C208, C209, C210, C211, C212, C213, C214, C215, C216, C217, C218, C219, C220, C221, C222, C223}
    Row14 := [...]rune{C224, C225, C226, C227, C228, C229, C230, C231, C232, C233, C234, C235, C236, C237, C238, C239}
    Row15 := [...]rune{C240, C241, C242, C243, C244, C245, C246, C247, C248, C249, C250, C251, C252, C253, C254, C255}
    
    Matrix := [16][16]rune{Row00, Row01, Row02, Row03, Row04, Row05, Row06, Row07, Row08, Row09, Row10, Row11, Row12, Row13, Row14, Row15}
    return Matrix
}
