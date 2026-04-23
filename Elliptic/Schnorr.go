package Elliptic

import (
    "DALOS_Crypto/Blake3"
    "fmt"
    "math/big"
    "strconv"
    "strings"
)

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

// SchnorrHash computes the Hash(r||P||m) that is used in SchnorrSign Function
func (e *Ellipse) SchnorrHash(R *big.Int, PublicKey string, Message string) *big.Int {
    var (
        PublicKeyStringX  string
        PublicKeyStringY  string
        SchnorrHashOutput *big.Int
    )
    //Convert R to its base 2 Representation as string
    RAsBinaryString := R.Text(2)
    
    //Retrieve the Affine Coordinates from the PublicKey, and gets their base 2 Representation as strings
    PublicKeyAffine, err := ConvertPublicKeyToAffineCoords(PublicKey)
    if err == nil {
        PublicKeyStringX = PublicKeyAffine.AX.Text(2)
        PublicKeyStringY = PublicKeyAffine.AY.Text(2)
        
    }
    
    //Converts the string Message to []byte , then to its base 2 representation
    BinaryMessage := Hash2BigInt([]byte(Message)).Text(2)
    
    //Concatenate all 4 Resulted Binary Strings
    ConcatenatedBinaryString := RAsBinaryString + PublicKeyStringX + PublicKeyStringY + BinaryMessage
    //Converts the ConcatenatedBinaryString representing a BitString to []byte
    ConcatenatedBinaryStringToByteSlice, err2 := BinaryStringToBytes(ConcatenatedBinaryString)
    
    //Going Forward, the ConcatenatedBinaryStringToByteSlice is hashed with Blake3, creating an output in bit size
    //using the Curve Safe Scalar size divided by 8.
    if err2 == nil {
        OutputSizeInBytes := int(e.S) / 8
        Hash := Blake3.SumCustom(ConcatenatedBinaryStringToByteSlice, OutputSizeInBytes)
        SchnorrHashOutput = Hash2BigInt(Hash)
    }
    return SchnorrHashOutput
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
func (e *Ellipse) SchnorrSign(KeyPair DalosKeyPair, Message string) string {
    //Outputs the SchnorrSignature as a string, in a special format
    var Signature SchnorrSignature
    
    //Generate a random number z
    RandomBits := e.GenerateRandomBitsOnCurve()
    z, _ := e.GenerateScalarFromBitString(RandomBits)
    
    //Calculate Curve Point R = z*G (we need r = R.AX for further computations)
    RExtended := e.ScalarMultiplierWithGenerator(z)
    RAffine := e.Extended2Affine(RExtended) //Part of the Output Signature
    r := RAffine.AX
    
    //Calculate Message-Hash m as integer, using Inputs (r, PublicKey of the Signer, and Message of the Signer)
    m := e.SchnorrHash(r, KeyPair.PUBL, Message)
    
    //Calculate s = z + Hash(r||P||m)*k (Part of the Output Signature)
    k := ConvertBase49toBase10(KeyPair.PRIV)
    s := new(big.Int).Add(z, new(big.Int).Mul(m, k))
    
    //Output Computed Values into the Signature.
    Signature.R = RAffine
    Signature.S = s
    SignatureAsString := ConvertSchnorrSignatureToString(Signature)
    
    return SignatureAsString
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
//==================================================================
func (e *Ellipse) SchnorrVerify(Signature, Message, PublicKey string) bool {
    var R CoordAffine
    Schnorr, err := ConvertSchnorrSignatureAsStringToStructure(Signature)
    
    //Step 1: Get R Point; we also need its Extended Form for Addition
    if err == nil {
        R = Schnorr.R
    }
    RExtend := e.Affine2Extended(R)
    
    //Step 2: Get m point by getting r first; r = R.AX
    r := R.AX
    m := e.SchnorrHash(r, PublicKey, Message)
    
    //Step 3: Get P Point from the Public Key, we need its Extended Coordinates
    PAffine, _ := ConvertPublicKeyToAffineCoords(PublicKey)
    PExtend := e.Affine2Extended(PAffine)
    
    //Step 4: Compute R + Hash(r||P||m) *   P
    //This is an Elliptic Point Addition between R and Hash(r||P||m) * P [Hash(r||P||m) being m]
    //That is, it is an Elliptic Point Addition between R, and m * P
    
    //Step 4.1: Compute m * P
    Multiplication := e.ScalarMultiplier(m, PExtend)
    //Step 4.1: Added it with R
    RightTerm, _ := e.Addition(RExtend, Multiplication)
    
    //Step 5: Compute s * G (multiply the Scalar s with the Ellipse Generator)
    LeftTerm := e.ScalarMultiplierWithGenerator(Schnorr.S)
    
    Result := e.ArePointsEqual(LeftTerm, RightTerm)
    return Result
}
