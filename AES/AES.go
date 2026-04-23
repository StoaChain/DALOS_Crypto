package AES

import (
	"DALOS_Crypto/Blake3"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

//
// Converts a String of 0s and 1s to a Slice of bytes.
//
func BitStringToHex(BitString string) []byte {
	var TwoToTen = new(big.Int)
	//Converting BitString to HEX
	TwoToTen.SetString(BitString, 2)
	BitStringHex := TwoToTen.Text(16)
	BitStringToEncrypt, _ := hex.DecodeString(BitStringHex)
	return BitStringToEncrypt
}

//
// Hashes a Password with Blake3 and creates a slice of bytes 32 units long
// that can be used as a KEY for AES Encryption and Decryption
//
func MakeKeyFromPassword(Password string) []byte {
	var SByteArray []byte
	//Making Key from Password. A Blake3 Hash with 32 bytes output is used.
	PasswordToByteSlice := []byte(Password)
	HashedPassword := Blake3.SumCustom(PasswordToByteSlice, 32)
	//Converting the resulting hash which is a slice of bytes, to hex (byte to hex)
	for i := 0; i < len(HashedPassword); i++ {
		SByteArray = append(SByteArray, HashedPassword[i])
	}
	Key, _ := hex.DecodeString(hex.EncodeToString(SByteArray))
	return Key
}

//
// Encrypts a String of 0s and 1s using a Password via AES and outputs another String of 0s and 1s
func EncryptBitString(BitString, Password string) (BitStringOutput string) {
	var CipherTextDec = new(big.Int)

	//Converting BitString to HEX
	BitStringToEncrypt := BitStringToHex(BitString)

	//Making Key from Password. A Blake3 Hash with 32 bytes output is used.
	Key := MakeKeyFromPassword(Password)

	//Create a New Cipher Block from the Key
	Block, err1 := aes.NewCipher(Key)
	// if there are any errors, handle them
	if err1 != nil {
		fmt.Println("Block Error:", err1)
	}

	//Create a new Galois Counter Mode
	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	AesGcm, err2 := cipher.NewGCM(Block)
	// if any error generating new GCM
	// handle them
	if err2 != nil {
		fmt.Println("AesGcm Error:", err2)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, AesGcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err3 := io.ReadFull(rand.Reader, nonce); err3 != nil {
		fmt.Println("Nonce Error:", err3)
	}

	//Encrypt the data using aesGCM.Seal
	CipherText := AesGcm.Seal(nonce, nonce, BitStringToEncrypt, nil)

	//Converting CipherText to a BitString
	CipherTextHex := hex.EncodeToString(CipherText)
	CipherTextDec.SetString(CipherTextHex, 16)
	BitStringOutput = CipherTextDec.Text(2)
	return BitStringOutput
}

func DecryptBitString(BitString, Password string) (BitStringOutput string, Error error) {
	var DecryptedDataDec = new(big.Int)

	//Converting BitString to HEX
	BitStringToDecrypt := BitStringToHex(BitString)

	//Making Key from Password. A Blake3 Hash with 32 bytes output is used.
	Key := MakeKeyFromPassword(Password)

	//Create a New Cipher Block from the Key
	Block, err1 := aes.NewCipher(Key)
	// if there are any errors, handle them
	if err1 != nil {
		fmt.Println("Block Error:", err1)
	}

	//Create a new Galois Counter Mode
	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	AesGcm, err2 := cipher.NewGCM(Block)
	// if any error generating new GCM
	// handle them
	if err2 != nil {
		fmt.Println("AesGcm Error:", err2)
	}

	//Get the nonce size
	NonceSize := AesGcm.NonceSize()

	//Extract the nonce from the encrypted data
	Nonce, CipherText := BitStringToDecrypt[:NonceSize], BitStringToDecrypt[NonceSize:]

	//Decrypt the data
	DecryptedData, err3 := AesGcm.Open(nil, Nonce, CipherText, nil)
	if err3 != nil {
		fmt.Println("DecryptedData Error:", err3)
	}

	//Converting DecryptedData back to a BitString
	DecryptedDataHex := hex.EncodeToString(DecryptedData)
	DecryptedDataDec.SetString(DecryptedDataHex, 16)
	BitStringOutput = DecryptedDataDec.Text(2)
	return BitStringOutput, err3
}
