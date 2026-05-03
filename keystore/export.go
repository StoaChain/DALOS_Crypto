package keystore

import (
	"DALOS_Crypto/AES"
	el "DALOS_Crypto/Elliptic"
	"fmt"
	"math/big"
	"os"
)

// ExportPrivateKey serializes a Genesis private key to the canonical
// wallet file under the public-key-derived filename.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. The receiver `(e *Ellipse)` is rewritten
// to `e *el.Ellipse` first parameter because Go forbids defining
// methods on types from external packages.
func ExportPrivateKey(e *el.Ellipse, BitString, Password string) {
	// Helper function to convert from base 2 to base 49
	convertBase2ToBase49 := func(input string) string {
		// Convert the input string from base 2 to big.Int
		bigIntValue := new(big.Int)
		if _, success := bigIntValue.SetString(input, 2); success {
			// Convert the big.Int value to base 49
			return bigIntValue.Text(49)
		}
		return "" // Return an empty string on failure
	}
	encryptedRaw := AES.EncryptBitString(BitString, Password)
	if encryptedRaw == "" {
		fmt.Println("Error: AES encryption failed; aborting key export.")
		return
	}
	EncryptedPK := convertBase2ToBase49(encryptedRaw)

	Scalar, err := e.GenerateScalarFromBitString(BitString)
	if err != nil {
		fmt.Println("Error: invalid bit string in ExportPrivateKey:", err)
		return
	}
	KeyPair, err := e.ScalarToKeys(Scalar)
	if err != nil {
		fmt.Println("Error: failed to derive key pair in ExportPrivateKey:", err)
		return
	}
	PublicKey := KeyPair.PUBL
	FileName := GenerateFilenameFromPublicKey(PublicKey)
	SmartAddress := el.DalosAddressMaker(PublicKey, true)
	StandardAddress := el.DalosAddressMaker(PublicKey, false)

	String0 := "=====================ѺurѺ₿ѺrѺΣ====================="
	String1 := "Your DALOS Account PrivateKey in encrypted form is:"
	String2 := "Your DALOS Account PublicKey:"
	String3 := "Your Smart DALOS Account Address is:"
	String4 := "Your Standard DALOS Account Address is:"

	OutputFile, err := os.Create(FileName)
	if err != nil {
		fmt.Println("Error: failed to create export file:", err)
		return
	}
	defer OutputFile.Close()

	//Exporting Data
	_, _ = fmt.Fprintln(OutputFile, String0)
	_, _ = fmt.Fprintln(OutputFile, String1)
	_, _ = fmt.Fprintln(OutputFile, EncryptedPK)
	_, _ = fmt.Fprintln(OutputFile, String0)
	_, _ = fmt.Fprintln(OutputFile, String2)
	_, _ = fmt.Fprintln(OutputFile, PublicKey)
	_, _ = fmt.Fprintln(OutputFile, String0)
	_, _ = fmt.Fprintln(OutputFile, String3)
	_, _ = fmt.Fprintln(OutputFile, SmartAddress)
	_, _ = fmt.Fprintln(OutputFile, String4)
	_, _ = fmt.Fprintln(OutputFile, StandardAddress)
	_, _ = fmt.Fprint(OutputFile, String0)
}
