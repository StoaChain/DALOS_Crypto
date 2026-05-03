package main

import (
	el "DALOS_Crypto/Elliptic"
	"DALOS_Crypto/keystore"
	"fmt"
)

// ProcessIntegerFlag validates the supplied integer-encoded private key
// and returns its 1600-bit binary form, or "" on failure.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. The receiver `(e *Ellipse)` is rewritten
// to `e *el.Ellipse` first parameter (Go forbids methods on external
// types). Empty-string sentinel preserved (KG-2 hardening — never
// terminates the process; no os.Exit).
func ProcessIntegerFlag(e *el.Ellipse, flagValue string, isBase10 bool) string {
	// Validate the private key
	isValid, BitString := e.ValidatePrivateKey(flagValue, isBase10)
	if !isValid {
		fmt.Println("Error: Invalid private key.")
		return ""
	}
	return BitString
}

// ProcessPrivateKeyConversion derives and prints the key pair + addresses
// from a bit-string private key.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. KG-2 hardening preserved: invalid bit
// string produces a clean error message and the function returns
// early without printing misleading output.
func ProcessPrivateKeyConversion(e *el.Ellipse, BitString string) {
	Scalar, err := e.GenerateScalarFromBitString(BitString)
	if err != nil {
		fmt.Println("Error: invalid bit string:", err)
		return
	}
	// Get the Private Key
	PrivateKey, err := e.ScalarToPrivateKey(Scalar)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Get the Key Pair
	KeyPair, err2 := e.ScalarToKeys(Scalar)
	if err2 != nil {
		fmt.Println("Error generating key pair:", err2)
		return
	}

	// Print the Private Key (same-package main call)
	PrintPrivateKey(PrivateKey)

	// Print the Key Pair (same-package main call)
	PrintKeys(KeyPair)

	//Printing Accounts
	SmartAccount := el.DalosAddressMaker(KeyPair.PUBL, true)
	StandardAccount := el.DalosAddressMaker(KeyPair.PUBL, false)
	fmt.Println("")
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
	fmt.Println("Your Smart DALOS Account Address is:")
	fmt.Println("")
	fmt.Println(SmartAccount)
	fmt.Println("")
	fmt.Println("")
	fmt.Println("Your Standard DALOS Account Address is:")
	fmt.Println("")
	fmt.Println(StandardAccount)
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
}

// ProcessKeyGeneration runs the full CLI key-generation pipeline:
// bitstring → scalar → keys → addresses → encrypted file.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. The trailing call to `e.SaveBitString(...)`
// is rewired to `SaveBitString(e, ...)` once T10.9 lands the
// SaveBitString relocation in this same file (transitional duplication
// keeps the original Elliptic-side method valid until then).
func ProcessKeyGeneration(e *el.Ellipse, BitString string, smartFlag *bool, password string) {
	// Generate Scalar from BitString
	Scalar, err := e.GenerateScalarFromBitString(BitString)
	if err != nil {
		fmt.Println("Error: invalid bit string:", err)
		return
	}

	// Get the Private Key
	PrivateKey, err := e.ScalarToPrivateKey(Scalar)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Get the Key Pair
	KeyPair, err := e.ScalarToKeys(Scalar)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	// Print the Private Key (same-package main call)
	PrintPrivateKey(PrivateKey)

	// Print the Key Pair (same-package main call)
	PrintKeys(KeyPair)

	// Generate account based on the smart or standard flag
	if *smartFlag {
		SmartAccount := el.DalosAddressMaker(KeyPair.PUBL, true)
		fmt.Println("")
		fmt.Println("")
		fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
		fmt.Println("Your Smart DALOS Account Address is:")
		fmt.Println("")
		fmt.Println(SmartAccount)
		fmt.Println("")
		fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
	} else {
		StandardAccount := el.DalosAddressMaker(KeyPair.PUBL, false)
		fmt.Println("")
		fmt.Println("")
		fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
		fmt.Println("Your Standard DALOS Account Address is:")
		fmt.Println("")
		fmt.Println(StandardAccount)
		fmt.Println("")
		fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
	}

	// Save the BitString with the provided password
	// (T10.9 cutover: same-package main.SaveBitString free function)
	SaveBitString(e, BitString, password)
}

// SaveBitString prompts the user to confirm their password (interactive
// stdin via fmt.Scanln) and then calls keystore.ExportPrivateKey to
// serialize the wallet file.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go. The receiver `(e *Ellipse)` is rewritten
// to `e *el.Ellipse` first parameter; the trailing call to
// `e.ExportPrivateKey(...)` is rewired to `keystore.ExportPrivateKey(e, ...)`.
// Living in `main` package keeps the interactive `fmt.Scanln` out of
// the pure-crypto Elliptic/ surface.
func SaveBitString(e *el.Ellipse, BitString, Password string) {
	var P2 string
	var Condition bool

	fmt.Println("")
	fmt.Println("The BitString representing the Private-Key is being saved!")

	// Confirm password
	for {
		fmt.Println("Confirm the entered Password by retyping it:")
		_, _ = fmt.Scanln(&P2)
		if Password == P2 {
			Condition = true
		} else {
			fmt.Println("Retyped password doesn't match the previous entered password!")
			Condition = false
		}

		// If confirmed correctly, break the loop
		if Condition {
			break
		}
	}

	// Export the private key using the confirmed password (cross-package call)
	keystore.ExportPrivateKey(e, BitString, Password)
}
