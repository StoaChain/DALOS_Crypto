package main

import (
	el "DALOS_Crypto/Elliptic"
	"fmt"
)

// PrintKeys writes the key-pair (PRIV + PUBL) to stdout with the
// canonical Ouronet banner.
//
// v4.0.0 carve-out (Phase 10, REQ-31): moved verbatim from
// Elliptic/KeyGeneration.go into the main-package CLI surface so the
// Elliptic/ package stays pure-crypto (no fmt.Println in non-test source).
func PrintKeys(Keys el.DalosKeyPair) {
	fmt.Println("")
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
	fmt.Println("Your Key-Pair is:")
	fmt.Println("")
	fmt.Println("PRIV: ", Keys.PRIV)
	fmt.Println("")
	fmt.Print("PUBL: ", Keys.PUBL)
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
}

// PrintPrivateKey writes the three private-key representations
// (BitString / Int10 / Int49) to stdout with the canonical Ouronet
// banner. v4.0.0 carve-out from Elliptic/KeyGeneration.go.
func PrintPrivateKey(Keys el.DalosPrivateKey) {
	fmt.Println("")
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
	fmt.Println("Your Private Key is in (Binary, Decimal, Base49):")
	fmt.Println("")
	fmt.Println("Bits : ", Keys.BitString)
	fmt.Println("")
	fmt.Println("Int10: ", Keys.Int10)
	fmt.Println("")
	fmt.Println("Int49: ", Keys.Int49)
	fmt.Println("")
	fmt.Println("=====================ѺurѺ₿ѺrѺΣ=====================")
}
