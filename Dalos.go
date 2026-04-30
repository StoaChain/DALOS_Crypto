package main

import (
    el "DALOS_Crypto/Elliptic"
    "flag"
    "fmt"
    "log"
    "os"
)

// Function to check if a character exists in the CharacterMatrix
func isCharInMatrix(char rune, matrix [16][16]rune) bool {
    for i := 0; i < 16; i++ {
        for j := 0; j < 16; j++ {
            if matrix[i][j] == char {
                return true
            }
        }
    }
    return false
}

// Function to confirm seed words
func confirmSeedWords(seedWords []string) {
    var inputWords []string
    
    fmt.Println("Please retype the seed words to confirm (separated by spaces):")
    
    // Using fmt.Scan to read all words (space-separated) into inputWords
    for i := 0; i < len(seedWords); i++ {
        var word string
        _, err := fmt.Scan(&word)
        if err != nil {
            fmt.Println("Error reading input:", err)
            os.Exit(1)
        }
        inputWords = append(inputWords, word)
    }
    
    // Check if the number of input words matches the original
    if len(inputWords) != len(seedWords) {
        fmt.Println("Error: Number of seed words does not match.")
        os.Exit(1)
    }
    
    // Check each seed word
    for i, word := range seedWords {
        if word != inputWords[i] {
            fmt.Printf("Error: Seed word '%s' does not match '%s'.\n", word, inputWords[i])
            os.Exit(1)
        }
    }
    
    fmt.Println("Seed words confirmed successfully.")
}

func main() {
    // Variables
    DalosEllipse := el.DalosEllipse()
    CharacterMatrix := el.CharacterMatrix()
    
    // Main command flags
    generateFlag := flag.Bool("g", false, "Generate a DALOS Key-Pair")
    specialGenerateFlag := flag.Bool("gd", false, "Special variant of generating a DALOS Key-Pair in Demo Mode (must be used alone)")
    convertFlag := flag.Bool("c", false, "Convert a DALOS PRIV Key to a PUBL Key")
    
    openFlag := flag.String("open", "", "Path to the wallet file to open")
    signFlag := flag.String("sign", "", "Signs a message with the private Key from the Opened Walelt")
    verifyFlag := flag.String("verify", "", "Verifies the signature of a Message m against a public key")
    
    // Sub-options for generating
    rawFlag := flag.Bool("raw", false, "Generate a DALOS KEY-Pair from random bits")
    bitFlag := flag.String("bits", "", "Generate a DALOS KEY-Pair from specific bits")
    seedFlag := flag.Int("seed", 0, "Generate a DALOS KEY-Pair from a Seed Words (specify number of words)")
    safeFlag := flag.Bool("safe", false, "Require confirmation of seed words")
    intaFlag := flag.String("i10", "", "Generate a DALOS KEY-Pair from an integer in base 10 as string")
    intbFlag := flag.String("i49", "", "Generate a DALOS KEY-Pair from an integer in base 49 as string")
    
    // Sub-options for generating an account
    smartFlag := flag.Bool("smart", false, "Generates a Smart DALOS Account")
    
    // Password flag for encryption
    passwordFlag := flag.String("p", "", "Password to encrypt or decrypt the private key (required for key generation)")
    // Message flag containing the Message to be signed or verified
    messageFlag := flag.String("m", "", "Contains the Message to be signed or verified")
    // Public flag containing a Public Key to be used for signature verification
    publicFlag := flag.String("public", "", "Contains the Public Key to be used for verifying a Signature of a Message")
    
    // Sub-options for conversion
    bitConvFlag := flag.String("bs", "", "Converts a private Key as BitString to Public Key")
    intConvFlag := flag.String("int10", "", "Converts a private Key as String representing an Integer in Base 10 to Public Key")
    strConvFlag := flag.String("int49", "", "Converts a private Key as String representing an Integer in Base 10 to Public Key")
    
    // Parse the flags
    flag.Parse()
    
    // Check if -safe is used without -seed
    if *safeFlag && *seedFlag == 0 {
        fmt.Println("Error: The -safe flag can only be used with the -seed flag.")
        os.Exit(1)
    }
    
    // Ensure `-gd` (special generate) is used alone
    if *specialGenerateFlag {
        if flag.NFlag() > 1 {
            fmt.Println("Error: -gd must be used alone with no other flags.")
            os.Exit(1)
        }
        fmt.Println("Generating a DALOS Key-Pair with special variant...")
        // Handle special generation logic here
        RandomBits := DalosEllipse.GenerateRandomBitsOnCurve()
        DalosEllipse.ProcessPrivateKeyConversion(RandomBits)
        os.Exit(0) // Exit after special generation
    }
    // Ensure that if -g is used, we also have the required flags
    if *generateFlag {
        // Validate the presence of one of the key generation methods (-raw, -bits, -seed, -i10, -i49)
        if !*rawFlag && *bitFlag == "" && *seedFlag == 0 && *intaFlag != "" && *intbFlag != "" {
            fmt.Println("Error: One of -raw, -bits, -seed, -i10, or -i49 must be provided when using -g.")
            os.Exit(1)
        }
        // Validate that the -p (password) flag is provided
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -g Flag.")
            os.Exit(1)
        }
        // Proceed with the key generation logic -raw Flag
        if *rawFlag {
            fmt.Println("Generating Key-Pair from random bits...")
            RandomBits := DalosEllipse.GenerateRandomBitsOnCurve()
            DalosEllipse.ProcessKeyGeneration(RandomBits, smartFlag, *passwordFlag)
        }
        // If -seed is used, validate that the correct number of seed words are provided
        if *seedFlag > 0 {
            seedCount := *seedFlag
            seedWords := flag.Args()
            // Validate seed count
            if seedCount < 4 || seedCount > 256 {
                fmt.Println("Error: Seed number must be between 4 and 256.")
                os.Exit(1)
            }
            // Validate seed words length and character restrictions
            if len(seedWords) != seedCount {
                fmt.Printf("Error: Expected %d words, but got %d.\n", seedCount, len(seedWords))
                os.Exit(1)
            }
            // Ensure seed words meet length requirements and character restrictions
            for _, word := range seedWords {
                if len(word) < 1 || len(word) > 256 {
                    fmt.Printf("Error: Seed word '%s' must be between 3 and 256 characters long.\n", word)
                    os.Exit(1) // Move exit here to stop execution
                }
                
                // Check that all characters in the word exist in the CharacterMatrix
                for _, char := range word {
                    if !isCharInMatrix(char, CharacterMatrix) {
                        fmt.Printf("Error: Seed word '%s' contains invalid character '%c'.\n", word, char)
                        os.Exit(1) // Ensure it exits if invalid character is found
                    }
                }
            }
            fmt.Println("Seed Words are valid. Proceeding with Key-Pair generation from Seed Words.")
            // Seed words confirmation if -safe flag is used
            if *safeFlag {
                confirmSeedWords(seedWords)
            }
            // Call the key generation logic using the valid seed words
            BitString := DalosEllipse.SeedWordsToBitString(seedWords)
            DalosEllipse.ProcessKeyGeneration(BitString, smartFlag, *passwordFlag)
        }
        
        // Handle other generation methods (e.g., -bits, -i10, -i49) here...
        // Proceed with the key generation logic -bits Flag
        if *bitFlag != "" {
            fmt.Println("Generating Key-Pair from specific bits...")
            // Validate the provided bit string using the ValidateBitString function
            TotalBoolean, LengthBoolean, StructureBoolean := DalosEllipse.ValidateBitString(*bitFlag)
            
            // Check validation results and provide detailed error messages
            if !TotalBoolean {
                if !LengthBoolean {
                    fmt.Println("Error: The provided bit string has an incorrect length.")
                }
                if !StructureBoolean {
                    fmt.Println("Error: The provided bit string contains invalid characters (only '0' and '1' are allowed).")
                }
                os.Exit(1)
            }
            
            // Proceed with processing the bit string since validation passed
            BitString := *bitFlag
            DalosEllipse.ProcessKeyGeneration(BitString, smartFlag, *passwordFlag)
        }
        
        if *intaFlag != "" {
            fmt.Println("Generating key pair from string representing an integer in base 10...")
            BitString := DalosEllipse.ProcessIntegerFlag(*intaFlag, true)
            if BitString == "" {
                fmt.Println("Aborting -i10 base-10 key generation.")
                os.Exit(1)
            }
            DalosEllipse.ProcessKeyGeneration(BitString, smartFlag, *passwordFlag)
        }
        if *intbFlag != "" {
            fmt.Println("Generating key pair from string representing an integer in base 49...")
            BitString := DalosEllipse.ProcessIntegerFlag(*intbFlag, false)
            if BitString == "" {
                fmt.Println("Aborting -i49 base-49 key generation.")
                os.Exit(1)
            }
            DalosEllipse.ProcessKeyGeneration(BitString, smartFlag, *passwordFlag)
        }
        
    } else if *convertFlag {
        // Handle the key conversion cases
        if *bitConvFlag != "" {
            fmt.Println("Converting The BitString to Public key and Dalos Accounts...")
            BitString := *bitConvFlag
            DalosEllipse.ProcessPrivateKeyConversion(BitString)
        } else if *intConvFlag != "" {
            fmt.Println("Converting The String Representing an Integer in base 10 to Public key and Dalos Accounts...")
            BitString := DalosEllipse.ProcessIntegerFlag(*intConvFlag, true)
            if BitString == "" {
                fmt.Println("Aborting -int10 base-10 conversion.")
                os.Exit(1)
            }
            DalosEllipse.ProcessPrivateKeyConversion(BitString)
        } else if *strConvFlag != "" {
            fmt.Println("Converting The String Representing an Integer in base 49 to Public key and Dalos Accounts...")
            BitString := DalosEllipse.ProcessIntegerFlag(*strConvFlag, false)
            if BitString == "" {
                fmt.Println("Aborting -int49 base-49 conversion.")
                os.Exit(1)
            }
            DalosEllipse.ProcessPrivateKeyConversion(BitString)
        } else {
            fmt.Println("Error: No valid conversion method selected.")
            flag.Usage()
            os.Exit(1)
        }
    } else if *openFlag != "" {
        // Check if the password flag is also set
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -open Flag.")
            os.Exit(1)
        }
        
        // Call the ImportPrivateKey function
        ReadKeyPair, err := DalosEllipse.ImportPrivateKey(*openFlag, *passwordFlag)
        if err != nil {
            log.Fatalf("Error opening wallet: %v", err)
        }
        
        //Print the Private Key on Screen
        BitString := DalosEllipse.ProcessIntegerFlag(ReadKeyPair.PRIV, false)
        if BitString == "" {
            fmt.Println("Aborting wallet open: private key invalid.")
            os.Exit(1)
        }
        DalosEllipse.ProcessPrivateKeyConversion(BitString)
    } else if *signFlag != "" {
        // Check if the password flag is also set
        if *passwordFlag == "" {
            fmt.Println("Error: -p (password) flag is required when using -sign Flag.")
            os.Exit(1)
        }
        if *messageFlag == "" {
            fmt.Println("Error: -m (message) flag is required when using -sign Flag.")
            os.Exit(1)
        }
        
        // Call the ImportPrivateKey function
        ReadKeyPair, err := DalosEllipse.ImportPrivateKey(*signFlag, *passwordFlag)
        if err != nil {
            log.Fatalf("Error opening wallet: %v", err)
        }
        
        //Print the Signature on screen
        Signature := DalosEllipse.SchnorrSign(ReadKeyPair, *messageFlag)
        fmt.Println("Your Signature is:")
        fmt.Println("")
        fmt.Println(Signature)
        fmt.Println("")
    } else if *verifyFlag != "" {
        // Check if the password flag is also set
        
        if *messageFlag == "" {
            fmt.Println("Error: -m (message) flag is required when using -verify Flag.")
            os.Exit(1)
        }
        if *publicFlag == "" {
            fmt.Println("Error: -public (Public-Key Input) flag is required when using -verify Flag.")
            os.Exit(1)
        }
        
        //Verify the Signature and print Verification on screen
        Verification := DalosEllipse.SchnorrVerify(*verifyFlag, *messageFlag, *publicFlag)
        fmt.Println("")
        fmt.Println("Your Verification is:")
        fmt.Println("")
        fmt.Println(Verification)
        fmt.Println("")
    } else {
        fmt.Println("Error: No valid operation selected.")
        flag.Usage()
        os.Exit(1)
    }
}
