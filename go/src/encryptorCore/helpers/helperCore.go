/*
*  Welcome to the AES cli encryption/decryption helper core. The functions contained herein
*  are the true heart of the AES cli encryption/decryption tool. NOTE: AES Core only accepts
*  12 BYTE IVs (nonces) and appends the IV/nonce to the beginning of the ouput file when
*  encryption is chosen as the desired operation. If using command-line provided string for
*  decryption, the 12 BYTE IV/nonce must be the first 12 BYTES of the string AND the string
*  must be hex.
*
*		- Brian Vohaska
 */

package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

//BlockSize is an exported constant.
//The blocksize of AES; used in defining KEY_SIZE
const BlockSize = 16

//MaxFileSize is an exported constant.
/*
*  MaxFileSize is the maximum number of BYTES that can be encrypted with GCM /before a new IV/nonce
*  must be chosen. After 2^32 blocks, the counter will repeat and could result in leaked plaintext.
*  64GB = 64 * 1024 *1024*1024
 */
const MaxFileSize = 68719476736

//CliParams is an exported STRUCT
type CliParams struct {
	CliFileSource      *string
	CliFileDestination *string
	CliStdIn           *string
	CliKey             *string
	CliPassword        *string
	CliADATA           *string
	CliStdOut          *bool
	CliEncrypt         *bool
	CliDecrypt         *bool
	CliVerbose         *bool
	Operation          *string
}

// CliFlags shoiuld be exported to another package
func CliFlags() (CliParams, bool) {

	var operation *string

	/*
	*  The following defines flags for all options present in this crypto tool
	*  Default ouput behaviour saves output to a file 'cliToolOutput' in the current folder
	 */

	cliFileSource := flag.String("source", "", "Set the location of the input file")
	cliFileDestination := flag.String("target", "", "Set the target location of the output file")
	cliStdIn := flag.String("textin", "", "Use the string \"[STRING]\" following -txtin as the source file")
	cliKey := flag.String("key", "", "Instruct the applicatiion to use a user provided key (hex only)")
	cliPassword := flag.String("password", "", "Instruct the application to use the ASCII password following -password")
	cliADATA := flag.String("adata", "", "Provide ASCII additional authenticated data following -adata")
	cliStdOut := flag.Bool("textout", false, "Print output to stdin")
	cliEncrypt := flag.Bool("encrypt", false, "Instruct the application to perform encryption")
	cliDecrypt := flag.Bool("decrypt", false, "Instruct the applicatiion to perform decryption")
	cliVerbose := flag.Bool("verbose", false, "Verbose Mode - reveals most of the internal variable state")

	flag.Parse()

	// Check to ensure mutually exclusive flags are not set
	if *cliEncrypt && *cliDecrypt {
		fmt.Println("You can select only one: -encrypt or -decrypt")
		return CliParams{}, false
	} else if *cliStdOut && len(*cliFileDestination) > 0 {
		fmt.Println("You can select only one: -textout or -target")
		return CliParams{}, false
	} else if len(*cliFileSource) > 0 && len(*cliStdIn) > 0 {
		fmt.Println("You can select only one: -textin or -source")
		return CliParams{}, false
	} else if len(*cliPassword) > 0 && len(*cliKey) > 0 {
		fmt.Println("You can select only one: -password or -key")
		return CliParams{}, false
	}

	// Check to ensure the minimum set of flags are set
	if (*cliEncrypt == false) && (*cliDecrypt == false) {
		fmt.Println("You must select one: -encrypt or -decrypt")
		return CliParams{}, false
	} else if (*cliStdOut == false) && (len(*cliFileDestination) == 0) {
		fmt.Println("You must select one: -textout or -target")
		return CliParams{}, false
	} else if (len(*cliFileSource) == 0) && (len(*cliStdIn) == 0) {
		fmt.Println("You must select one: -textin or -source")
		return CliParams{}, false
	} else if (len(*cliPassword) == 0) && (len(*cliKey) == 0) {
		fmt.Println("WARNING - You have not selected: -password or -key; A RANDOM key will be used!")
	}

	// Determine the d/encryption operation
	if *cliEncrypt {
		temp := "encrypt"
		operation = &temp
	} else if *cliDecrypt {
		temp := "decrypt"
		operation = &temp
	} else {
		fmt.Println("CliFlags - Warning: Unknown error in Encrypt/Decrypt selection")
	}

	return CliParams{cliFileSource, cliFileDestination, cliStdIn, cliKey, cliPassword, cliADATA, cliStdOut, cliEncrypt, cliDecrypt, cliVerbose, operation}, true
}

// GetAESRandomBytes shoiuld be exported to another package
func GetAESRandomBytes(randomSlice []byte, verbose bool) bool {
	// Check the length of the randomSlice to make sure it is 16, or 32 Bytes
	if len(randomSlice) == 0 {
		fmt.Println("Error: Requested random bytes is of zero length")
		return false
	} else if len(randomSlice) > 32 {
		fmt.Println("Error: Requested random bytes too long")
		return false
	} else if len(randomSlice)%16 != 0 && len(randomSlice) != 12 {
		fmt.Println("Error: Requested random bytes not of length 12, 16, 32")
		return false
	}

	// rand.Read will read len(randomSlice) bytes
	numRead, err := rand.Read(randomSlice)
	if err != nil {
		fmt.Println("error:", err)
		return false
	}

	// Print the random bytes to stdIn if verbose is set to TRUE
	if verbose {
		fmt.Printf("GetAESRandomBytes - Random bytes of length %d: %x\n", numRead, randomSlice)
	}
	return true
}

// TestGetAESRandomBytes should be exported to another package
//func TestGetAESRandomBytes () {}

// KeyFromPassword should be exported to another package
func KeyFromPassword(password *string, salt []byte, securityParameter int, verbose bool) []byte {
	/*
	*  Declaring variables here so excentuate the scope of variables used
	*   in KeyFromPassword; done instead of on-the-fly declarations
	 */
	var (
		passBytes []byte
		KeyExpand []byte
	)

	// Convert the password string into a byte array; Assign the resulting slice to passBytes
	passBytes = []byte(*password)

	/*
	*  Perform PBKDF2 Key Expansion on the password bytes associated with passBytes. If
	*  SHA-256 is exchanged with another cryptographic hash function change the reference
	*  in the verbose output.
	 */
	KeyExpand = pbkdf2.Key(passBytes, salt, securityParameter, 32, sha256.New)

	if verbose {
		fmt.Printf("KeyFromPassword - Number of hashes (SHA-256): %d\n", securityParameter)
		fmt.Printf("KeyFromPassword - Salt (hex): %x\n", salt)
		fmt.Printf("SECRET - KeyFromPassword - Password: \"%s\"\n", *password)
		fmt.Printf("SECRET - KeyFromPassword - key (hex): %x\n", KeyExpand)
	}

	return KeyExpand
}

// TestKeyFromPassword should be exported to another package
//func TestKeyFromPassword () {}

//AESCore should be exported to another package
func AESCore(iv []byte, key []byte, adata *string, inputText []byte, operation string, verbose bool) ([]byte, bool) {
	/*
	*  Declaring variables here so excentuate the scope of variables used
	*  in AESCore; done instead of on-the-fly declarations
	 */
	var (
		decErr     error
		hasAdata   bool
		byteAdata  []byte
		OutputText []byte
		//aesBlock NewCipher
		//aesGCM NewGCM
	)

	/*
	*  Check to determine if there is ADATA to be processed. If there is
	*  convert the ADATA string into a BYTE slice as required by Go's AES
	*  implementation.
	 */
	if len(byteAdata) > 0 {
		hasAdata = true
		byteAdata = []byte(*adata)
	} else {
		hasAdata = false
	}

	if verbose {
		fmt.Printf("AESCore - Does ADATA exist: %t\n", hasAdata)
		if byteAdata == nil {
			fmt.Println("AESCore - byteAdata was nil")
		} else {
			fmt.Printf("AESCore - byteAdata contained the following ADATA: %s", byteAdata)
		}
		fmt.Printf("AESCore - The iv/nonce used was (hex): %x\n", iv)
		fmt.Printf("SECRET - AESCore - The key used was (hex): %x\n", key)
		//fmt.Printf("AESCore - Input Text: %x\n", inputText)
	}

	// Initialize a new Go AES cipher object
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Critial error in AESCore - NewCipher:", err)
		return nil, false
	}
	// Set the AES cipher object mode to GCM
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println("Critial error in AESCore - NewGCM:", err)
		return nil, false
	}

	/*
	*  Begin Decryption/Encryption operations
	*  If Decryption/Encryption were not given as *operation, print an error
	 */
	if operation == "decrypt" {
		OutputText, decErr = aesGCM.Open(nil, iv, inputText[12:], byteAdata)
	} else if operation == "encrypt" {
		OutputText = aesGCM.Seal(nil, iv, inputText, byteAdata)
		//WARNING: AESCore appends the IV to the beginning of the output file. AESCore will use this on decyrption!
		OutputText = append(iv, OutputText...)
	} else {
		fmt.Println("AESCore - Invalid cipher operation during Operation Check")
		return nil, false
	}

	// Error checking to ensure there were now decryption errors
	if decErr != nil {
		fmt.Println("AESCore - There was a decryption error -", decErr)
		//fmt.Printf("AESCore - Output Text: %x\n", outputText)
		return nil, false
	}

	if verbose {
		fmt.Printf("AESCore - %s-ion completed.\n", operation)
		//fmt.Printf("The ouptut text is (hex): %x\n", outputText)
	}

	// SUCCESS: Return the output of the Decryption/Encryption if there were no errors
	if OutputText != nil {
		return OutputText, true
	}

	/*
	*  FAILURE: If outputText was nil but passed the above tests an unknow error
	*  occired. Since Decryption/Encryption should not fail silently, the default return
	*  value is failure represented by the tuple (false, nil)
	 */
	fmt.Printf("AESCore - WARNING - An unknown error occured. The output text is NIL but no oither errors were detected")
	return nil, false
}

//TestAESCore should be exported to another paclage
/*func TestAESCore () {
	// AES Test vectors: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
	key := 53382df51d7d4d17964e178d9ccb2dea7ae8e2238c3a91a392d53fba523f48c4
	iv := ede60d67a345d2be699d3b24
	pt := 7e14b6a5b616ce97e02f9377002786a5
	ct: = 5c4ba32d35959c7e9e94a1f9c0a5c2e0
	//adata := nil
}
*/
