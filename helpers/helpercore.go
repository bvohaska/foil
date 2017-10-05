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
	"errors"
	"flag"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

//BlockSize is an exportable CONSTANT
// The blocksize of AES; used in defining KEY_SIZE
const BlockSize = 16

//MaxFileSize is an exportable CONSTANT
/*
*  MaxFileSize is the maximum number of BYTES that can be encrypted with GCM /before a new IV/nonce
*  must be chosen. After 2^32 blocks, the counter will repeat and could result in leaked plaintext.
*  64GB = 64 * 1024 *1024*1024
 */
const MaxFileSize = 68719476736

//CliParams is an exportable STRUCT
/*
*  CliParams is the basis struct for storing all of the data associated with CLI flags. This struct is
*  used in nearly every function in the main package. Take care in removing any fields  or changing the
*  order within the struct.
 */
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

//CliFlags is an exportable FUNCTION
/*
*  CliFlags parses all command-line flags and input. CliFlags also contains base logic for determining
*  if certain flags are (1) mutually exclusive, (2) must be set, or (3) have another logical relationship.
*  Be EXREMELY careful when editing this function. Changes to the logic here could have unforseen effects
*  as this function is used in EVERY function in the encryptorCore main package.
 */
func CliFlags() (CliParams, bool) {

	var operation *string

	/*
	*  The following block defines all available command-line options. Ther is no default ouput behaviour
	*  and the application will abort if no output direction is given.
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
	} else if (*cliEncrypt == true) && (len(*cliPassword) == 0) && (len(*cliKey) == 0) {
		/*
		*  This logic will allow for a use to encrypt wihtout a key or password. This is the only default
		*  behaviour present in this application. When no key or password is given, a random key will be
		*  generated, used, and printed to StdOut. The key will not be written to file. If this key is lost,
		*  there is no way to recover it.
		 */
		fmt.Println("WARNING - You have not selected: -password or -key; A RANDOM key will be used!")
	}

	// Determine if the user requests an encryption or decryption operation
	if *cliEncrypt {
		temp := "encrypt"
		operation = &temp
	} else if *cliDecrypt {
		temp := "decrypt"
		operation = &temp
	} else {
		fmt.Println("CliFlags - Warning: Unknown error in Encrypt/Decrypt selection")
		return CliParams{}, false
	}

	// SUCCESS
	return CliParams{cliFileSource, cliFileDestination, cliStdIn, cliKey, cliPassword, cliADATA, cliStdOut, cliEncrypt, cliDecrypt, cliVerbose, operation}, true
}

//GetAESRandomBytes is an exportable FUNCTION
/*
*  GetAESRandomBytes receives a slice and returns with 12, 16, or 32 bytes of random. No other lengths
*  will be accepted. This design choice was made to minimize the probability that users would
*  accidentally request keys of inappropriate size. This logic can be easily modified within
*  GetAESRandomBytes but it is not recommended. GetAESRandom bytes receives random from the go package
*  'crypto/rand'; specifically, rand.Read() which reads from os.urandom. See rand.Read() documentation
*  for more information.
 */
func GetAESRandomBytes(randomSlice []byte, verbose bool) error {

	// Check the length of the randomSlice to ebsure it is of length: 16, or 32
	if len(randomSlice) == 0 {
		return errors.New("Error: Requested random bytes is of zero length")
	} else if len(randomSlice) > 32 {
		return errors.New("Error: Requested random bytes too long")
	} else if len(randomSlice)%16 != 0 && len(randomSlice) != 12 {
		return errors.New("Error: Requested random bytes not of length 12, 16, 32")
	}

	// Read 'len(randomSlice)' bytes from os.urandom and store them in *randomSlice
	numRead, err := rand.Read(randomSlice)
	if err != nil {
		return err
	}

	// Print the random bytes to stdIn if verbose is set to TRUE
	if verbose {
		fmt.Printf("GetAESRandomBytes - Random bytes of length %d: %x\n", numRead, randomSlice)
	}

	// SUCCESS
	return nil
}

//KeyFromPassword is an exportable FUNCTION
/*
*  KeyFromPassword receives a password string as given following the -password flag and performs a
*  PBKDF2 key expansion operation. The result is returned by KeyExpand. Note: the size of the PBKDF2
*  digest is set to 32 bytes to align with the 256-bit key size requirement of this application.
 */
func KeyFromPassword(password *string, salt []byte, securityParameter int, verbose bool) []byte {
	/*
	*  Declaring variables here so excentuate the scope of variables used in KeyFromPassword; this was done
	*  instead of using on-the-fly declarations. This design decision was informed by not wanting key related
	*  bits to go 'missing' or otherwise be logically unaccounted for.
	 */
	var (
		passBytes []byte
		KeyExpand []byte
	)

	// Convert the password string into a byte array; Assign the resulting slice to passBytes
	passBytes = []byte(*password)

	/*
	*  This line performs PBKDF2 Key Expansion on the password string associated with passBytes. If  SHA-256 is
	*  exchanged with some other cryptographic hash function, the verbose block will require changing. If
	*  changing the cryptographic hash function ensure the digest output length is 256 bits to align with the
	*  256-bit key size used in AESCore
	 */
	KeyExpand = pbkdf2.Key(passBytes, salt, securityParameter, 32, sha256.New)

	// If verbose mode is activated, print the following to StdOut
	if verbose {
		fmt.Printf("KeyFromPassword - Number of hashes (SHA-256): %d\n", securityParameter)
		fmt.Printf("KeyFromPassword - Salt (hex): %x\n", salt)
		fmt.Printf("SECRET - KeyFromPassword - Password: \"%s\"\n", *password)
		fmt.Printf("SECRET - KeyFromPassword - key (hex): %x\n", KeyExpand)
	}

	return KeyExpand
}

//AESCore is an exportable FUNCTION
/*
*  AESCore is the core AES function in this encryption and decryption tool.
 */
func AESCore(iv []byte, key []byte, adata *string, inputText []byte, operation string, verbose bool) ([]byte, error) {
	/*
	*  Declaring variables here so excentuate the scope of variables used in KeyFromPassword; this was done
	*  instead of using on-the-fly declarations. This design decision was informed by not wanting key related
	*  bits to go 'missing' or otherwise be logically unaccounted for.
	 */
	var (
		decErr     error
		hasAdata   bool
		byteAdata  []byte
		OutputText []byte
	)

	/*
	*  Check to determine if ADATA is present. If ADATA is presenet, then convert the ADATA string into a BYTE
	*  slice as required by Go's AES implementation.
	 */
	if len(byteAdata) > 0 {
		hasAdata = true
		byteAdata = []byte(*adata)
	} else {
		hasAdata = false
	}

	/*
	*  If verbose mode is activated, print the following to StdOut. The print statement containing inputText is
	*  commented out. Be careful when uncommenting as inputText may be large. Uncommenting is only recommended
	*  for debugging purposes when verbose mode is insufficient.
	 */
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

	// Initialize a new instance of Go's AES cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Critial error in AESCore - NewCipher: %v\n", err)
	}
	// Initialize the GCM mode on the AES cipher instance
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("Critial error in AESCore - NewGCM: %v\n", err)
	}

	/*
	*  This block determines whether inputText should be sent to a decryption or encryption operation. If 'decrypt' or
	*  'encrypt' was not given as *operation, an error will be printed to StdOut. Note: For decryption, the first 12
	*  bytes of inputText are taken as the IV/nonce. Note: aesGCM.Seal()/Open() perform operations on []bytes. Note:
	*  When encrypting inputText, AESCore will append the randomly generated IV to the beginning of the output file.
	*  AESCore will use this on decyrption!
	 */
	if operation == "decrypt" {
		OutputText, decErr = aesGCM.Open(nil, iv, inputText[12:], byteAdata)
		if decErr != nil {
			//return nil, fmt.Errorf("AESCore - There was a decryption error: %v\nOutput Text: %x", decErr, outputText)
			return nil, fmt.Errorf("AESCore - There was a decryption error: %v\n", decErr)
		}
	} else if operation == "encrypt" {
		OutputText = aesGCM.Seal(nil, iv, inputText, byteAdata)
		OutputText = append(iv, OutputText...)
	} else {
		return nil, errors.New("AESCore - Invalid cipher operation during Operation Check")
	}

	/*
	* If verbose mode is activated, print the following to StdOut. The print statement containing OutputText is
	*  commented out. Be careful when uncommenting as inputText may be large. Uncommenting is only recommended
	*  for debugging purposes when verbose mode is insufficient.
	 */
	if verbose {
		fmt.Printf("AESCore - %s-ion completed.\n", operation)
		//fmt.Printf("The ouptut text is (hex): %x\n", outputText)
	}

	// SUCCESS: Return the output of the Decryption/Encryption if there were no errors
	if OutputText != nil {
		return OutputText, nil
	}

	/*
	*  FAILURE: If outputText was nil but passed the above tests an unknow error occured. Since Decryption/Encryption
	*  should not fail silently, the default return value is failure represented by the tuple (false, nil)
	 */
	return nil, errors.New("AESCore - WARNING - An unknown error occured. The output text is NIL but no oither errors were detected")
}

//TODO: Fix file IO stream for AESCore
