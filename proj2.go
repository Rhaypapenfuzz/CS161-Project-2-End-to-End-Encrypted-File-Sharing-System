package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

	/*
	 ********************************************
	 **   		 My Own Notes				  **
	 **        		 HKDF  	            	  **
	 ********************************************
	 */
	//deriving a new Symmetric Key from Hash-based key derivation function (HKDF)
	// In use this will be an actual old symmetric key
	OldSymmetricKey := userlib.RandomBytes(16)

	newSymmetricKey, err := HKDF(OldSymmetricKey)
	if err != nil {
		//return nil, err
	}
	userlib.SetDebugStatus(true)
	userlib.DebugMsg("Symmetric Key: %v", newSymmetricKey)
	userlib.SetDebugStatus(false)

}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username              string
	Password              string
	Argon2KeyFromPassword []byte
	CurrentSymmetricKey   []byte
	NextSymmetricKey      []byte
	DSSignKey             userlib.DSSignKey

	/*
		OwnedFilesMap [filename -> metaUUID(PersonalUUID_2_FileInfo), filename2 ->
		metaUUID(PersonalUUID_2_FileInfo)]*/
	//OwnedFiles[filename1,filename2,filename3 ]
	//FileMetaDataKeys[filename:privatekey, filename2,privatekey]
	/*
		ownedFile =
		AccessibleFile =
		files File
		fileAccessInfo FileAccessInfo
	*/
	//UsernameKey int
	//PasswordSalt [] byte
	//PrivateKey int

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type SignedUser struct {
	UserData  []byte
	Signature []byte
}

/*
type FileAccessInfo {
	filename
	UUID_byteslice
}

{
	Filename string
	Filekey PrivateKey
}


type File struct {
	filename string
	filesize size
	filedata byte[]
}
*/
/*
********************************************
**    Hash-based key derivation function  **
**        		 HKDF  	            	  **
********************************************
 */

// Generate 128-bit symmetric key from previous previous 128-bit symmetric key
func HKDF(Previouskey []byte) ([]byte, error) {
	randomBytes := userlib.RandomBytes(256)
	key, err := userlib.HMACEval(Previouskey, randomBytes)
	if err != nil {
		return nil, err
	}

	//postprocessing to get first 16 bytes symmetric key
	newSymmetricKey := key[:len(key)-16]

	return newSymmetricKey, nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//Generate UUID from username
	usernameBytes := []byte(username) //convert username to bytes
	new_UUID, _ := uuid.FromBytes(usernameBytes[:16])

	//Generate random salt, use this with password to get key using argon2
	passwordBytes := []byte(password) //convert password string to bytes
	randomSalt := userlib.RandomBytes(256)

	argon2KeyFromPassword := userlib.Argon2Key(passwordBytes, randomSalt, 32)

	//store username and password in struct
	userdataptr.Username = username

	//generate first symmetric key
	randomSalt2 := userlib.RandomBytes(256)

	privateKeyBytes := userlib.Argon2Key(passwordBytes, randomSalt2, 32)

	//use private key in hdfk to get currentSymmetricKey
	symmetricKey, err := HKDF(privateKeyBytes)
	if err != nil {
		return nil, nil
	}
	//store currentSymmetricKey in struct
	userdataptr.CurrentSymmetricKey = symmetricKey

	//genarate another  key
	randomSalt3 := userlib.RandomBytes(256)

	privateKeyBytes = userlib.Argon2Key(passwordBytes, randomSalt3, 32)
	//use 2nd private key in hdfk to get nextSymmetricKey
	symmetricKey, err = HKDF(privateKeyBytes)
	if err != nil {
		return nil, nil
	}
	//store nextSymmetricKey in struct
	userdataptr.NextSymmetricKey = symmetricKey

	//Generate digital signature key
	dSSignKey, dSVerifyKey, err := userlib.DSKeyGen()

	userdataptr.Password = password
	//userdataptr.PasswordSalt = randomSalt
	userdataptr.Argon2KeyFromPassword = argon2KeyFromPassword

	userdataptr.DSSignKey = dSSignKey

	//Marshal user struct
	userMarshalled, err := json.Marshal(userdataptr)

	//generate random iv
	randomIV := userlib.RandomBytes(16)

	//do symmetric encryption with argon2 key on the user bytes
	userMarshalledCiphertext := userlib.SymEnc(argon2KeyFromPassword, randomIV, userMarshalled)

	//append 256 bytes salt to user bytes
	userData := append(userMarshalledCiphertext, randomSalt...)

	//INTEGRITY STEP
	/*
		Generate dskey
		sign whole user struct with DSSignKey and store this
		store dsverifykey on keystore
		KeyStoreset(usernameDSVerifyKey, DSVerifyKey)
		DatastoreSet(UUID, STRUCT:SALT)
	*/
	signature, err := userlib.DSSign(dSSignKey, userData)
	key := username + "DSVerifyKey"
	userlib.KeystoreSet(key, dSVerifyKey)
	var signedUser SignedUser
	signedUser.UserData = userData
	signedUser.Signature = signature
	//userDataWithSignature := append(userData, signature...)

	signedUserMarshalled, err := json.Marshal(signedUser)

	//upload userData
	//userlib.DatastoreSet(new_UUID, userDataWithSignature)
	userlib.DatastoreSet(new_UUID, signedUserMarshalled)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//Create UUID from username
	usernameBytes := []byte(username) //convert username to bytes
	user_UUID, _ := uuid.FromBytes(usernameBytes[:16])

	//look for username in datastore
	userDataWithSaltandSignature, ok := userlib.DatastoreGet(user_UUID)
	if ok == false { //if the user can't be found.
		return userdataptr, err //return empty user and nil

	}
	//Integrity Step
	//Check if digital signature of received user info
	//is same as userSignature on keystore
	/*
		extract signature bytes
		verifyKey = KeystoreGet(usernameDSVerifyKey)
		obtain userDataWithSalt from info
		err = DSVerify(verifyKey, userDataWithSalt, signature) error.
		if no err, file is valid else return nil User and error
	*/
	var signedUser SignedUser
	err = json.Unmarshal(userDataWithSaltandSignature, &signedUser)

	//signature := userDataWithSaltandSignature[len(userDataWithSaltandSignature)-256:]
	signature := signedUser.Signature
	dSVerifyKey, ok := userlib.KeystoreGet(username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return userdataptr, err
	}
	//userDataWithSalt := userDataWithSaltandSignature[:len(userDataWithSaltandSignature)-256]
	userDataWithSalt := signedUser.UserData
	err = userlib.DSVerify(dSVerifyKey, userDataWithSalt, signature)
	if err != nil { //if the user data was corrupted
		return userdataptr, err //return empty user and nil
	}

	//get salt from last 256 bytes of userData
	PasswordSalt := userDataWithSalt[len(userDataWithSalt)-256:]
	passwordBytes := []byte(password) //convert password string to bytes

	//get argon2 key from password and salt
	argon2KeyFromPassword := userlib.Argon2Key(passwordBytes, PasswordSalt, 32)

	//Remove salt from bytes
	userData := userDataWithSalt[:len(userDataWithSalt)-256]

	//decrypt userData bytes from datastore with this argon2key to get user struct
	decryptedUserData := userlib.SymDec(argon2KeyFromPassword, userData)

	//Unmarshal struct
	var userUnMarshalled User
	err = json.Unmarshal(decryptedUserData, &userUnMarshalled)
	if err != nil { //if unable to marshall
		return userdataptr, err //return empty user and nil
	}

	//Check if password from user struct is equal to password from input
	if userUnMarshalled.Password != password {
		return userdataptr, nil
	}

	userdataptr = &userUnMarshalled

	return userdataptr, nil
}

//not in use right now
func DeepEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//NEED: confidentiality and integrity guarantees
	//different users should be allowed to use the same filename
	//without interfering with each other

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	//In the case that the filedoesn’t exist,
	//or if it appears to have been tampered with,
	//return nil as the data and trigger an error.

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//If the file does not exist, return nil as the data and trigger an error
	//You do not need to check the integrity of the existing file; however,
	//if the file is badly broken, return nil as the data and trigger an error.
	//Do not forget to update the user structure if you change it.
	//Note: if the file has a size of 1000TB, and you just want to add
	//one byte, you should not need to download or decrypt the whole file

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
