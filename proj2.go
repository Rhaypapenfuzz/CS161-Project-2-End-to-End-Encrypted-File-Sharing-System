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
	if err != nil{
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
	Username string
	Password string
	Argon2KeyFromPassword []byte
	CurrentSymmetricKey []byte
	NextSymmetricKey []byte
	DSSignKey userlib.DSSignKey

	/*OwnedFilesMap [filename -> metaUUID(PersonalUUID_2_FileInfo), filename2 ->
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
   if err != nil{
   		return nil, err
   }

   //postprocessing to get first 16 bytes symmetric key
   newSymmetricKey := key[:len(key)- 16]

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
	//generate public key
	//rsaPublicKey, rsaPrivateKey, err := func pkeKeyGen()
	//if err != nil {
	//	return userdataptr, err
	//}
	//ciphertext, err = pkeEnc(rsaPublicKey, username)
	
	//Generate UUID from username
   	usernameBytes := []byte(username) //convert username to bytes
	new_UUID, _ := uuid.FromBytes(usernameBytes[:16])	

	//Generate random salt, use this with password to get key using argon2
	passwordBytes := []byte(password) //convert password string to bytes
	randomSalt := userlib.RandomBytes(256) 
	argon2KeyFromPassword := userlib.Argon2Key(passwordBytes, randomSalt, 32) 
	
	//store username and password in struct
	userdataptr.Username = username
	userdataptr.Password = password
	//userdataptr.PasswordSalt = randomSalt
	userdataptr.Argon2KeyFromPassword = argon2KeyFromPassword

	//Marshal user struct
	userMarshalled, err := json.Marshal(userdataptr)

	//generate random iv
	randomIV := userlib.RandomBytes(16) 

	//do symmetric encryption with argon2 key on the user bytes 
	userMarshalledCiphertext := userlib.SymEnc(argon2KeyFromPassword, randomIV, userMarshalled)
	

	//Want to print to terminal
	//userlib.DebugMsg("UUID as string:%v", userMarshalledCiphertext)

	//append 256 bytes salt to user bytes
	userData := append(userMarshalledCiphertext, randomSalt...)
 	userlib.DatastoreSet(new_UUID, userData)

 	//trying to print with DebugMsg
	// k := uuid.New()
	// k[0] = 10
	// userlib.DebugMsg("UUID as string:%v", k.String())

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
	userData, ok := userlib.DatastoreGet(user_UUID)

	//return emptry user and nil if UUID does not exist
	 if ok == false {
	 	return userdataptr, nil
	 }
	//get salt from last 256 bytes of userData
	PasswordSalt := userData[len(userData)-256:]
	passwordBytes := []byte(password) //convert password string to bytes
	
	//get argon2 key from password and salt
	argon2KeyFromPassword := userlib.Argon2Key(passwordBytes, PasswordSalt, 32) 

	//Remove salt from bytes	        
	userData = userData[:len(userData)- 256]

	//decrypt userData bytes from datastore with this argon2key to get user struct
	decryptedUserData := userlib.SymDec(argon2KeyFromPassword, userData)

	//Unmarshal struct
	var userUnMarshalled User
	err = json.Unmarshal(decryptedUserData, &userUnMarshalled)

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
