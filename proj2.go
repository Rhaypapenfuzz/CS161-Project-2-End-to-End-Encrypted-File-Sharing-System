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
	newUUID, _ := uuid.FromBytes(usernameBytes[:16])

	//Generate random salt, use this with password to get key using argon2
	passwordBytes := []byte(password) //convert password string to bytes
	randomSalt := userlib.RandomBytes(256)

	argon2KeyFromPassword := userlib.Argon2Key(passwordBytes, randomSalt, 32)

	//store username and UserSalt in struct
	userdataptr.Username = username
	userdataptr.UserSalt = randomSalt

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

	privateKeyBytes2 := userlib.Argon2Key(passwordBytes, randomSalt3, 32)

	//use 2nd private key in hdfk to get nextSymmetricKey
	symmetricKey2, err := HKDF(privateKeyBytes2)
	if err != nil {
		return nil, nil
	}
	//store nextSymmetricKey in struct
	userdataptr.NextSymmetricKey = symmetricKey2

	//Generate digital signature key
	dSSignKey, dSVerifyKey, err := userlib.DSKeyGen()

	userdataptr.Password = password
	userdataptr.Argon2KeyFromPassword = argon2KeyFromPassword
	//userdataptr.PasswordSalt = randomSalt

	userdataptr.DSSignKey = dSSignKey

	//Generate User's Publics and Private Key
	pkeEncKey, pkeDecKey, err := userlib.PKEKeyGen()
	//Store Public key in keystore
	keyStr := username + "PublicKey"
	userlib.KeystoreSet(keyStr, pkeEncKey)
	//Store private key is user struct
	userdataptr.PrivateKey = pkeDecKey

	userdataptr.OwnedFiles = make(map[string]uuid.UUID)
	userdataptr.FileMetaDataKeys = make(map[string][]byte)

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
	var signedUser DSSignedData
	signedUser.Data = userData
	signedUser.Signature = signature
	//userDataWithSignature := append(userData, signature...)

	signedUserMarshalled, err := json.Marshal(signedUser)

	//upload userData
	//userlib.DatastoreSet(newUUID, userDataWithSignature)
	userlib.DatastoreSet(newUUID, signedUserMarshalled)

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
	userUUID, _ := uuid.FromBytes(usernameBytes[:16])

	//look for username in datastore
	userDataWithSaltandSignature, ok := userlib.DatastoreGet(userUUID)
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
	var signedUser DSSignedData
	err = json.Unmarshal(userDataWithSaltandSignature, &signedUser)
	if err != nil { //if key doesn't exist in keystore
		return userdataptr, err
	}

	dSVerifyKey, ok := userlib.KeystoreGet(username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return userdataptr, err
	}
	//signature := userDataWithSaltandSignature[len(userDataWithSaltandSignature)-256:]
	signature := signedUser.Signature
	//userDataWithSalt := userDataWithSaltandSignature[:len(userDataWithSaltandSignature)-256]
	userDataWithSalt := signedUser.Data
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

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//NEED: confidentiality and integrity guarantees
	//different users should be allowed to use the same filename
	//without interfering with each other
	// create FileMetaData object
	var fileMetaData FileMetaData

	// FileMetaData.FileUUID = generate random uuid for file and appendByte
	fileUUID := uuid.New()
	//fileMetaData.FileUUIDArray = append(fileMetaData.FileUUIDArray, fileUUID)

	/******
	appendByteUUID := uuid.New()
	fileMetaData.AppendByteUUID = appendByteUUID
	******/
	// FileMetaData.FileSymmetricKey = FileSymmetricKey
	//Generate new next Symmetric key with HKDF
	fileMetaData.FileSymmetricKey = userdata.CurrentSymmetricKey
	userdata.CurrentSymmetricKey = userdata.NextSymmetricKey
	userdata.NextSymmetricKey, _ = HKDF(fileMetaData.FileSymmetricKey)

	// Steps for the dataStore shared FileUUIDArray
	fileUUIDArrayUUID := uuid.New()
	//fileUUIDArray := fileMetaData.FileUUIDArray
	var fileUUIDArray []uuid.UUID
	fileUUIDArray = append(fileUUIDArray, fileUUID)

	fileUUIDArrayMarshalled, _ := json.Marshal(fileUUIDArray)

	randomIV := userlib.RandomBytes(16)
	encryptedFileUUIDArrayMarshalled := userlib.SymEnc(fileMetaData.FileSymmetricKey, randomIV, fileUUIDArrayMarshalled)

	dSSignKey := userdata.DSSignKey
	dSFileVerifyKey, _ := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")

	fileKeyStr := fileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"

	userlib.KeystoreSet(fileKeyStr, dSFileVerifyKey)

	encryptedFileUUIDArraySignature, _ := userlib.DSSign(dSSignKey, encryptedFileUUIDArrayMarshalled)
	var signedEncryptedFileUUIDArrayMarshalled DSSignedData
	signedEncryptedFileUUIDArrayMarshalled.Data = encryptedFileUUIDArrayMarshalled
	signedEncryptedFileUUIDArrayMarshalled.Signature = encryptedFileUUIDArraySignature

	signedEncryptedFileUUIDArrayMarshalledMarshalled, _ := json.Marshal(signedEncryptedFileUUIDArrayMarshalled)

	userlib.DatastoreSet(fileUUIDArrayUUID, signedEncryptedFileUUIDArrayMarshalledMarshalled)

	// AppendBit = data’s last byte
	/******
	//appendByte := data[len(data)-1:]
	// data = data except last bit
	//fileData := data[:len(data)-1]
	*****/
	fileData := data

	// encryptData = encrypt data with FileMetaData.FileSymmetricKey
	randomIV = userlib.RandomBytes(16)
	encryptedFileData := userlib.SymEnc(fileMetaData.FileSymmetricKey, randomIV, fileData)

	//encryptAppendByte = encrypt AppendByte with FileMetaData.FileSymmetricKey
	/******
	randomIV = userlib.RandomBytes(16)
	encryptedAppendByte := userlib.SymEnc(fileMetaData.FileSymmetricKey, randomIV, appendByte)
	***********/

	//INTEGRITY STEP
	// generate digital key pair or get user's digital key
	//dSSignKey, dSVerifyKey, err := userlib.DSKeyGen()
	//userlib.KeystoreGet(userdata.Username + filename + "DSVerifyKey"):alternate
	//In fileVerificationKeys store Filename:DSVerifyKey :alternate
	dSSignKey = userdata.DSSignKey
	dSFileVerifyKey, _ = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")

	fileKeyStr = fileUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	/******
	appendKeyStr := appendByteUUID.String()
	appendKeyStr = appendKeyStr + "DSVerifyKey"
	******/
	userlib.KeystoreSet(fileKeyStr, dSFileVerifyKey)
	/*****
	userlib.KeystoreSet(appendKeyStr, dSFileVerifyKey)
	******/
	//encryptedfileDataSignature = sign encryptedfileData with private digital signature key
	encryptedFileDataSignature, _ := userlib.DSSign(dSSignKey, encryptedFileData)
	var signedFileData DSSignedData
	signedFileData.Data = encryptedFileData
	signedFileData.Signature = encryptedFileDataSignature
	/*****
	//encryptedAppendByteSignature = sign encryptedAppendByte with private digital signature key
	encryptedAppendByteSignature, _ := userlib.DSSign(dSSignKey, encryptedAppendByte)
	var signedAppendByte DSSignedData
	signedAppendByte.Data = encryptedAppendByte
	signedAppendByte.Signature = encryptedAppendByteSignature
	******/
	signedFileDataMarshalled, _ := json.Marshal(signedFileData)
	/******
	signedAppendByteMarshalled, _ := json.Marshal(signedAppendByte)
	******/

	userlib.DatastoreSet(fileUUID, signedFileDataMarshalled)
	/******
	userlib.DatastoreSet(appendByteUUID, signedAppendByteMarshalled)
	*****/

	/*
	 ********************************************
	 **   		 							   **
	 **        		 METADATA  	               **
	 ********************************************
	 */
	/*
		//Generate Public and Private Key for file
		pkeEncKey, pkeDecKey, _ := userlib.PKEKeyGen()
		//Store FileMetaData Public key in keystore
		keyStr := userdata.Username + filename + "MetaDataPublicKey"
		userlib.KeystoreSet(keyStr, pkeEncKey)
		//Store FileMetaData private key is user struct// will store symmetric key for user share with
		userdata.FileMetaDataKeys = make(map[string]userlib.PKEDecKey)
		userdata.FileMetaDataKeys[filename] = pkeDecKey

		// FileMetaData.OwnersUsername = username
		fileMetaData.OwnersUsername = userdata.Username

		// encryptFileMetaData with file public key
		//if using the same public key then userPublicKey, _ := userlib.KeystoreGet(userdata.Username + "PublicKey")
		fileMetaDataMarshalled, _ := json.Marshal(fileMetaData)
		encryptedFileMetaData, _ := userlib.PKEEnc(pkeEncKey, fileMetaDataMarshalled)
	*/
	//Generate new symmetric Key for file
	symmetricKey := userdata.CurrentSymmetricKey
	userdata.CurrentSymmetricKey = userdata.NextSymmetricKey
	userdata.NextSymmetricKey, _ = HKDF(symmetricKey)

	//Store FileMetaData Symmetric Key  is user struct
	//userdata.FileMetaDataKeys = make(map[string][]byte)
	userdata.FileMetaDataKeys[filename] = symmetricKey

	fileMetaData.FileUUIDArrayUUID = fileUUIDArrayUUID
	fileMetaData.SharedMetaDataSymmetricKeysMap = make(map[string][]byte) //users shared with and their metadata Symmetric Keys
	fileMetaData.SharedMetaDataUUIDsMap = make(map[string]uuid.UUID)

	// FileMetaData.OwnersUsername = username
	fileMetaData.OwnersUsername = userdata.Username
	// encryptFileMetaData with file public key
	fileMetaDataMarshalled, _ := json.Marshal(fileMetaData)
	//generate random iv
	randomIV = userlib.RandomBytes(16)
	//do symmetric encryption with argon2 key on the fileMetaData
	encryptedFileMetaData := userlib.SymEnc(symmetricKey, randomIV, fileMetaDataMarshalled)

	// mix filename with username to get metaUUID
	metaUUIDString := filename + userdata.Username
	metaUUIDBytes := []byte(metaUUIDString) //convert username to bytes
	metaUUID, _ := uuid.FromBytes(metaUUIDBytes[:16])

	// In OwnedFilesMap, create filename maps -> metaUUID
	//userdata.OwnedFiles = make(map[string]uuid.UUID)
	userdata.OwnedFiles[filename] = metaUUID

	//METADATA INTEGRITY STEP

	//encryptedMetaDataSignature = sign encryptFileMetaData with private digital signature key
	encryptedFileMetaDataSignature, _ := userlib.DSSign(dSSignKey, encryptedFileMetaData)
	var signedEncryptedFileMetaData DSSignedData
	signedEncryptedFileMetaData.Data = encryptedFileMetaData
	signedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
	signedEncryptedFileMetaDataMarshalled, _ := json.Marshal(signedEncryptedFileMetaData)
	userlib.DatastoreSet(metaUUID, signedEncryptedFileMetaDataMarshalled)

	dSMetaDataVerifyKey, _ := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(metaDataKeyStr, dSMetaDataVerifyKey)

	//if generating new digital for each file then follow this step
	// KeyStoreSet(usernameFilenameDSVerifyKey: FileDSVerifyKey)

	////////////
	//get user salt and argon2Key
	userSalt := userdata.UserSalt
	argon2KeyFromPassword := userdata.Argon2KeyFromPassword

	//Form UUID from username
	usernameBytes := []byte(userdata.Username) //convert username to bytes
	userUUID, _ := uuid.FromBytes(usernameBytes[:16])

	//Marshal user struct
	userMarshalled, _ := json.Marshal(userdata)

	//generate random iv
	randomIV = userlib.RandomBytes(16)

	//do symmetric encryption with argon2 key on the user bytes
	userMarshalledCiphertext := userlib.SymEnc(argon2KeyFromPassword, randomIV, userMarshalled)

	//append 256 bytes salt to user bytes
	userData := append(userMarshalledCiphertext, userSalt...)

	//INTEGRITY STEP
	/*
		sign whole user struct with DSSignKey and store this
		KeyStoreset(usernameDSVerifyKey, DSVerifyKey)
		DatastoreSet(UUID, STRUCT:SALT)
	*/
	signature, _ := userlib.DSSign(dSSignKey, userData)

	var signedUser DSSignedData
	signedUser.Data = userData
	signedUser.Signature = signature

	signedUserMarshalled, _ := json.Marshal(signedUser)

	//upload userData
	userlib.DatastoreSet(userUUID, signedUserMarshalled)

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	//In the case that the filedoesn’t exist,
	//or if it appears to have been tampered with,
	//return nil as the data and trigger an error.
	//dSKeyStr := userdata.Username + "DSVerifyKey"
	//dSVerifyKey, _ := userlib.KeystoreGet(dSKeyStr)

	////use filename and look in users OwnedFilesMap to get metaUUID
	//userdata.OwnedFiles = make(map[string]uuid.UUID)
	metaUUID, found := userdata.OwnedFiles[filename]
	if found == false { //	if filename doesn’t exist abort
		return nil, errors.New("Can't be found")
	}
	//Marshalled(encryptedFileMetaData+signature) = DatastoreGet(metaUUID)
	signedEncryptedFileMetaDataMarshalled, ok := userlib.DatastoreGet(metaUUID)
	if ok == false { //if the file can't be found.
		return nil, errors.New("No data found") //return empty data and nil
	}

	//UnMarshal signedEncryptedFileMetaDataMarshalled
	var signedEncryptedFileMetaData DSSignedData
	err = json.Unmarshal(signedEncryptedFileMetaDataMarshalled, &signedEncryptedFileMetaData)
	if err != nil { //if unable to marshall
		return nil, err //return empty user and nil
	}
	//get signature from encryptedFileMetaData+signature
	signature := signedEncryptedFileMetaData.Signature
	//get encryptedFileMetaData
	encryptedFileMetaData := signedEncryptedFileMetaData.Data
	//check if fileMetadata is authentic and for integrit
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	dSVerifyKey, ok := userlib.KeystoreGet(metaDataKeyStr)
	if ok == false { //if key doesn't exist in keystore
		return nil, errors.New("Can't find valid dsVerify Key ") //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileMetaData, signature)
	if err != nil { //if the user data was corrupted
		return nil, err //return empty nil and err
	}

	//decrypt encryptedFileMetaData with our private key for this file
	//decryptedFileMetaData, _ := userlib.PKEDec(userdata.PrivateKey, encryptedFileMetaData)

	//decrypt encryptedFileMetaData with our symmetric key for this file
	symmetricKey, found := userdata.FileMetaDataKeys[filename]
	if found == false { //	if filename doesn’t exist abort
		return nil, errors.New("No SymmetricKey found to decrypt this Metadata")
	}
	decryptedFileMetaDataMarshalled := userlib.SymDec(symmetricKey, encryptedFileMetaData)

	//unmarshal file meta data
	var decryptedFileMetaData FileMetaData
	err = json.Unmarshal(decryptedFileMetaDataMarshalled, &decryptedFileMetaData)
	if err != nil { //if unable to marshall
		return nil, err //return empty user and nil
	}

	// encryptData = encrypt newFileData with FileMetaData.FileSymmetricKey
	//randomIV := userlib.RandomBytes(16)
	//encryptedFileData := userlib.SymEnc(symmetricKey, randomIV, data)

	////////
	//decrypt online FileUUIDArray and update user's FileUUIDArray
	fileUUIDArrayUUID := decryptedFileMetaData.FileUUIDArrayUUID
	signedEncryptedFileUUIDArrayMarshalledMarshalled, ok := userlib.DatastoreGet(fileUUIDArrayUUID)
	if ok == false { //if the fileUUIDArray can't be found.
		return nil, errors.New("No data found") //return empty data and nil

	}
	//UnMarshal signedFileDataMarshalled
	var signedEncryptedFileUUIDArrayMarshalled DSSignedData
	err = json.Unmarshal(signedEncryptedFileUUIDArrayMarshalledMarshalled, &signedEncryptedFileUUIDArrayMarshalled)
	if err != nil { //if unable to marshall
		return nil, err //return nil and error
	}
	//get signature
	signature = signedEncryptedFileUUIDArrayMarshalled.Signature
	encryptedFileUUIDArrayMarshalled := signedEncryptedFileUUIDArrayMarshalled.Data

	//verify Data
	fileKeyStr := fileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	dSVerifyKey, ok = userlib.KeystoreGet(fileKeyStr)
	if ok == false { //if the key can't be found.
		return nil, err //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileUUIDArrayMarshalled, signature)
	if err != nil { //if the user data was corrupted
		return nil, err //return empty nil and err
	}
	//	decrypt FileUUIDArray with decryptedFileMetaData.FileSymmetricKey
	decryptedFileUUIDArrayMarshalled := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, encryptedFileUUIDArrayMarshalled)

	var decryptedFileUUIDArray []uuid.UUID                                          //Fix me ########**********************
	err = json.Unmarshal(decryptedFileUUIDArrayMarshalled, &decryptedFileUUIDArray) //FIX ME
	if err != nil {                                                                 //if unable to marshall
		return nil, err //return nil and error
	}
	//decryptedFileMetaData.FileUUIDArray = decryptedFileUUIDArray

	//////////////

	var totalFile []byte
	for uuidIndex := range decryptedFileUUIDArray { //get uuid.UUID
		fileUUID := decryptedFileUUIDArray[uuidIndex]
		//retrieve info from Datastore
		signedFileDataMarshalled, ok := userlib.DatastoreGet(fileUUID)
		if ok == false { //if the file can't be found.
			return nil, errors.New("No data found") //return empty data and nil
		}
		//UnMarshal signedFileDataMarshalled
		var signedFileData DSSignedData
		err = json.Unmarshal(signedFileDataMarshalled, &signedFileData)
		if err != nil { //if unable to marshall
			return nil, err //return nil and error
		}
		//get signature
		signature = signedFileData.Signature
		fileData := signedFileData.Data
		//verify Data
		fileKeyStr := fileUUID.String()
		fileKeyStr = fileKeyStr + "DSVerifyKey"
		dSVerifyKey, ok := userlib.KeystoreGet(fileKeyStr)
		if ok == false { //if the key can't be found.
			return nil, errors.New("No valid dsVerify key found") //return empty data and nil
		}
		err = userlib.DSVerify(dSVerifyKey, fileData, signature)
		if err != nil { //if the user data was corrupted
			return nil, err //return empty nil and err
		}

		//	decrypt fileData with decryptedFileMetaData.FileSymmetricKey
		decryptedUserData := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, fileData)
		totalFile = append(totalFile, decryptedUserData...)
		totalFile = []byte(totalFile)
		/*
			unmarshal file data
			WholeFile = unmarshal file data
		*/

	}
	/******
	//do same for decryptedFileMetaData.AppendByteUUID
	appendByteUUID := decryptedFileMetaData.AppendByteUUID
	//retrieve info from Datastore
	signedFileDataMarshalled, ok := userlib.DatastoreGet(appendByteUUID)
	if ok == false { //if the file can't be found.
		return nil, err //return empty data and nil
	}
	//UnMarshal signedFileDataMarshalled
	var signedFileData DSSignedData
	err = json.Unmarshal(signedFileDataMarshalled, &signedFileData)
	if err != nil { //if unable to marshall
		return nil, err //return nil and error
	}
	//get signature
	signature = signedFileData.Signature
	fileData := signedFileData.Data
	//verify Data
	fileKeyStr := appendByteUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	dSVerifyKey, ok = userlib.KeystoreGet(fileKeyStr)
	if ok == false { //if the key can't be found.
		return nil, err //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, fileData, signature)
	if err != nil { //if the user data was corrupted
		return nil, err //return empty nil and err
	}
	//	decrypt fileData with decryptedFileMetaData.FileSymmetricKey
	decryptedUserData := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, fileData)
	totalFile = append(totalFile, decryptedUserData...)
	*****/
	return totalFile, nil
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

	//look in owned files for file metaUUID using filename
	metaUUID, found := userdata.OwnedFiles[filename]
	if found == false { //	if metaUUID doesn’t exist abort
		return errors.New("No file found")
	}
	//get for encryptedFileMetaData in datastore
	encryptedFileMetaData, ok := userlib.DatastoreGet(metaUUID)
	if ok == false { //if the data can't be found.
		return errors.New("No data found at this UUID") //return err
	}
	//CHECK INTEGRITY
	//UnMarshal signedEncryptedFileMetaDataMarshalled
	var signedEncryptedFileMetaData DSSignedData
	err = json.Unmarshal(encryptedFileMetaData, &signedEncryptedFileMetaData)
	if err != nil { //if unable to marshall
		return err //return error
	}
	//get signature from encryptedFileMetaData+signature
	signature := signedEncryptedFileMetaData.Signature
	//get encryptedFileMetaData
	encryptedFileMetaData = signedEncryptedFileMetaData.Data
	//check if fileMetadata is authentic and for integrity
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	dSVerifyKey, ok := userlib.KeystoreGet(metaDataKeyStr)
	if ok == false { //if key doesn't exist in keystore
		return err //return error
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileMetaData, signature)
	if err != nil { //if the user data was corrupted
		return err //return error
	}
	//get symmetric key and decrypt encryptedFileMetaData for this file
	symmetricKey, found := userdata.FileMetaDataKeys[filename]
	if found == false { //	if filename doesn’t exist abort
		return err
	}
	decryptedFileMetaDataMarshalled := userlib.SymDec(symmetricKey, encryptedFileMetaData)

	//unmarshal and get File MetaData
	var decryptedFileMetaData FileMetaData
	err = json.Unmarshal(decryptedFileMetaDataMarshalled, &decryptedFileMetaData)
	if err != nil { //if unable to marshall
		return err //return empty user and nil
	}

	/////////
	//decrypt online FileUUIDArray and update user's FileUUIDArray
	fileUUIDArrayUUID := decryptedFileMetaData.FileUUIDArrayUUID
	signedEncryptedFileUUIDArrayMarshalledMarshalled, ok := userlib.DatastoreGet(fileUUIDArrayUUID)
	if ok == false { //if the fileUUIDArray can't be found.
		return err //return empty data and nil

	}
	//UnMarshal signedFileDataMarshalled
	var signedEncryptedFileUUIDArrayMarshalled DSSignedData
	err = json.Unmarshal(signedEncryptedFileUUIDArrayMarshalledMarshalled, &signedEncryptedFileUUIDArrayMarshalled)
	if err != nil { //if unable to marshall
		return err //return nil and error
	}
	//get signature
	signature = signedEncryptedFileUUIDArrayMarshalled.Signature
	encryptedFileUUIDArrayMarshalled := signedEncryptedFileUUIDArrayMarshalled.Data

	//verify Data
	fileKeyStr := fileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	dSVerifyKey, ok = userlib.KeystoreGet(fileKeyStr)
	if ok == false { //if the key can't be found.
		return err //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileUUIDArrayMarshalled, signature)
	if err != nil { //if the user data was corrupted
		return err //return empty nil and err
	}
	//	decrypt FileUUIDArray with decryptedFileMetaData.FileSymmetricKey
	decryptedFileUUIDArrayMarshalled := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, encryptedFileUUIDArrayMarshalled)

	var decryptedFileUUIDArray []uuid.UUID
	err = json.Unmarshal(decryptedFileUUIDArrayMarshalled, &decryptedFileUUIDArray)
	if err != nil { //if unable to marshall
		return err //return nil and error
	}

	//generate random new FileDataUUID and append UUID to FileUUIDArray
	newFileDataUUID := uuid.New()
	decryptedFileUUIDArray = append(decryptedFileUUIDArray, newFileDataUUID)

	//decryptedFileMetaData.FileUUIDArray = decryptedFileUUIDArray

	// encryptData = encrypt newFileData with FileMetaData.FileSymmetricKey
	randomIV := userlib.RandomBytes(16)
	encryptedFileData := userlib.SymEnc(decryptedFileMetaData.FileSymmetricKey, randomIV, data)

	////////

	// Step to update online shared FileUUIDArray in dataStore
	fileUUIDArrayMarshalled, _ := json.Marshal(decryptedFileUUIDArray)

	randomIV = userlib.RandomBytes(16)
	encryptedFileUUIDArrayMarshalled = userlib.SymEnc(decryptedFileMetaData.FileSymmetricKey, randomIV, fileUUIDArrayMarshalled)

	dSSignKey := userdata.DSSignKey
	dSFileVerifyKey, _ := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")

	fileKeyStr = decryptedFileMetaData.FileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"

	userlib.KeystoreSet(fileKeyStr, dSFileVerifyKey)

	encryptedFileUUIDArraySignature, _ := userlib.DSSign(dSSignKey, encryptedFileUUIDArrayMarshalled)
	var newSignedEncryptedFileUUIDArrayMarshalled DSSignedData
	newSignedEncryptedFileUUIDArrayMarshalled.Data = encryptedFileUUIDArrayMarshalled
	newSignedEncryptedFileUUIDArrayMarshalled.Signature = encryptedFileUUIDArraySignature

	signedEncryptedFileUUIDArrayMarshalledMarshalled, _ = json.Marshal(newSignedEncryptedFileUUIDArrayMarshalled)

	userlib.DatastoreSet(fileUUIDArrayUUID, signedEncryptedFileUUIDArrayMarshalledMarshalled)

	/*
	 ********************************************
	 **   		  Integrity Step 			   **
	 **        		 New Data  	               **
	 ********************************************
	 */
	//INTEGRITY STEP
	//get user's digital signing key
	dSSignKey = userdata.DSSignKey
	//get user's digital verifying key
	dSFileVerifyKey, _ = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	//upload digital verifying key for appended data's to keystore
	fileKeyStr = newFileDataUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(fileKeyStr, dSFileVerifyKey)

	//encryptedfileDataSignature = sign encryptedfileData with private digital signature key
	encryptedFileDataSignature, _ := userlib.DSSign(dSSignKey, encryptedFileData)

	var signedFileData DSSignedData
	signedFileData.Data = encryptedFileData
	signedFileData.Signature = encryptedFileDataSignature

	signedFileDataMarshalled, _ := json.Marshal(signedFileData)

	userlib.DatastoreSet(newFileDataUUID, signedFileDataMarshalled)

	/*
	 ********************************************
	 **   		  Integrity Step 			   **
	 **        		 METADATA  	               **
	 ********************************************
	 */

	// marshal encryptFileMetaData
	fileMetaDataMarshalled, _ := json.Marshal(decryptedFileMetaData)
	//generate random iv
	randomIV = userlib.RandomBytes(16)
	//get user's FileMetaData symmetric encryption key
	symmetricKey = userdata.FileMetaDataKeys[filename]
	//encrypt fileMetaData
	encryptedFileMetaData = userlib.SymEnc(symmetricKey, randomIV, fileMetaDataMarshalled)

	//sign encryptedFileMetaData with private digital signature key
	encryptedFileMetaDataSignature, _ := userlib.DSSign(dSSignKey, encryptedFileMetaData)
	var newSignedEncryptedFileMetaData DSSignedData
	newSignedEncryptedFileMetaData.Data = encryptedFileMetaData
	newSignedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
	signedEncryptedFileMetaDataMarshalled, _ := json.Marshal(newSignedEncryptedFileMetaData)

	dSVerifyKey, ok = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return err //return error
	}
	metaDataKeyStr = metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(metaDataKeyStr, dSVerifyKey)
	userlib.DatastoreSet(metaUUID, signedEncryptedFileMetaDataMarshalled)

	//Upload userData
	//get user salt and argon2Key
	userSalt := userdata.UserSalt
	argon2KeyFromPassword := userdata.Argon2KeyFromPassword

	//Form UUID from username
	usernameBytes := []byte(userdata.Username) //convert username to bytes
	userUUID, _ := uuid.FromBytes(usernameBytes[:16])

	//Marshal user struct
	userMarshalled, _ := json.Marshal(userdata)

	//generate random iv
	randomIV = userlib.RandomBytes(16)

	//do symmetric encryption with argon2 key on the user bytes
	userMarshalledCiphertext := userlib.SymEnc(argon2KeyFromPassword, randomIV, userMarshalled)

	//append 256 bytes salt to user bytes
	userData := append(userMarshalledCiphertext, userSalt...)

	//INTEGRITY STEP
	/*
		sign whole user struct with DSSignKey and store this
		DatastoreSet(UUID, STRUCT:SALT)
	*/
	signature, _ = userlib.DSSign(dSSignKey, userData)

	var signedUser DSSignedData
	signedUser.Data = userData
	signedUser.Signature = signature

	signedUserMarshalled, _ := json.Marshal(signedUser)

	//upload userData
	userlib.DatastoreSet(userUUID, signedUserMarshalled)

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
	emptyString := ""
	//check if filename exist in OwnedFiles and get fileUUIDArrayUUID
	metaUUID, found := userdata.OwnedFiles[filename]
	if found == false { //	if filename doesn’t exist abort
		return emptyString, errors.New("File does not exist")
	}
	//Marshalled(encryptedFileMetaData+signature) = DatastoreGet(metaUUID)
	signedEncryptedFileMetaDataMarshalled, ok := userlib.DatastoreGet(metaUUID)
	if ok == false { //if the file can't be found.
		return emptyString, errors.New("No data found at this UUID") //return empty data and nil

	}
	//UnMarshal signedEncryptedFileMetaDataMarshalled
	var signedEncryptedFileMetaData DSSignedData
	err = json.Unmarshal(signedEncryptedFileMetaDataMarshalled, &signedEncryptedFileMetaData)
	if err != nil { //if unable to marshall
		return emptyString, err //return empty user and nil
	}
	//get signature from encryptedFileMetaData+signature
	signature := signedEncryptedFileMetaData.Signature
	//get encryptedFileMetaData
	encryptedFileMetaData := signedEncryptedFileMetaData.Data
	//check if fileMetadata is authentic and for integrity
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	dSVerifyKey, ok := userlib.KeystoreGet(metaDataKeyStr)
	if ok == false { //if key doesn't exist in keystore
		return emptyString, errors.New("No valid dsVerify Key found") //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileMetaData, signature)
	if err != nil { //if the user data was corrupted
		return emptyString, err //return empty nil and err
	}

	//decrypt encryptedFileMetaData with our symmetric key for this file
	symmetricKey, found := userdata.FileMetaDataKeys[filename]
	if found == false { //	if filename doesn’t exist abort
		return emptyString, errors.New("No valid Symmetric Key found")
	}
	decryptedFileMetaDataMarshalled := userlib.SymDec(symmetricKey, encryptedFileMetaData)

	//unmarshal file meta data
	var decryptedFileMetaData FileMetaData
	err = json.Unmarshal(decryptedFileMetaDataMarshalled, &decryptedFileMetaData)
	if err != nil { //if unable to marshall
		return emptyString, err //return empty user and nil
	}
	//#################
	//Must generate metadata Symmetric Key for the recipient instead of the recipient generating it
	//users shared with and their metadata Symmetric Keys
	//decryptedFileMetaData.SharedMetaDataSymmetricKeysMap[recipient] = recipientMetaDataSymmetricKey

	//decrypt online FileUUIDArray and update user's FileUUIDArray
	fileUUIDArrayUUID := decryptedFileMetaData.FileUUIDArrayUUID
	signedEncryptedFileUUIDArrayMarshalledMarshalled, ok := userlib.DatastoreGet(fileUUIDArrayUUID)
	if ok == false { //if the fileUUIDArray can't be found.
		return emptyString, errors.New("No data found at this UUID") //return empty data and nil

	}
	//UnMarshal signedFileDataMarshalled
	var signedEncryptedFileUUIDArrayMarshalled DSSignedData
	err = json.Unmarshal(signedEncryptedFileUUIDArrayMarshalledMarshalled, &signedEncryptedFileUUIDArrayMarshalled)
	if err != nil { //if unable to marshall
		return emptyString, err //return nil and error
	}
	//get signature
	signature = signedEncryptedFileUUIDArrayMarshalled.Signature
	encryptedFileUUIDArrayMarshalled := signedEncryptedFileUUIDArrayMarshalled.Data

	//verify Data
	fileKeyStr := fileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	dSVerifyKey, ok = userlib.KeystoreGet(fileKeyStr)
	if ok == false { //if the key can't be found.
		return emptyString, errors.New("No valid dsVerify Key found") //return empty data and nil
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileUUIDArrayMarshalled, signature)
	if err != nil { //if the user data was corrupted
		return emptyString, err //return empty nil and err
	}

	//#############**********
	///STEP TO ADD USER TO SharedMetaDataSymmetricKeysMap AND SharedMetaDataUUIDsMap
	//Generate new symmetric Key for file
	metaDataSymmetricKey := userdata.CurrentSymmetricKey
	userdata.CurrentSymmetricKey = userdata.NextSymmetricKey
	userdata.NextSymmetricKey, _ = HKDF(symmetricKey)

	decryptedFileMetaData.SharedMetaDataSymmetricKeysMap[recipient] = metaDataSymmetricKey

	//magicString = fileUUIDArrayUUID + decryptedFileMetaData.FileSymmetricKey + metaDataSymmetricKey + decryptedFileMetaData.OwnersUsername
	magicStringBytes, err := fileUUIDArrayUUID.MarshalBinary()
	if err != nil { //if unable to marshall
		return emptyString, err //return nil and error
	}
	//userlib.SetDebugStatus(true)
	//userlib.DebugMsg("fileUUIDArrayUUID: %v", magicStringBytes)

	magicStringBytes = append(magicStringBytes, decryptedFileMetaData.FileSymmetricKey...)
	//userlib.DebugMsg("FileSymmetricKey: %v", magicStringBytes)

	magicStringBytes = append(magicStringBytes, metaDataSymmetricKey...)

	magicStringBytes = append(magicStringBytes, []byte(decryptedFileMetaData.OwnersUsername)...)

	//Encrypt magic string with recipient's public key
	recipientPublicKey, ok := userlib.KeystoreGet(recipient + "PublicKey")
	if ok == false { //if key doesn't exist in keystore
		return emptyString, errors.New("No valid dsVerify Key found") //return empty data and nil
	}

	encryptedMagicString, err := userlib.PKEEnc(recipientPublicKey, magicStringBytes)
	if err != nil { //if unable to encrypt magicString
		return emptyString, err
	}

	dSSignKey := userdata.DSSignKey
	//sign magic string with sender's private digital signing key
	encryptedMagicStringSignature, _ := userlib.DSSign(dSSignKey, encryptedMagicString)
	var signedEncryptedMagicString DSSignedData
	signedEncryptedMagicString.Data = encryptedMagicString
	signedEncryptedMagicString.Signature = encryptedMagicStringSignature

	signedEncryptedMagicStringMarshalled, _ := json.Marshal(signedEncryptedMagicString)

	magicString := string(signedEncryptedMagicStringMarshalled)

	////////#####****************
	// mix filename with username to get metaUUID
	metaUUIDString := magicString + userdata.Username
	metaUUIDBytes := []byte(metaUUIDString) //convert metaUUIDString to bytes
	recipientMetaUUID, _ := uuid.FromBytes(metaUUIDBytes[:16])

	decryptedFileMetaData.SharedMetaDataUUIDsMap[recipient] = recipientMetaUUID

	//UPLOAD NEW METADATA
	// marshal encryptFileMetaData
	fileMetaDataMarshalled, _ := json.Marshal(decryptedFileMetaData)
	//generate random iv
	randomIV := userlib.RandomBytes(16)
	//get user's FileMetaData symmetric encryption key
	symmetricKey = userdata.FileMetaDataKeys[filename]
	//encrypt fileMetaData
	encryptedFileMetaData = userlib.SymEnc(symmetricKey, randomIV, fileMetaDataMarshalled)

	//sign encryptedFileMetaData with private digital signature key
	encryptedFileMetaDataSignature, _ := userlib.DSSign(dSSignKey, encryptedFileMetaData)
	var newSignedEncryptedFileMetaData DSSignedData
	newSignedEncryptedFileMetaData.Data = encryptedFileMetaData
	newSignedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
	signedEncryptedFileMetaDataMarshalled, _ = json.Marshal(newSignedEncryptedFileMetaData)
	dSVerifyKey, ok = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return emptyString, errors.New("No valid dsVerify Key found") //return nil and error
	}
	metaDataKeyStr = metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(metaDataKeyStr, dSVerifyKey)
	userlib.DatastoreSet(metaUUID, signedEncryptedFileMetaDataMarshalled)

	//share magic string
	return magicString, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	//check if filename already exist in OwnedFiles, return error if it exists
	_, ok := userdata.OwnedFiles[filename]
	if ok == true { //if filename already exists
		return errors.New("File already exist")
	}
	//convert magicString to bytes
	magicStringtoBytes := []byte(magic_string) //convert username to bytes

	//unmarshal to get SignedMagicString
	var signedMagicString DSSignedData
	err := json.Unmarshal(magicStringtoBytes, &signedMagicString)
	if err != nil { //if unable to marshal
		return errors.New("Can't UnMarshal Magic String")
	}
	//check magicString integrity
	//get signature from signedMagicString
	signature := signedMagicString.Signature
	//get encryptedMagicString
	encryptedMagicString := signedMagicString.Data
	//check if encryptedMagicString is authentic and for integrity
	dSVerifyKey, ok := userlib.KeystoreGet(sender + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return errors.New("DSVerifyKey Can't be retrieved") //return error
	}

	err = userlib.DSVerify(dSVerifyKey, encryptedMagicString, signature)
	if err != nil { //if the user data was corrupted
		return err
	}

	//decrypt magicString with current user’s private key
	magicStringBytes, err := userlib.PKEDec(userdata.PrivateKey, encryptedMagicString)
	if err != nil { //if unable to decrypte magicStringBytes
		return err
	}

	//create metedata object
	var fileMetaData FileMetaData

	//get and convert username to string from bytes
	UUIDBytes := magicStringBytes[:16]
	FileSymmetricKeyBytes := magicStringBytes[:32]
	FileSymmetricKeyBytes = FileSymmetricKeyBytes[len(FileSymmetricKeyBytes)-16:]
	metaDataSymmetricKey := magicStringBytes[:48]
	metaDataSymmetricKey = metaDataSymmetricKey[len(metaDataSymmetricKey)-16:]
	OwnersUsernameBytes := magicStringBytes[len(UUIDBytes)+len(FileSymmetricKeyBytes):]

	fileUUIDArrayUUID, _ := uuid.FromBytes(UUIDBytes)                     //unMarshallBinary FileUUIDArrayUUID
	fileMetaData.FileUUIDArrayUUID = fileUUIDArrayUUID                    //store FileUUIDArrayUUID in metadata
	fileMetaData.FileSymmetricKey = FileSymmetricKeyBytes                 //store FileSymmetricKey in metadata
	fileMetaData.OwnersUsername = string(OwnersUsernameBytes)             //store owner in metadata owner
	fileMetaData.SharedMetaDataSymmetricKeysMap = make(map[string][]byte) //users shared with and their metadata Symmetric Keys
	fileMetaData.SharedMetaDataUUIDsMap = make(map[string]uuid.UUID)      //user shared with and metaDataUUIDs

	// mix filename with username to get metaUUID
	metaUUIDString := magic_string + userdata.Username
	metaUUIDBytes := []byte(metaUUIDString) //convert metaUUIDString to bytes
	metaUUID, _ := uuid.FromBytes(metaUUIDBytes[:16])

	//In OwnedFilesMap create filename:metaUUID
	//userdata.OwnedFiles = make(map[string]uuid.UUID)
	userdata.OwnedFiles[filename] = metaUUID

	///#########**************
	//instead of generating a new metaData SymmetricKey
	//Set the one by sender in user userdata.FileMetaDataKeys[filename] = metaDataSymmetricKey]
	//Generate new symmetric Key for file

	/*symmetricKey := userdata.CurrentSymmetricKey
	userdata.CurrentSymmetricKey = userdata.NextSymmetricKey
	userdata.NextSymmetricKey, _ = HKDF(symmetricKey)
	*/

	userdata.FileMetaDataKeys[filename] = metaDataSymmetricKey

	//encryptedMasterkey = datastoreGet(uuid)

	// encryptFileMetaData with file symmetricKey key
	fileMetaDataMarshalled, _ := json.Marshal(fileMetaData)
	//generate random iv
	randomIV := userlib.RandomBytes(16)
	//do symmetric encryption with argon2 key on the fileMetaData
	encryptedFileMetaData := userlib.SymEnc(metaDataSymmetricKey, randomIV, fileMetaDataMarshalled)

	//METADATA INTEGRITY STEP
	encryptedFileMetaDataSignature, _ := userlib.DSSign(userdata.DSSignKey, encryptedFileMetaData)
	var signedEncryptedFileMetaData DSSignedData
	signedEncryptedFileMetaData.Data = encryptedFileMetaData
	signedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
	signedEncryptedFileMetaDataMarshalled, _ := json.Marshal(signedEncryptedFileMetaData)

	dSVerifyKey, ok = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return err //return error
	}
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(metaDataKeyStr, dSVerifyKey)
	userlib.DatastoreSet(metaUUID, signedEncryptedFileMetaDataMarshalled)

	//UPLOAD USER DATA
	//get user salt and argon2Key
	userSalt := userdata.UserSalt
	argon2KeyFromPassword := userdata.Argon2KeyFromPassword

	//Form UUID from username
	usernameBytes := []byte(userdata.Username) //convert username to bytes
	userUUID, _ := uuid.FromBytes(usernameBytes[:16])

	//Marshal user struct
	userMarshalled, _ := json.Marshal(userdata)

	//generate random iv
	randomIV = userlib.RandomBytes(16)

	//do symmetric encryption with argon2 key on the user bytes
	userMarshalledCiphertext := userlib.SymEnc(argon2KeyFromPassword, randomIV, userMarshalled)

	//append 256 bytes salt to user bytes
	userData := append(userMarshalledCiphertext, userSalt...)

	//USERDATA INTEGRITY STEP
	/*
		sign whole user struct with DSSignKey and store this
		KeyStoreset(usernameDSVerifyKey, DSVerifyKey
		DatastoreSet(UUID, STRUCT:SALT)
	*/
	signature, _ = userlib.DSSign(userdata.DSSignKey, userData)
	var signedUser DSSignedData
	signedUser.Data = userData
	signedUser.Signature = signature
	signedUserMarshalled, _ := json.Marshal(signedUser)
	//store userData in DataStore
	userlib.DatastoreSet(userUUID, signedUserMarshalled)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	//Look in OwnedFiles map and get metaDataUUID
	metaUUID, found := userdata.OwnedFiles[filename]
	if found == false { //if filename doesn’t exist return error
		return errors.New("No file found")
	}
	//get metaData, check integrity, decrypt it
	signedEncryptedFileMetaDataMarshalled, ok := userlib.DatastoreGet(metaUUID)
	if ok == false { //if the metaData can't be found.
		return errors.New("No data found at this UUID") //return error
	}
	//CHECK INTEGRITY
	//UnMarshal signedEncryptedFileMetaDataMarshalled
	var signedEncryptedFileMetaData DSSignedData
	err = json.Unmarshal(signedEncryptedFileMetaDataMarshalled, &signedEncryptedFileMetaData)
	if err != nil { //if unable to marshall
		return err //return error
	}
	//get signature from encryptedFileMetaData+signature
	signature := signedEncryptedFileMetaData.Signature
	//get encryptedFileMetaData
	encryptedFileMetaData := signedEncryptedFileMetaData.Data
	//check if fileMetadata is authentic and for integrity
	metaDataKeyStr := metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	dSVerifyKey, ok := userlib.KeystoreGet(metaDataKeyStr)
	if ok == false { //if key doesn't exist in keystore
		return err //return error
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileMetaData, signature)
	if err != nil { //if the user data was corrupted
		return err //return error
	}
	//decrypt encryptedFileMetaData with our symmetric key for this file
	symmetricKey, found := userdata.FileMetaDataKeys[filename]
	if found == false { //	if filename doesn’t exist abort
		return err
	}
	decryptedFileMetaDataMarshalled := userlib.SymDec(symmetricKey, encryptedFileMetaData)

	//unmarshal file meta data
	var decryptedFileMetaData FileMetaData
	err = json.Unmarshal(decryptedFileMetaDataMarshalled, &decryptedFileMetaData)
	if err != nil { //if unable to marshall
		return err //return error
	}
	//In metaData, check if current user is owner
	if decryptedFileMetaData.OwnersUsername != userdata.Username { //if current user is not the original owner
		return err //return error
	}
	//get array located at fileUUIDArrayUUID, check integrity and decrypt it
	//decrypt online FileUUIDArray and update user's FileUUIDArray
	signedEncryptedFileUUIDArrayMarshalledMarshalled, ok := userlib.DatastoreGet(decryptedFileMetaData.FileUUIDArrayUUID)
	if ok == false { //if the fileUUIDArray can't be found.
		return err //return error

	}
	//UnMarshal signedFileDataMarshalled
	var signedEncryptedFileUUIDArrayMarshalled DSSignedData
	err = json.Unmarshal(signedEncryptedFileUUIDArrayMarshalledMarshalled, &signedEncryptedFileUUIDArrayMarshalled)
	if err != nil { //if unable to marshall
		return err //return error
	}
	//get signature
	signature = signedEncryptedFileUUIDArrayMarshalled.Signature
	encryptedFileUUIDArrayMarshalled := signedEncryptedFileUUIDArrayMarshalled.Data

	//verify Data
	fileKeyStr := decryptedFileMetaData.FileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	dSVerifyKey, ok = userlib.KeystoreGet(fileKeyStr)
	if ok == false { //if the key can't be found.
		return err //return error
	}
	err = userlib.DSVerify(dSVerifyKey, encryptedFileUUIDArrayMarshalled, signature)
	if err != nil { //if the user data was corrupted
		return err //return error
	}
	//	decrypt FileUUIDArray with decryptedFileMetaData.FileSymmetricKey
	decryptedFileUUIDArrayMarshalled := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, encryptedFileUUIDArrayMarshalled)

	var decryptedFileUUIDArray []uuid.UUID                                          //Fix me ########**********************
	err = json.Unmarshal(decryptedFileUUIDArrayMarshalled, &decryptedFileUUIDArray) //FIX ME
	if err != nil {                                                                 //if unable to marshall
		return err //return error
	}
	//////////////

	//check integrity of old files, decrypt old files
	//Now encrypt files with new symmetric key and sign them
	//generate new fileUUIDs and store them in this new uuid
	var totalFile []byte
	for uuidIndex := range decryptedFileUUIDArray { //get uuid.UUID
		fileUUID := decryptedFileUUIDArray[uuidIndex]
		//retrieve info from Datastore
		signedFileDataMarshalled, ok := userlib.DatastoreGet(fileUUID)
		if ok == false { //if the file can't be found.
			return err //return empty data and nil
		}

		//delete current fileUUID
		userlib.DatastoreDelete(fileUUID)
		//UnMarshal signedFileDataMarshalled
		var signedFileData DSSignedData
		err = json.Unmarshal(signedFileDataMarshalled, &signedFileData)
		if err != nil { //if unable to marshall
			return err //return nil and error
		}
		//get signature
		signature = signedFileData.Signature
		fileData := signedFileData.Data
		//verify Data
		fileKeyStr := fileUUID.String()
		fileKeyStr = fileKeyStr + "DSVerifyKey"
		dSVerifyKey, ok := userlib.KeystoreGet(fileKeyStr)
		if ok == false { //if the key can't be found.
			return err //return empty data and nil
		}
		err = userlib.DSVerify(dSVerifyKey, fileData, signature)
		if err != nil { //if the user data was corrupted
			return err //return empty nil and err
		}

		//	decrypt fileData with decryptedFileMetaData.FileSymmetricKey
		decryptedUserData := userlib.SymDec(decryptedFileMetaData.FileSymmetricKey, fileData)
		totalFile = append(totalFile, decryptedUserData...)
		totalFile = []byte(totalFile)

	}

	//encrypt file with new FileSymmetricKey
	decryptedFileMetaData.FileSymmetricKey = userdata.CurrentSymmetricKey
	userdata.CurrentSymmetricKey = userdata.NextSymmetricKey
	userdata.NextSymmetricKey, _ = HKDF(decryptedFileMetaData.FileSymmetricKey)

	//encrypt totalFile with newFileSymmetricKey and store it
	randomIV := userlib.RandomBytes(16)
	encryptedTotalFile := userlib.SymEnc(decryptedFileMetaData.FileSymmetricKey, randomIV, totalFile)

	//INTEGRITY STEP
	// generate digital key pair or get user's digital key
	//dSSignKey, dSVerifyKey, err := userlib.DSKeyGen()
	//userlib.KeystoreGet(userdata.Username + filename + "DSVerifyKey"):alternate
	//In fileVerificationKeys store Filename:DSVerifyKey :alternate

	//get owner's dsVerify Key
	dSFileVerifyKey, ok := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok == false { //if the key can't be found.
		return err
	}
	//////NEW FILE
	fileUUID := uuid.New()
	fileKeyStr = fileUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(fileKeyStr, dSFileVerifyKey)

	//sign file
	//encryptedfileDataSignature = sign encryptedfileData with private digital signature key
	encryptedFileDataSignature, _ := userlib.DSSign(userdata.DSSignKey, encryptedTotalFile)
	var signedFileData DSSignedData
	signedFileData.Data = encryptedTotalFile
	signedFileData.Signature = encryptedFileDataSignature
	signedFileDataMarshalled, _ := json.Marshal(signedFileData)
	userlib.DatastoreSet(fileUUID, signedFileDataMarshalled) //upload file to Datastore to FileUUIDArrayUUID

	//In SharedMetaDataSymmetricKeysMap remove target_username
	delete(decryptedFileMetaData.SharedMetaDataSymmetricKeysMap, target_username)
	delete(decryptedFileMetaData.SharedMetaDataUUIDsMap, target_username)

	//////FILEUUIDARRAY
	var fileUUIDArray []uuid.UUID
	fileUUIDArray = append(fileUUIDArray, fileUUID)

	// Step to update online shared FileUUIDArray in dataStore
	fileUUIDArrayMarshalled, _ := json.Marshal(fileUUIDArray)

	randomIV = userlib.RandomBytes(16)
	encryptedFileUUIDArrayMarshalled = userlib.SymEnc(decryptedFileMetaData.FileSymmetricKey, randomIV, fileUUIDArrayMarshalled)

	dSSignKey := userdata.DSSignKey
	dSFileUUIDArrayVerifyKey, _ := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")

	fileUUIDArrayUUID := uuid.New()
	decryptedFileMetaData.FileUUIDArrayUUID = fileUUIDArrayUUID
	fileKeyStr = decryptedFileMetaData.FileUUIDArrayUUID.String()
	fileKeyStr = fileKeyStr + "DSVerifyKey"

	userlib.KeystoreSet(fileKeyStr, dSFileUUIDArrayVerifyKey)

	encryptedFileUUIDArraySignature, _ := userlib.DSSign(dSSignKey, encryptedFileUUIDArrayMarshalled)
	var newSignedEncryptedFileUUIDArrayMarshalled DSSignedData
	newSignedEncryptedFileUUIDArrayMarshalled.Data = encryptedFileUUIDArrayMarshalled
	newSignedEncryptedFileUUIDArrayMarshalled.Signature = encryptedFileUUIDArraySignature

	signedEncryptedFileUUIDArrayMarshalledMarshalled, _ = json.Marshal(newSignedEncryptedFileUUIDArrayMarshalled)

	userlib.DatastoreSet(fileUUIDArrayUUID, signedEncryptedFileUUIDArrayMarshalledMarshalled)

	//UPLOAD OWNER FILE METADATA
	fileMetaDataMarshalled, _ := json.Marshal(decryptedFileMetaData)

	metaDataSymmetricKey := userdata.FileMetaDataKeys[filename]
	//generate random iv
	randomIV = userlib.RandomBytes(16)
	//do symmetric encryption with argon2 key on the fileMetaData
	newEncryptedFileMetaData := userlib.SymEnc(metaDataSymmetricKey, randomIV, fileMetaDataMarshalled)

	//METADATA INTEGRITY STEP
	encryptedFileMetaDataSignature, _ := userlib.DSSign(userdata.DSSignKey, newEncryptedFileMetaData)
	dSVerifyKey, ok = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok == false { //if key doesn't exist in keystore
		return err //return error
	}
	metaDataKeyStr = metaUUID.String()
	metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
	userlib.KeystoreSet(metaDataKeyStr, dSVerifyKey)
	var newSignedEncryptedFileMetaData DSSignedData
	newSignedEncryptedFileMetaData.Data = newEncryptedFileMetaData
	newSignedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
	newSignedEncryptedFileMetaDataMarshalled, _ := json.Marshal(newSignedEncryptedFileMetaData)
	userlib.DatastoreSet(metaUUID, newSignedEncryptedFileMetaDataMarshalled)

	//for all users left in SharedMetaDataSymmetricKeysMap, give them the updated file info
	err = userdata.RecursiveShareNewFileMetaData(decryptedFileMetaData, fileUUIDArrayUUID, decryptedFileMetaData.FileSymmetricKey)
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(fileUUIDArrayUUID)
	return nil
}

// The structure definition for a user record
type User struct {
	Username              string
	Password              string
	Argon2KeyFromPassword []byte
	CurrentSymmetricKey   []byte
	NextSymmetricKey      []byte
	DSSignKey             userlib.DSSignKey
	OwnedFiles            map[string]userlib.UUID //[filename -> metaUUID(PersonalUUID_2_FileInfo),...]
	PrivateKey            userlib.PKEDecKey
	FileMetaDataKeys      map[string][]byte //FileMetaDataKeys[filename:SymmetricKey, filename2,privatekey]
	UserSalt              []byte
}

type DSSignedData struct {
	Data      []byte
	Signature []byte
}

type FileMetaData struct {
	//FileUUIDArray     []uuid.UUID
	FileUUIDArrayUUID uuid.UUID
	//AppendByteUUID                 uuid.UUID
	FileSymmetricKey               []byte
	OwnersUsername                 string
	SharedMetaDataSymmetricKeysMap map[string][]byte //users shared with and their metadata Symmetric Keys
	SharedMetaDataUUIDsMap         map[string]uuid.UUID
}

func (userdata *User) RecursiveShareNewFileMetaData(ownersFileMetaData FileMetaData, newFileUUIDArrayUUID uuid.UUID, newFileSymmetricKey []byte) (err error) {
	/////THIS FUNCTION MUST CHANGE TO A RECURSIVE ONE
	if len(ownersFileMetaData.SharedMetaDataUUIDsMap) == 0 { //if map is empty, that is no shared user exist
		return nil
	}
	for username, metaUUID := range ownersFileMetaData.SharedMetaDataUUIDsMap {
		//retrieve users metadata from Datastore
		//get metaData, check integrity, decrypt it
		signedEncryptedFileMetaDataMarshalled, ok := userlib.DatastoreGet(metaUUID)
		if ok == false { //if the metaData can't be found.
			return err //return error
		}
		//CHECK INTEGRITY
		var signedEncryptedFileMetaData DSSignedData
		err = json.Unmarshal(signedEncryptedFileMetaDataMarshalled, &signedEncryptedFileMetaData)
		if err != nil { //if unable to marshall
			return err //return error
		}
		//get signature from encryptedFileMetaData+signature
		signature := signedEncryptedFileMetaData.Signature
		//get encryptedFileMetaData
		encryptedFileMetaData := signedEncryptedFileMetaData.Data

		metaDataKeyStr := metaUUID.String()
		metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"

		//check if fileMetadata is authentic and for integrity
		dSVerifyKey, ok := userlib.KeystoreGet(metaDataKeyStr)
		if ok == false { //if key doesn't exist in keystore
			return err //return error
		}
		err = userlib.DSVerify(dSVerifyKey, encryptedFileMetaData, signature)
		if err != nil { //if the user data was corrupted
			return err //return error
		}
		//decrypt encryptedFileMetaData with our symmetric key for this file
		symmetricKey, found := ownersFileMetaData.SharedMetaDataSymmetricKeysMap[username]
		if found == false { //	if filename doesn’t exist abort
			return err
		}
		decryptedFileMetaDataMarshalled := userlib.SymDec(symmetricKey, encryptedFileMetaData)

		//unmarshal file meta data
		var decryptedFileMetaData FileMetaData
		err = json.Unmarshal(decryptedFileMetaDataMarshalled, &decryptedFileMetaData)
		if err != nil { //if unable to marshall
			return err //return error
		}

		//Now make new changes
		decryptedFileMetaData.FileUUIDArrayUUID = newFileUUIDArrayUUID
		decryptedFileMetaData.FileSymmetricKey = newFileSymmetricKey

		////Upload NEW FILE METADATA
		// encryptFileMetaData with file symmetricKey
		fileMetaDataMarshalled, _ := json.Marshal(decryptedFileMetaData)

		metaDataSymmetricKey := ownersFileMetaData.SharedMetaDataSymmetricKeysMap[username]
		//generate random iv
		randomIV := userlib.RandomBytes(16)
		//do symmetric encryption with argon2 key on the fileMetaData
		newEncryptedFileMetaData := userlib.SymEnc(metaDataSymmetricKey, randomIV, fileMetaDataMarshalled)

		//METADATA INTEGRITY STEP
		encryptedFileMetaDataSignature, _ := userlib.DSSign(userdata.DSSignKey, newEncryptedFileMetaData)
		dSVerifyKey, ok = userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
		if ok == false { //if key doesn't exist in keystore
			return err //return error
		}
		metaDataKeyStr = metaUUID.String()
		metaDataKeyStr = metaDataKeyStr + "DSVerifyKey"
		userlib.KeystoreSet(metaDataKeyStr, dSVerifyKey)
		var newSignedEncryptedFileMetaData DSSignedData
		newSignedEncryptedFileMetaData.Data = newEncryptedFileMetaData
		newSignedEncryptedFileMetaData.Signature = encryptedFileMetaDataSignature
		newSignedEncryptedFileMetaDataMarshalled, _ := json.Marshal(newSignedEncryptedFileMetaData)
		userlib.DatastoreSet(metaUUID, newSignedEncryptedFileMetaDataMarshalled)

		//if they have shared it with other users, remove it too
		err = userdata.RecursiveShareNewFileMetaData(decryptedFileMetaData, newFileUUIDArrayUUID, newFileSymmetricKey)
		if err != nil {
			return err
		}

	}

	return nil
}

/*
********************************************
**    Hash-based key derivation function  **
**        		 HKDF  	            	  **
********************************************
 */
// Generate 128-bit symmetric key from previous previous 128-bit symmetric key
func HKDF(previouskey []byte) ([]byte, error) {
	randomBytes := userlib.RandomBytes(256)
	key, err := userlib.HMACEval(previouskey, randomBytes)
	if err != nil {
		return nil, err
	}
	//postprocessing to get first 16 bytes symmetric key
	//newSymmetricKey := key[:len(key)-16]
	newSymmetricKey := key[:16]
	return newSymmetricKey, nil
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
