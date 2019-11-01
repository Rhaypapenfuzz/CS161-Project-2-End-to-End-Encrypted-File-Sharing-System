package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	"errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

// Helper Functions

/** Resets Datastore to same state after TestInit. **/
func ResetDatastore() {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	userlib.DebugMsg("cleared datastore")
	userlib.DebugMsg("cleared keystore")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		userlib.DebugMsg("user not re-intialized", err)
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	return
}

/** Shares a file between user u and user u2 and returns first error. **/
func SetSharedFile(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {

	var file2 []byte
	var magic_string string

	file1, err := u.LoadFile(fn1)
	if err != nil {
		return err
	}

	magic_string, err = u.ShareFile(fn1, u2n)
	if err != nil {
		return err
	}
	err = u2.ReceiveFile(fn2, un, magic_string)
	if err != nil {
		return err
	}

	file2, err = u2.LoadFile(fn2)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(file1, file2) {
		return errors.New("files not identical after sharing")
	}

	return nil
}

/** After user u revokes access for user u2, checks that u2 can no longer see appends. **/
func RevokedOwnerAppend(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, recipFile, appendData []byte
	appendData = []byte("Owner will attempt to append this data, but recipient should not see it")

	err := u.AppendFile(fn1, appendData)
	if err != nil {
		userlib.DebugMsg("AppendFile failed for owner")
		return err
	}

	// This may or may not cause error depending on implementation
	recipFile, err = u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should NOT be equal
	if reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("File access was NOT denied")
	}

	return nil
}

/** After user u revokes access for user u2, checks that u2 can no longer see stores. **/
func RevokedOwnerStore(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, storeData []byte
	storeData = []byte("Owner will attempt to store this data, but recipient should not be able to access it")

	u.StoreFile(fn1, storeData)

	// May or may not return error depending on implementatin
	recipFile, err := u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should NOT be equal
	if reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("File access was NOT denied")
	}

	return nil
}

/** After user u revokes access for user u2, checks that u2 can no longer append file. **/
func RevokedRecipientAppend(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, recipFile, appendData []byte
	appendData = []byte("Recipient will attempt to append this data, but should not affect owner's file")

	// May or may not return error depending on implementation
	err := u2.AppendFile(fn2, appendData)
	if err != nil {
		userlib.DebugMsg("AppendFile failed for recipient")
	}

	// May or may not return error depending on implementation
	recipFile, err = u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should NOT be equal
	if reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("File access was NOT denied")
	}

	return nil
}

/** After user u revokes access for user u2, checks that u2 can no longer overwrite file. **/
func RevokedRecipientStore(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, storeData []byte
	storeData = []byte("Recipient will attempt to store this data, but it should not overwrite owner's data")

	u2.StoreFile(fn2, storeData)

	// May or may not return error depending on implementation
	recipFile, err := u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should NOT be equal
	if reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("File access was NOT denied")
	}

	return nil
}

/** After user u gives access for user u2, checks that u2 CAN SEE overwrites to file. **/
func SharedOwnerAppend(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, recipFile, appendData []byte
	appendData = []byte("Owner will attempt to append this data")

	err := u.AppendFile(fn1, appendData)
	if err != nil {
		userlib.DebugMsg("AppendFile failed for owner")
		return err
	}

	recipFile, err = u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
		return err
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should be equal
	if !reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("Files fail DeepEqual")
	}

	return nil
}

/** After user u gives access to user u2, checks that u2 CAN SEE appends to file. **/
func SharedOwnerStore(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, storeData []byte
	storeData = []byte("Owner will attempt to store this data")

	u.StoreFile(fn1, storeData)

	recipFile, err := u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
		return err
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should be equal
	if !reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("Files fail DeepEqual")
	}

	return nil
}

/** After user u gives access to user u2, checks that u2 CAN MAKE appends to file. **/
func SharedRecipientAppend(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, recipFile, appendData []byte
	appendData = []byte("Recipient will attempt to append this data")

	err := u2.AppendFile(fn2, appendData)
	if err != nil {
		userlib.DebugMsg("AppendFile failed for recipient")
		return err
	}

	recipFile, err = u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
		return err
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should be equal
	if !reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("Files fail DeepEqual")
	}

	return nil
}

/** After user u gives access to user u2, checks that u2 CAN MAKE overwrites to file. **/
func SharedRecipientStore(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {
	var ownerFile, storeData []byte
	storeData = []byte("Recipient will attempt to store this data")

	u2.StoreFile(fn2, storeData)

	recipFile, err := u2.LoadFile(fn2)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for recipient")
		return err
	}

	ownerFile, err = u.LoadFile(fn1)
	if err != nil {
		userlib.DebugMsg("LoadFile failed for owner")
		return err
	}

	// Files should be equal
	if !reflect.DeepEqual(ownerFile, recipFile) {
		return errors.New("Files fail DeepEqual")
	}

	return nil
}

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	// userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

// Single User Functionality

func TestBadPassword(t *testing.T) {

	u, err := GetUser("alice", "foobar")
	if err == nil {
		t.Error("Failed to return error for invalid password", err)
	}

	//	if strings.Compare("alice", u.username) == 0 {
	//		t.Error("Failed to hide user data when inputing valid password")
	//	}
	t.Log("Returned error for bad password", u)
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestBadLoadName(t *testing.T) {
	var v, v2 []byte

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v, err = u.LoadFile("fileone")
	if err == nil {
		t.Error("Failed to return error with bad filename", err)
		return
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}

	// file contents should NOT be equal
	if reflect.DeepEqual(v, v2) {
		t.Error("Loaded File with Invalid Name", v, v2)
		return
	}

}

func TestSameFilenameTwoUsers(t *testing.T) {
	var kirby *User
	var aliceFile, kirbyFile, v1, v2 []byte

	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	kirby, err = InitUser("kirby", "foobar")
	if err != nil {
		t.Error("Failed to initialize kirby", err)
		return
	}

	kirbyFile = []byte("This is a kirby's file")
	kirby.StoreFile("myfile", kirbyFile)

	aliceFile = []byte("This is a Alice's file")
	alice.StoreFile("myfile", aliceFile)

	v1, err = kirby.LoadFile("myfile")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}

	v2, err = alice.LoadFile("myfile")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}

	// file contents should NOT be equal
	if reflect.DeepEqual(v1, v2) {
		t.Error("Separate users given same file", v1, v2)
		return
	}

	// file contents SHOULD be equal
	if !reflect.DeepEqual(aliceFile, v2) {
		t.Error("File changed after store", aliceFile, v2)
		return
	}

	// file contents SHOULD be equal
	if !reflect.DeepEqual(kirbyFile, v1) {
		t.Error("File changed after store", kirbyFile, v1)
		return
	}
}

func TestStoreOverwrite(t *testing.T) {

	var v, v2 []byte

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v = []byte("New text for file1")
	u.StoreFile("file1", v)

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}

	// files SHOULD be equal
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestSmallFileAppend(t *testing.T) {
	var appended, small, data []byte

	small = []byte("This is a small file of text")
	data = []byte("Data to Append")

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u.StoreFile("smallfile", small)

	err = u.AppendFile("smallfile", data)
	if err != nil {
		t.Error("Returned error with AppendFile", err)
		return
	}

	appended, err = u.LoadFile("smallfile")
	if err != nil {
		t.Error("Failed to download", err)
		return
	}

	small = append(small, data...)

	if len(small) != len(appended) {
		t.Error("Appended file does not have same length", len(small), len(appended))
		return
	}

	if !reflect.DeepEqual(small, appended) {
		t.Error("Appended file does not reflect changes")
		return
	}
}

func TestLargeFileAppend(t *testing.T) {
	var appended, large, data []byte

	large = make([]byte, 60000)
	for i := range large {
		large[i] = '\x41'
	}

	data = []byte("data to append")

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u.StoreFile("largefile", large)

	err = u.AppendFile("largefile", data)
	if err != nil {
		t.Error("Returned error with AppendFile", err)
		return
	}

	appended, err = u.LoadFile("largefile")
	if err != nil {
		t.Error("Failed to download", err)
		return
	}

	large = append(large, data...)

	// files should be same length
	if len(large) != len(appended) {
		t.Error("Appended file not same length", len(large), len(appended))
		return
	}

	// file contents SHOULD be equal
	if !reflect.DeepEqual(large, appended) {
		t.Error("Appended file does not reflect changes")
		return
	}

}

// Helper function to corrupt single byte
func CorruptByte(b byte) byte {
	return b + 1
}

// Single User Integrity

func TestModifiedFile(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	datastore := userlib.DatastoreGetMap()
	for key, value := range datastore {
		vlen := len(value)
		if vlen > 0 {
			value[vlen-1] = CorruptByte(value[vlen-1])
			datastore[key] = value
		}
	}

	_, err = u.LoadFile("file1")
	// Should return error
	if err == nil {
		ResetDatastore()
		t.Error("Failed to recognize corrupted byte in file", err)
		return
	}
	ResetDatastore()
}

func TestModifiedUser(t *testing.T) {

	datastore := userlib.DatastoreGetMap()
	for key, value := range datastore {
		vlen := len(value)
		if vlen > 0 {
			value[vlen-1] = CorruptByte(value[vlen-1])
			datastore[key] = value
		}
	}

	_, err := GetUser("alice", "fubar")
	if err == nil {
		ResetDatastore()
		t.Error("Failed to recognize corrupted byte in user data")
		return
	}
	t.Log("Error msg is ", err)
	ResetDatastore()
}

/** Skeleton code test left unchanged. **/
func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err, u)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestReceiveDupFilename(t *testing.T) {
	var magic_string string

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err, u)
		return
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u.StoreFile("dupFilname", []byte("Bob will already have a file of this name"))
	u2.StoreFile("dupFilename", []byte("Bob's file with this name"))

	magic_string, err = u.ShareFile("dupFilename", "bob")
	err = u2.ReceiveFile("dupFilename", "alice", magic_string)
	if err == nil {
		t.Error("failed to catch error, bob already has file of this name")
		return
	}

}

func TestReceiveDupMagic(t *testing.T) {
	var magic_string string

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("failed to reload user", err, u)
		return
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("failed to initialize bob", err2)
		return
	}

	u.StoreFile("dupMagic", []byte("Alice will revoke Bob's access and then he will try to receive file with same magic string"))

	magic_string, err = u.ShareFile("dupMagic", "bob")
	err = u2.ReceiveFile("dupMagic", "alice", magic_string)
	if err != nil {
		t.Error("Bob did not receive file", err)
		return
	}

	err = u.RevokeFile("dupMagic", "bob")
	if err != nil {
		t.Error("Revoke file failed", err)
	}

	err = u2.ReceiveFile("dupMagic", "alice", magic_string)

	err = RevokedOwnerAppend(u, u2, "dupMagic", "dupMagic", "alice", "bob")
	if err != nil {
		t.Error("Revoke file failed to prevent Bob from seeing Alice's updates", err)
	}

	err = RevokedRecipientAppend(u, u2, "dupMagic", "dupMagic", "alice", "bob")
	if err != nil {
		t.Error("Revoke failed to prevent Bob from appending to Alice's file", err)
	}

}

func TestShareLoadDifFile(t *testing.T) {
	var bobFile, aliceFile []byte
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("failed to reload user", err, u)
		return
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("failed to initialize bob", err2)
		return
	}

	u.StoreFile("tryToGetThis", []byte("Bob will try to access this file even though he was shared a different file"))
	u.StoreFile("fileForBob", []byte("Alice will give this file to Bob"))

	err = SetSharedFile(u, u2, "fileForBob", "fileForBob2", "alice", "bob")

	bobFile, err = u2.LoadFile("tryToGetThis")
	if err == nil {
		t.Error("loaded alice's other file")
		return
	}

	aliceFile, err = u.LoadFile("tryToGetThis")
	if err != nil {
		t.Error("failed to load bob's file")
		return
	}

	if reflect.DeepEqual(bobFile, aliceFile) {
		t.Error("Bob got alice's other file")
		return
	}

}
func TestShareAppend(t *testing.T) {
	var sharedFile []byte
	sharedFile = []byte("Bob and Alice share this file 1 to test append")

	// Get user alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user bob
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	// Alice stores new shared file
	u.StoreFile("sharedFile1a", sharedFile)
	_, err = u.LoadFile("sharedFile1a")
	if err != nil {
		t.Error("File upload or download failed", err)
		return
	}

	// Alice shares new file with Bob
	err = SetSharedFile(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file failed", err)
		return
	}

	// Alice appends file
	err = SharedOwnerAppend(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file fails when Alice appends", err)
		return
	}

	// Bob appends file
	err = SharedRecipientAppend(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file fails when Bob appends", err)
		return
	}
}

func TestShareStore(t *testing.T) {
	var sharedFile []byte
	sharedFile = []byte("Bob and Alice share this file 2 to test store")

	// Get user alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user bob
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	// Alice stores new shared file
	u.StoreFile("sharedFile2a", sharedFile)
	_, err = u.LoadFile("sharedFile1a")
	if err != nil {
		t.Error("File upload or download failed", err)
		return
	}

	// Alice shares new file with Bob
	err = SetSharedFile(u, u2, "sharedFile2a", "sharedFile2b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file failed", err)
		return
	}

	// Alice stores new data in file
	err = SharedOwnerStore(u, u2, "sharedFile2a", "sharedFile2b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file fails when Alice stores", err)
		return
	}

	// Bob stores new data in file
	err = SharedRecipientStore(u, u2, "sharedFile2a", "sharedFile2b", "alice", "bob")
	if err != nil {
		t.Error("Sharing file fails when Bob stores", err)
		return
	}

}

func TestShareThreeUsers(t *testing.T) {
	var sharedFile []byte

	// Create new file to share
	sharedFile = []byte("three users can share this file")

	// Get users Alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user Bob
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	// Initialize user Yoshi
	u3, err3 := InitUser("yoshi", "spottedegg")
	if err3 != nil {
		t.Error("Failed to initialize user", u3)
		return
	}

	// Alice stores new file
	u.StoreFile("sharedFile3U", sharedFile)
	_, err = u.LoadFile("sharedFile3U")
	if err != nil {
		t.Error("File upload or download failed", err)
		return
	}

	// Alice shares file with Bob
	err = SetSharedFile(u, u2, "sharedFile3U", "sharedFile3U", "alice", "bob")
	if err != nil {
		t.Error("File shareing failed with Bob", err)
		return
	}

	//Alice shares file with Yoshi
	err = SetSharedFile(u, u3, "sharedFile3U", "sharedFile3U", "alice", "yoshi")
	if err != nil {
		t.Error("File shareing failed with Yoshi", err)
		return
	}
}

func TestRevokeOwnerAppend(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("RevokeFile failed", err)
		return
	}

	err = RevokedOwnerAppend(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Alice's revoke failed to hide access from Bob", err)
		return
	}
}

func TestRevokeOwnerStore(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	err = RevokedOwnerStore(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Alice's revoke failed to hide access from Bob", err)
		return
	}
}

func TestRevokeRecipientAppend(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	err = RevokedRecipientAppend(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Alice's revoke failed to prevent updates from Bob", err)
		return
	}
}

func TestRecipientStore(t *testing.T) {

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	err = RevokedRecipientStore(u, u2, "sharedFile1a", "sharedFile1b", "alice", "bob")
	if err != nil {
		t.Error("Alice's revoke failed to prevent updates from Bob", err)
		return
	}
}

func TestRevokeThreeUsers(t *testing.T) {
	var sharedFile, bobFile []byte

	// New file to share
	sharedFile = []byte("Alice wants to share this file with her friends Bob and Yoshi")

	// Get user Alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user Bob
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	// Get user Yoshi
	u3, err3 := GetUser("yoshi", "spottedegg")
	if err3 != nil {
		t.Error("Failed to reload user", err3)
		return
	}

	// Store new file
	u.StoreFile("sharedFile3U2", sharedFile)
	_, err = u.LoadFile("sharedFile3U2")
	if err != nil {
		t.Error("Failed to upload or download sharedFile3U2", err)
	}

	// Share file with Bob
	err = SetSharedFile(u, u2, "sharedFile3U2", "sharedFile3U2", "alice", "bob")
	if err != nil {
		t.Error("Shared file failed", err)
	}

	// Share file with Yoshi
	err = SetSharedFile(u, u3, "sharedFile3U2", "sharedFile3U2", "alice", "yoshi")
	if err != nil {
		t.Error("Shared file failed", err)
	}

	// Revoke Bob's access
	err = u.RevokeFile("sharedFile3U2", "bob")
	if err != nil {
		t.Error("Revoke file failed", err)
		return
	}

	// Bob tries to append data
	err = RevokedRecipientAppend(u, u2, "sharedFile3U2", "sharedFile3U2", "alice", "bob")
	if err != nil {
		t.Error("Alice's revoke failed to prevent updates from Bob", err)
		return
	}

	// Yoshi attempts to append data
	err = SharedRecipientAppend(u, u3, "sharedFile3U2", "sharedFile3U2", "alice", "yoshi")
	if err != nil {
		t.Error("Yoshi was unable update Alice's file", err)
		return
	}

	// Check to see that Yoshi's updates are hidden from Bob
	sharedFile, err = u3.LoadFile("sharedFile3U2")
	if err != nil {
		t.Error("File download failed", err)
		return
	}

	bobFile, err = u2.LoadFile("sharedFile3U2")
	if reflect.DeepEqual(bobFile, sharedFile) {
		t.Error("Bob was able to see changes after yoshi", bobFile, sharedFile)
		return
	}

	// Alice tries to append Data
	err = SharedOwnerAppend(u, u3, "sharedFile3U2", "sharedFile3U2", "alice", "yoshi")
	if err != nil {
		t.Error("Alice is unable to append to her file", err)
		return
	}

	// Check that Bob can't see Alice's updates
	sharedFile, err = u3.LoadFile("sharedFile3U2")
	if err != nil {
		t.Error("File download failed", err)
		return
	}

	bobFile, err = u2.LoadFile("sharedFile3U2")
	if reflect.DeepEqual(bobFile, sharedFile) {
		t.Error("Bob was able to see changes after yoshi", bobFile, sharedFile)
		return
	}

}

// Test with children

func TestShareChild(t *testing.T) {
	var sharedFile []byte

	sharedFile = []byte("Alice creates a new file that she will send to Bob. Then Bob will send file Bob Jr.")

	// Get users Alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user Bob
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	// Initialize user Bob Jr.
	u3, err3 := InitUser("bobJr", "babyfoobar")
	if err3 != nil {
		t.Error("Failed to initialize user", u3)
		return
	}

	// Alice stores new file
	u.StoreFile("sharedFileC", sharedFile)

	// Alice shares file with Bob
	err = SetSharedFile(u, u2, "sharedFileC", "sharedFileC", "alice", "bob")
	if err != nil {
		t.Error("File sharing failed with Bob", err)
		return
	}

	// Bob shared file with Bob Jr.
	err = SetSharedFile(u2, u3, "sharedFileC", "sharedFileC", "bob", "bobJr")
	if err != nil {
		t.Error("File sharing failed with Bob Jr.", err)
		return
	}

	// Check that Bob Jr. CAN append
	err = SharedRecipientAppend(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. does not have access to append Alice's file")
		return
	}

	// Check that Bob Jr. CAN store
	err = SharedRecipientStore(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. does not have access to append Alice's file")
		return
	}

	// Check that Bob Jr. CAN see Alice's append
	err = SharedOwnerAppend(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. still does not have access to append Alice's file")
		return
	}

	// Check that Bob Jr. cannot see ALice's store
	err = SharedOwnerStore(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. does not have access to store to Alice's file")
		return
	}
}

func TestRevokeChild(t *testing.T) {

	// Get users Alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	// Get user Bob Jr.
	u3, err3 := GetUser("bobJr", "babyfoobar")
	if err3 != nil {
		t.Error("Failed to initialize user", u3)
		return
	}

	// Alice revokes Bob's access, which revokes Bob Jr.'s access
	u.RevokeFile("sharedFileC", "bob")

	// Check that Bob Jr. cannot append
	err = RevokedRecipientAppend(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. still has access to append Alice's file")
		return
	}

	// Check that Bob Jr. cannot store
	err = RevokedRecipientStore(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. still has access to append Alice's file")
		return
	}

	// Check that Bob Jr. cannot see Alice's append
	err = RevokedOwnerAppend(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. still has access to append Alice's file")
		return
	}

	// Check that Bob Jr. cannot see ALice's store
	err = RevokedOwnerStore(u, u3, "sharedFileC", "sharedFileC", "alice", "bobJr")
	if err != nil {
		t.Error("Bob Jr. still has access to store to Alice's file")
		return
	}
}

// Multi-user Integrity Test
func TestRevokeMallory(t *testing.T) {
}

/*
func TestHashBasedDFunc(t *testing.T) {

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)

	RandomOldSymmetricKey := userlib.RandomBytes(16)
	newSymmetricKey, err := HKDF(RandomOldSymmetricKey)
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to get New Symmetric Key", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("New Symmetric Key Derived", newSymmetricKey)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy

}*/
