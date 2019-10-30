package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	"errors"
	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

//

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

func ResetSharedFile(u *User, u2 *User, fn1 string, fn2 string, un string, u2n string) error {

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

type TestUser struct {
	ut *User
}

func (t *TestUser) StoreFile(filename string, data []byte) {
	userlib.DebugMsg("overwrote storefile")
	t.ut.StoreFile(filename, data)
}

func DatastoreGet(uuid uuid.UUID) {
	userlib.DebugMsg("DatstoreGet overwrite")
	userlib.DatastoreGet(uuid)
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

// Multi-User functionality

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

func TestShareAppend(t *testing.T) {
	var aliceFile, bobFile, appendData []byte

	appendData = []byte("more data to append")

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	err2 = u2.AppendFile("file2", appendData)
	if err2 != nil {
		t.Error("AppendFile failed", err2)
	}

	bobFile, err2 = u2.LoadFile("file2")
	if err2 != nil {
		t.Error("Failed to download file after append", err2)
		return
	}

	aliceFile, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download shared file after other user appends", err)
		return
	}

	// files should be equal
	if !reflect.DeepEqual(aliceFile, bobFile) {
		t.Error("Shared file is not the same among users")
		return
	}
}

func TestShareOverwrite(t *testing.T) {

	var aliceFile, bobFile, newData []byte

	newData = []byte("this is new data to put on the file")

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	u2.StoreFile("file2", newData)

	bobFile, err2 = u2.LoadFile("file2")
	if err2 != nil {
		t.Error("Failed to download file after store", err2)
		return
	}

	aliceFile, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download shared file after other user stores", err)
		return
	}

	//files should equal newData
	if !reflect.DeepEqual(aliceFile, newData) {
		t.Error("Shared file was not updated for Alice")
		return
	}

	// files should be equal
	if !reflect.DeepEqual(aliceFile, bobFile) {
		t.Error("Shared file is not the same among users")
		return
	}
}

func TestShareThreeUsers(t *testing.T) {
	var aliceFile, bobFile, yoshiFile, sharedFile []byte
	sharedFile = []byte("three users can share this file")

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err2)
		return
	}

	u3, err3 := InitUser("yoshi", "spottedegg")
	if err3 != nil {
		t.Error("Failed to initialize user", u3)
		return
	}

	var magic_string string

	u.StoreFile("shared3", sharedFile)

	aliceFile, err = u.LoadFile("shared3")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	// share file with bob
	magic_string, err = u.ShareFile("sharedd", "bob")
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}
	err = u2.ReceiveFile("shared3bob", "alice", magic_string)
	if err != nil {
		t.Error("Bob failed to receive the shared message", err)
		return
	}

	// share file with yoshi
	magic_string, err = u.ShareFile("shared3", "yoshi")
	if err != nil {
		t.Error("Failed to share the a file with yoshi", err)
		return
	}
	err = u3.ReceiveFile("shared3yoshi", "alice", magic_string)
	if err != nil {
		t.Error("Yoshi failed to receive the shared message", err)
		return
	}

	bobFile, err = u2.LoadFile("shared3bob")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	yoshiFile, err = u3.LoadFile("shared3yoshi")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(aliceFile, sharedFile) {
		t.Error("Alice does not have shared file", sharedFile, aliceFile)
		return
	}

	if !reflect.DeepEqual(yoshiFile, sharedFile) {
		t.Error("Yoshi does not have shared file", sharedFile, yoshiFile)
		return
	}

	if !reflect.DeepEqual(bobFile, sharedFile) {
		t.Error("Bob does not have shared file", sharedFile, bobFile)
		return
	}
}

func TestRevokeOwnerAppend(t *testing.T) {
	var file1, file2 []byte

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("RevokeFile failed", err)
		return
	}

	err = u.AppendFile("file1", []byte("Bob shouldn't see this"))
	if err != nil {
		t.Error("AppendFile failed for owner", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	file1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download file for owner", err)
		return
	}

	file2, err = u2.LoadFile("file2")

	if reflect.DeepEqual(file2, file1) {
		t.Error("Bob saw updated version of Alice's file after AppendFile", file1, file2)
		return
	}
}

func TestRevokeOwnerStore(t *testing.T) {
	var file1, file2 []byte

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

	// Share file with Bob again
	err = ResetSharedFile(u, u2, "file1", "file2", "alice", "bob")
	if err != nil {
		t.Error("Shared file failed", err)
	}

	// Revoke Bob's file then store new file
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Revoke file failed", err)
		return
	}

	u.StoreFile("file1", []byte("New data that Bob still shouldn't see"))

	file1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download file for owner after StoreFile", err)
		return
	}

	file2, err = u2.LoadFile("file2")

	if reflect.DeepEqual(file2, file1) {
		t.Error("Bob saw updated version of Alice's file after StoreFile", file1, file2)
		return
	}
}

func TestRevokeRecipientAppend(t *testing.T) {
}

func TestRecipientStore(t *testing.T) {
}

func TestRevokeThreeUsers(t *testing.T) {
}

// Test with children

func TestShareChild(t *testing.T) {
}

func TestRevokeChild(t *testing.T) {
}

// Test with children and siblings

func TestRevokeChildSibling(t *testing.T) {
}

// Multi-user Integrity Test
func TestRevokeMallory(t *testing.T) {
}
