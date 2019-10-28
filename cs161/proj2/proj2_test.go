package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
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

	if string.Compare("alice", u.username) == 0 {
		t.Error("Failed to hide user data when inputing valid password")
	}
	t.Log("Returned error for bad password", u)
	return
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

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

	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v, err2 := u.LoadFile("fileone")
	if err2 == nil {
		t.Error("Failed to return error with bad filename", err2)
		return
	}

	v2, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}

	// file contents should NOT be equal
	if reflect.DeepEqual(v, v2) {
		t.Error("Loaded File with Invalid Name", v, v2)
		return
	}

}

func TestSameFilenameTwoUsers(t *testing.T) {

	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	kirby, err2 := InitUser("kirby", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize kirby", err2)
		return
	}

	kirbyFile := []byte("This is a kirby's file")
	kirby.SetFile("myfile", kirbyFile)

	aliceFile := []byte("This is a Alice's file")
	alice.SetFile("myfile", aliceFile)

	v1, err3 := kirby.LoadFile("myfile")
	v2, err4 := alice.LoadFile("myfile")

	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}

	if err4 != nil {
		t.Error("Failed to upload and download", err4)
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
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("New text for file1")
	u.SetFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	// files SHOULD be equal
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func SmallFileAppend(t *testing.T) {

}

func EfficientAppend(t *testing.T) {

}

// Single User Integrity

func TestModifiedFile(t *testing.T) {
}

func TestModifiedUserData(t *testing.T) {
}

// Multi-User functionality

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
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
}

func TestShareSet(t *testing.T) {
}

func TestRevokeTwoUsers(t *testing.T) {
}

func TestShareRevokeLargeFamily(t *testing.T) {
}

// Multi-user Integrity Test
func TestRevokeMallory(t *testing.T) {
}
