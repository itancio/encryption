package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	_"encoding/hex"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)

	// To convert uuid.UUID to string, use userUuid.String()
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username 	string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	UserUuid   	uuid.UUID
	PublicKey  	userlib.PKEEncKey
	PrivateKey 	userlib.PKEDecKey
	SignKey    	userlib.DSSignKey
	VerifyKey  	userlib.DSVerifyKey

}

type DatastoreValue struct {
	Cipher 		[]byte
	Tag    		[]byte
}

type File struct {
	Filetype	string
	Content		[]byte

	Next		uuid.UUID
	Next_Ek		[]byte
	Next_Ak		[]byte

	Tail		uuid.UUID	
	Tail_Ek		[]byte
	Tail_Ak		[]byte

}

type Accesspoint struct {
	Owner		[]byte
	Addr		uuid.UUID
	Ek			[]byte
	Ak			[]byte
}

type Sharelist struct {
	List		[]string
}

// NOTE: The following methods have toy (insecure!) implementations.
// Helper function for InitUser and GetUser
func GenerateKeys(username string, password string) (userUuid uuid.UUID, encryptKey []byte, authKey []byte, err error) {
	// Check if username or password is an empty string
	if username == "" || password == "" {
		return uuid.Nil, nil, nil, errors.New("the user credentials are invalid")
	}

	// Generate deterministic key for uuid
	passphrase := username + password
	salt := userlib.Hash([]byte(passphrase))
	userUuid, err = uuid.FromBytes(userlib.Argon2Key([]byte(passphrase), salt, 16))

	if err != nil {
		return uuid.Nil, nil, nil, nil
	}

	// Generate deterministic key for encryption/ decryption
	passphrase1 := userlib.Hash([]byte(username + password))
	salt1 := userlib.Hash([]byte(passphrase1))
	encryptKey = userlib.Argon2Key([]byte(passphrase1), salt1, 16)

	// Generate deterministic key for authentication
	passphrase2 := userlib.Hash([]byte(passphrase1))
	salt2 := userlib.Hash([]byte(passphrase2))
	authKey = userlib.Argon2Key([]byte(passphrase2), salt2, 16)
	
	return userUuid, encryptKey, authKey, err //make sure to add err once we figure out how to
}

// Encrypt, authenticate and store for symmetric encryption
func Encode(dataUuid uuid.UUID, serializedData []byte, encryptKey []byte, authKey []byte) (err error){
	// Encrypt the user struct
	iv := userlib.RandomBytes(userlib.AESKeySizeBytes)
	encrypted_struct := userlib.SymEnc(encryptKey, iv, serializedData)

	// Authenticate the user struct; Creating tag for the user
	macEncrypted_struct, err := userlib.HMACEval(authKey, encrypted_struct)

	if err != nil {
		return errors.New("cannot authenticate the encrypted data")
	}

	// Create the DsValue for the datastore
	var dsvalue DatastoreValue 
	dsvalue.Cipher = encrypted_struct
	dsvalue.Tag = macEncrypted_struct

	// Serialize the datastorevalue
	serializedDsValue, err := json.Marshal(dsvalue)
	// userlib.DebugMsg(fmt.Sprintf("ENCODE: serializedDsvalue: %s", serializedDsValue[:20]))

	if err != nil {
		return errors.New("cannot serialize the datastore value of the data")
	}

	// Store the serialized DsValue in the datastore
	userlib.DatastoreSet(dataUuid, serializedDsValue)

	return nil
}

// Retrieve, De-crypt, authenticate for symmetric encryption
// This is useful for symmetric authentication and decryption of a serialized data
func Decode(dataUuid uuid.UUID, encryptKey []byte, authKey []byte) (serializedData []byte, err error) {
	// Get value from the datastore using the data uuid
	datastoreValue, ok := userlib.DatastoreGet(dataUuid)
	// userlib.DebugMsg(fmt.Sprintf("DECODE: datastoreValue: %s", datastoreValue[:20]))

	if !ok  {
		return nil, errors.New("this data does not exist in the Datastore")
	}

	// De-serialize the datastore value
	var dsvalue DatastoreValue
	err = json.Unmarshal(datastoreValue, &dsvalue)

	if err != nil {
		return nil, errors.New("cannot deserialized data in the datastore")
	}

	cipher := dsvalue.Cipher
	tag := dsvalue.Tag

	// Check if data has been tampered with
	authData, err := userlib.HMACEval(authKey, cipher)

	if err != nil {
		panic(err)
	}

	ok = userlib.HMACEqual(authData, tag)

	if !ok {
		return nil, (errors.New("data is corrupted"))
	}

	// Decrypt the userStruct
	serializedData = userlib.SymDec(encryptKey, cipher)

	return serializedData, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username

	// Check if username is empty
	if len(username) == 0 {
		return nil, errors.New("an empty username is provided")
	}

	// Generate public-private keys
	userdata.PublicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("cannot generate public/private key pair")
	}

	// Generate sign-verify keys
	userdata.SignKey, userdata.VerifyKey, err = userlib.DSKeyGen()

	if err != nil {
		return nil, errors.New("cannot generate digital signature key pair")
	}

	// Generate deterministic keys
	var encryptKey []byte
	var authKey []byte

	userdata.UserUuid, encryptKey, authKey, err = GenerateKeys(username, password)

	if err != nil {
		return nil, errors.New("cannot generate symmetric keys for the user")
	}


	// Serialize the user struct
	serializedUserdata, err := json.Marshal(userdata)

	if err != nil {
		return nil, errors.New("cannot serialize userdata")
	}
	
	// Encrypt, Authenticate, and store the user struct
	err = Encode(userdata.UserUuid, serializedUserdata, encryptKey, authKey)
	if err != nil {
		return nil, errors.New("encoding of user struct failed")
	}


	// Store the public key in the Keystore
	ksKey := string(userlib.Hash([]byte(username + "PKEEncKey")))
	err = userlib.KeystoreSet(ksKey, userdata.PublicKey)

	if err != nil {
		return nil, errors.New("cannot store the user's public key in the Keystore")
	}

	// Store the verify key in the Keystore
	ksKey = string(userlib.Hash([]byte(username + "DSVerify")))
	err = userlib.KeystoreSet(ksKey, userdata.VerifyKey)

	if err != nil {
		return nil, errors.New("cannot store the user's verify key in the Keystore")
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	var encryptK []byte
	var authK []byte
	var userId uuid.UUID
	// Re-derive the keys for user's uuid, encryption key, and authentication key
	userId, encryptK, authK, err = GenerateKeys(username, password)

	if err != nil {
		return nil, err
	}

	user_struct, err := Decode(userId, encryptK, authK)
	if err != nil {
		return nil, errors.New("getuser: data problem with the encryption")
	}

	// De-serialize the user struct
	err = json.Unmarshal(user_struct, userdataptr)
	if err != nil {
		return nil, errors.New("getuser: the user cannot be de-serialized")
	}
	
	return userdataptr, nil

}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Create deterministic keys
	passphrase := userdata.Username + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)

	if err != nil {
		return errors.New("storefile: cannot generate deterministic keys")
	}

	// Create file struct
	var file File
	file.Content = content
	file.Filetype = "File"

	// If file does not exist yet, create a file struct and access point
	// userdata.FileMap[filename] == uuid.Nil.String()
	if _, ok := userlib.DatastoreGet(storageKey); !ok {

		// Generate random uuid
		fileId := uuid.New()

		// Generate random encryption and authentication keys. 
		// these are the C2
		fileEncryptK := userlib.RandomBytes(userlib.AESKeySizeBytes)
		fileAuthenK := userlib.RandomBytes(userlib.AESKeySizeBytes)

		serialFile, err := json.Marshal(file)
		// userlib.DebugMsg(fmt.Sprintf("STORE 1: serial File: %s", serialFile))

		if err != nil {
			return errors.New("store: cannot add values to the datastore")
		}
		err = Encode(fileId, serialFile, fileEncryptK, fileAuthenK)

		if err != nil {
			return errors.New("store: cannot encode file")
		}
		//making the access point for owner of file
		var access Accesspoint 
		access.Owner = (userlib.Hash([]byte(userdata.Username)))
		access.Addr = fileId 
		access.Ek = fileEncryptK
		access.Ak = fileAuthenK
		
		serial_ap, err := json.Marshal(access)
		// userlib.DebugMsg(fmt.Sprintf("STORE 1: serialized ap: %s", serial_ap))
		if err != nil {
			return errors.New("store: cannot serialize access point")
		}
	
		// Initialize share list
		passphrase := userdata.UserUuid.String() + filename + "sharelist"
		salt := string((userlib.Hash([]byte(passphrase))))
		s, e, a, err := GenerateKeys(passphrase, salt)

		if err != nil {
			return errors.New("load: cannot generate keys for the sharelist")
		}

		var sharelist Sharelist
		sharelist.List = []string{}
		serialSharelist, err := json.Marshal(sharelist)
		if err != nil {
			return errors.New("store: cannot serialize the sharelist")
		}
		err = Encode(s, serialSharelist, e, a)
		if err != nil {
			return errors.New("load: cannot create sharelist")
		}

		return Encode(storageKey, serial_ap, encryptKey, authKey)

	} else {
		//the case if file exists for owner  
		if !ok {
			return errors.New("store: cannot retrieve from DStore")
		}
		var ap Accesspoint
		for i := 0; i < 3; i++ {
			serialDsVal, err := Decode(storageKey, encryptKey, authKey)
			// userlib.DebugMsg(fmt.Sprintf("STORE 2: serialized ap CORRECT?: %s", serialDsVal))

			if err != nil {
				return errors.New("store: cannot decode the accesspoint")
			}

			err = json.Unmarshal(serialDsVal, &ap)
			if err != nil {
				return errors.New("STORE 2: accesspoint can be de-serialized")
			}
	
			//this is the file now...serialized
			encryptKey = ap.Ek
			authKey = ap.Ak
			storageKey = ap.Addr

			err = json.Unmarshal(serialDsVal, &file)
			if err != nil {
				return errors.New("load: accesspoint cannot be de-serialized")
			}
			if file.Filetype != "File" {
				serialDsVal, err = Decode(storageKey, encryptKey, authKey)
				if err != nil {
					return errors.New("load: accesspoint cannot be decoded/unlocked")
				}

				err = json.Unmarshal(serialDsVal, &ap)
				if err != nil {
					return errors.New("load: accesspoint cannot be de-serialized")
				}

				//handle err
				encryptKey = ap.Ek
				authKey = ap.Ak
				storageKey = ap.Addr
				// userlib.DebugMsg("Continuing")
				continue;
			}
			if file.Filetype == "File" {
				file.Content = content
				break;
			}
		}
		// Serialize the file struct
	
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return err
		}
		// userlib.DebugMsg(fmt.Sprintf("Content: %s", file.Content))
		return Encode(storageKey, fileBytes, encryptKey, authKey)
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Traverse through accesspoint
	passphrase := userdata.Username + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)
	if err != nil {
		return errors.New("append: cannot generate keys")
	}

	var file File
	var ap Accesspoint
	index := 0
	for { //remove the conditions after so that it's an infinite loop
		decryptFile, err := Decode(storageKey, encryptKey, authKey)
		// userlib.DebugMsg("decryptfile: %s", err)
		if err != nil {
			return errors.New(strings.ToTitle("append: file does not exist"))
		}
		err = json.Unmarshal(decryptFile, &ap)
		if err != nil {
			return errors.New("append: accesspoint cannot be de-serialized")
		}
		// userlib.DebugMsg("File: %s", err)
		encryptKey = ap.Ek
		authKey = ap.Ak
		storageKey = ap.Addr
		err = json.Unmarshal(decryptFile, &file)
		if err != nil {
			return errors.New("append: accesspoint cannot be de-serialized")
		}
		if file.Filetype != "File" {
			decryptFile, err = Decode(storageKey, encryptKey, authKey)
			if err != nil {
				// userlib.DebugMsg(fmt.Sprintf("Content: %s %d", err, index))
				return errors.New("append: file cannot be decoded")
			}
			index ++
			err = json.Unmarshal(decryptFile, &ap)

			if err != nil {
				return errors.New("append: file cannot be de-serialized")
			}
			encryptKey = ap.Ek
			authKey = ap.Ak
			storageKey = ap.Addr
			// userlib.DebugMsg("Continuing")
			continue;
		}

		if file.Filetype == "File" {
			break
		}
	}

	// Generate random keys
	newStorageKey := uuid.New() //storage key
	newEncryptKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
	newAuthKey := userlib.RandomBytes(userlib.AESKeySizeBytes)

	// Create new file struct
	var newFile File
	newFile.Content = content
	
	var prev File //the file tail is pointing to

	// Follow the tail. if it's nil, just
	// userlib.DebugMsg("1ppend: UUID: %s Content: %s", newStorageKey, hex.EncodeToString(content))
	if file.Tail == uuid.Nil {
		file.Next_Ak = newAuthKey
		file.Next_Ek = newEncryptKey
		file.Next = newStorageKey

		file.Tail_Ak = newAuthKey
		file.Tail_Ek = newEncryptKey
		file.Tail = newStorageKey
	} else {
		prevFile, err := Decode(file.Tail, file.Tail_Ek, file.Tail_Ak)
		// userlib.DebugMsg("2append: UUID: %s ", file.Tail)
		if err != nil {
			return errors.New("append: tail file cannot be de-serialized")
			
		}
		err = json.Unmarshal(prevFile, &prev)

		if err != nil {
			return errors.New("append: cannot serialize file")
		}
		prev.Next  = newStorageKey
		prev.Next_Ak = newAuthKey
		prev.Next_Ek = newEncryptKey

		serializedPrev, err := json.Marshal(prev)

		if err != nil {
			return errors.New("append: cannot serialize serializedPrev")
		}

		err = Encode(file.Tail, serializedPrev, file.Tail_Ek, file.Tail_Ak)

		if err != nil {
			return errors.New("append: cannot encode serializedPreb")
		}

		file.Tail = newStorageKey
		file.Tail_Ak = newAuthKey
		file.Tail_Ek = newEncryptKey
		file.Tail = newStorageKey
		// userlib.DebugMsg("3append: UUID: %s ", file.Tail)

		// serializedFile, err := json.Marshal(file)
		// err = Encode(storageKey, serializedFile, encryptKey, authKey)
		if err != nil {
			return errors.New("append: primary file cannot be de-serialized")
		}
	}
	serializedFile, err := json.Marshal(file)
	if err != nil {
		return errors.New("append: cannot serialize serializedFile")
	}
	err = Encode(storageKey, serializedFile, encryptKey, authKey)
	if err != nil {
		return errors.New("append: cannot encode file")
	}
	serializedNewFile, err := json.Marshal(newFile)
	if err != nil {
		return errors.New("append: cannot serialize serializedNewFile")
	}

	return Encode(newStorageKey, serializedNewFile, newEncryptKey, newAuthKey)
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Generate deterministic keys to unlock the first accesspoint
	passphrase := userdata.Username + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)

	if err != nil {
		return nil, errors.New("load: cannot generate keys for the central hub")
	}

	var file File
	var ap Accesspoint

	for i:= 0; i < 3; i++ { //remove the conditions after so that it's an infinite loop
		decryptFile, err := Decode(storageKey, encryptKey, authKey)
		if decryptFile == nil {
			return nil, errors.New("load: what is being accessed does not exist")
		}
		// userlib.DebugMsg("decryptfile: %s", decryptFile)
		if err != nil {
			return nil, errors.New(strings.ToTitle("load: file does not exist"))
		}
		err = json.Unmarshal(decryptFile, &ap)
		if err != nil {
			return nil, errors.New("load: accesspoint cannot be de-serialized")
		}
		// userlib.DebugMsg("File: %s", err)
		encryptKey = ap.Ek
		authKey = ap.Ak
		storageKey = ap.Addr
		err = json.Unmarshal(decryptFile, &file)
		if err != nil {
			return nil, errors.New("load: accesspoint cannot be de-serialized")
		}
		if file.Filetype != "File" {
			decryptFile, err = Decode(storageKey, encryptKey, authKey)
			if err != nil {
				// userlib.DebugMsg(fmt.Sprintf("Content: %s %d", err, i))
				return nil, errors.New("load: file cannot be decoded")
			}
			err = json.Unmarshal(decryptFile, &ap)

			if err != nil {
				return nil, errors.New("load: file cannot be de-serialized")
			}
			encryptKey = ap.Ek
			authKey = ap.Ak
			storageKey = ap.Addr
			// userlib.DebugMsg("Continuing")
			continue;
		}
		if file.Filetype == "File" {
			// userlib.DebugMsg("Fileeeeeeeeee: ")
			// content = file.Content

			// Iterate over every linked list nodes of a file
			// userlib.DebugMsg("load: decryptfile: %s", file.Next)
			// index := 0
			if file.Next != uuid.Nil {
				for file.Next != uuid.Nil {
					// userlib.DebugMsg("load: decryptfile: ")
					// userlib.DebugMsg("Chains of files: %s", hex.EncodeToString(content))
			
					decryptFile, err := Decode(storageKey, encryptKey, authKey)
					// userlib.DebugMsg("index: %d", index)
					// index++
					if err != nil {
						return nil, errors.New(strings.ToTitle("load: file does not exist"))
					}
					err = json.Unmarshal(decryptFile, &file)
					if err != nil {
						return nil, errors.New("load: accesspoint cannot be de-serialized")
					}
					// userlib.DebugMsg("File: %s", err)
					storageKey = file.Next
					encryptKey = file.Next_Ek
					authKey = file.Next_Ak
					content = append(content, file.Content...)
					// userlib.DebugMsg("load: decryptfile: %s", hex.EncodeToString(content))
	
				}
			} else {
				content = file.Content
			}

			break;
		}
	}

	// userlib.DebugMsg("Final result: %s", content)
	return content, err
}


// Helper function for Asymmetric encryption, signature and storage
func RsaEncode(dataUuid uuid.UUID, serializedData []byte, ek userlib.PKEEncKey, authKey userlib.DSSignKey) (err error){
	// Encrypt the user struct
	encrypted_struct, err := userlib.PKEEnc(ek, serializedData)
	// userlib.DebugMsg("creating: the user exists %s", err)

	if err != nil {
		return errors.New("cannot encrypt data")
	}

	// Sign the encryted struct
	signEncrypted_struct, err := userlib.DSSign(authKey, encrypted_struct)

	if err != nil {
		return errors.New("cannot authenticate the encrypted data")
	}

	// Create the DsValue for the datastore
	var dsvalue DatastoreValue 
	dsvalue.Cipher = encrypted_struct
	dsvalue.Tag = signEncrypted_struct

	// Serialize the datastorevalue
	serializedDsValue, err := json.Marshal(dsvalue)
	// userlib.DebugMsg("rsaEncode: serializedDsValue %s", serializedDsValue[:30])

	if err != nil {
		return errors.New("cannot serialize the datastore value of the data")
	}

	// Store the serialized DsValue in the datastore
	userlib.DatastoreSet(dataUuid, serializedDsValue)

	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Check if recipient exists.
	ksKey := string(userlib.Hash([]byte(recipientUsername + "PKEEncKey")))
	recipients_Pk, ok := userlib.KeystoreGet(ksKey)
	// if ok {
	// 	userlib.DebugMsg("creating: the user exists %s", recipients_Pk)
	// }

	if !ok {
		return uuid.Nil, errors.New("create inv: recipient does not exist")
	}

	// Check if file exist
	passphrase := userdata.Username + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	user_storageKey, user_encryptKey, user_authKey, err := GenerateKeys(passphrase, salt)


	if err != nil {
		return uuid.Nil, errors.New("file does not exist in the user's namespace")
	}

	decryptFile, err := Decode(user_storageKey, user_encryptKey, user_authKey)
	// userlib.DebugMsg("decryptfile: %s", err)
	if err != nil {
		return uuid.Nil, errors.New("create inv: file does not exist")
	}

	var ap Accesspoint
	err = json.Unmarshal(decryptFile, &ap)
	if err != nil {
		return uuid.Nil, errors.New("create inv: accesspoint cannot be de-serialized")
	}
	
	// PART 1: Create temporary message to share with the recipient
	invitationPtr = uuid.New()

	// If user is not the owner, share the owner's encrypt-auth keys
	// Otherwise, share the ap 
	var message Accesspoint
	if ap.Owner == nil {		//non-owner
		// userlib.DebugMsg("create Inv non-owner CHEECK", (userlib.Hash([]byte(userdata.Username)))[:15])
		message.Addr = user_storageKey
		message.Ek = user_encryptKey
		message.Ak = user_authKey
		// userlib.DebugMsg(fmt.Sprintf("CHEECK"))
	} else {					// owner
		// userlib.DebugMsg("create Inv owner CHEECK", (userlib.Hash([]byte(userdata.Username)))[:15])
		message.Addr = ap.Addr
		message.Ek = ap.Ek
		message.Ak = ap.Ak

		// Owner updates share list
		passphrase := userdata.UserUuid.String() + filename + "sharelist"
		salt := string((userlib.Hash([]byte(passphrase))))
		storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)

		if err != nil {
			return uuid.Nil, errors.New("create inv: cannot generate keys for the sharelist")
		}

		sharelist, err := Decode(storageKey, encryptKey, authKey)
		if err != nil {
			return uuid.Nil, errors.New("create inv: cannot decode sharelist")
		}

		// Update sharelist
		var shared Sharelist
		json.Unmarshal(sharelist, &shared)
		shared.List = append(shared.List, recipientUsername)
		// userlib.DebugMsg(fmt.Sprintf("SHARELIST: %s", sharelist))
		// Re-encode
		serial_sharelist, err := json.Marshal(shared)
		if err != nil {
			return uuid.Nil, errors.New("create inv: cannot serialized sharelist")
		}

		err = Encode(storageKey, serial_sharelist, encryptKey, authKey)

		if err != nil {
			return uuid.Nil, errors.New("create inv: cannot encode sharelist")
		}
	}

	serialMessage, err := json.Marshal(message)
	if err != nil {
		return uuid.Nil, errors.New("create inv: cannot serialized message")
	}
	err = RsaEncode(invitationPtr, serialMessage, recipients_Pk, userdata.SignKey)
	if err != nil {
		// userlib.DebugMsg("decryptfile: %s", err)
		return uuid.Nil, errors.New("create inv: cannot encode message asymmetrically")
	}

	// PART 2: Create Alice-to-Bob Accesspoint
	passphrase = recipientUsername + filename + userdata.UserUuid.String()
	salt = string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)
	if err != nil {
		return uuid.Nil, errors.New("create inv: cannot generate keys for alice-to-bob accesspoint")
	}
	
	var AtoB Accesspoint
	AtoB.Addr = message.Addr
	AtoB.Ek = message.Ek
	AtoB.Ak = message.Ak

	serialAtoB, err := json.Marshal(AtoB)
	if err != nil {
		return uuid.Nil, errors.New("create inv: atob accesspoint cannot be serialized")
	}

	err = Encode(storageKey, serialAtoB, encryptKey, authKey)
	if err != nil {
		return uuid.Nil, errors.New("create inv: atob accesspoint cannot be encoded")
	}

	return invitationPtr, nil
}

// Helper function for Asymmetric verify, decryption
func RsaDecode(dataUuid uuid.UUID, decryptKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (serializedData []byte, err error){
	// Get value from the datastore using the data uuid
	datastoreValue, ok := userlib.DatastoreGet(dataUuid)
	// userlib.DebugMsg("rsaEncode: serializedDsValue %s", datastoreValue[:30])

	if !ok  {
		return nil, errors.New("this data does not exist in the Datastore")
	}

	// De-serialize the datastore value
	var dsvalue DatastoreValue
	err = json.Unmarshal(datastoreValue, &dsvalue)

	if err != nil {
		return nil, errors.New("cannot deserialized data in the datastore")
	}

	cipher := dsvalue.Cipher
	tag := dsvalue.Tag
	
	// Verify the encryted struct
	err = userlib.DSVerify(verifyKey, cipher, tag)

	if err != nil {
		return nil, errors.New("data is corrupted/tampered")
	}

	// Decrypt the data Struct
	serializedData, err = userlib.PKEDec(decryptKey, cipher)
	if err != nil {
		return nil, errors.New("rsadecode: cannot decrypt")
	}

	return serializedData, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Check if user already already has a file with the given filename in their personal file namespace.
	passphrase := userdata.Username + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)

	if err != nil {
		errContent := fmt.Sprintf("accept: error from generateKeys - %s", err)
		return errors.New(errContent)
	}

	_, ok := userlib.DatastoreGet(storageKey)

	if ok {
		return errors.New("accept: file already exists in the user's personal file namespace")
	}


	ksKey := string(userlib.Hash([]byte(senderUsername + "DSVerify")))
	senderPrivK, ok := userlib.KeystoreGet(ksKey)
	if !ok {
		return errors.New("accept: key not in keystore")
	}
	serial_invt, err := RsaDecode(invitationPtr, userdata.PrivateKey, senderPrivK)
	if err != nil {
		err_content := fmt.Sprintf( "accept: error message from rsadecode - %s", err)
		return errors.New(err_content)
	}
	var ap Accesspoint
	err = json.Unmarshal(serial_invt, &ap)
	if err != nil { 
		return errors.New("accept:type mismatch")
	}
	
	//Acceptee is creating their own access point
	var userAp Accesspoint

	if err != nil {
		return errors.New("accept:cannot generate keys for accesspoint")
	}

	userAp.Addr = ap.Addr
	userAp.Ek = ap.Ek
	userAp.Ak = ap.Ak
	acceptee_access, err := json.Marshal(userAp)
	if err != nil {
		return errors.New("accept: couldn't serialize acceptee access point")
	}

	err = Encode(storageKey, acceptee_access, encryptKey, authKey)
	if err != nil {
		return errors.New("accept: couldn't encode acceptee access point")
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Check if the given filename is currently shared with the recipient
	passphrase := recipientUsername + filename + userdata.UserUuid.String()
	salt := string((userlib.Hash([]byte(passphrase))))
	recipient_storageK, _, _, err := GenerateKeys(passphrase, salt)

	if err != nil {
		return errors.New("revoke: cannot generate keys")
	}

	_, ok := userlib.DatastoreGet(recipient_storageK)

	if !ok {
		return errors.New("revoke: the given filename is not currently shared with recipientUsername")
	}

	// PART 1: Change keys in Owner's accesspoint
	// Generatekeys(Username + filename + Userdata.uuid) to unlock the owner's accesspoint
	passphrase = userdata.Username + filename + userdata.UserUuid.String()
	salt = string((userlib.Hash([]byte(passphrase))))
	storageKey, encryptKey, authKey, err := GenerateKeys(passphrase, salt)

	if err != nil {
		return errors.New("revoke: filename must not exist in the caller's namespace")
	}

	// Use keys to unlock the file struct.
	// var file File
	var file_owner Accesspoint
	decrypt_ap, err := Decode(storageKey, encryptKey, authKey) 
	if err != nil {
		return errors.New("revoke: couldn't decocde accesspoint")
	}
	err = json.Unmarshal(decrypt_ap, &file_owner)
	if err != nil {
		return errors.New("revoke: couldn't deserialze access point")
	}

	decrypt_file, err := Decode(file_owner.Addr, file_owner.Ek, file_owner.Ak)//this is the serialized file that the keys point to
	if err != nil {
		return errors.New("revoke: couldn't decocde file")
	}
	// Create new random keys and uuid
	new_uuid := uuid.New()
	new_ek := userlib.RandomBytes(userlib.AESKeySizeBytes)
	new_ak := userlib.RandomBytes(userlib.AESKeySizeBytes)
	// Re-encrypt the file with new keys and store with the new uuid
	userlib.DatastoreDelete(file_owner.Addr)
	err = Encode(new_uuid, decrypt_file, new_ek, new_ak)
	if err != nil {
		return errors.New("revoke: couldn't encode file")
	}

	// Delete the old file from datastore (or clear the file struct)
	// userlib.DatastoreDelete(file_owner.Addr)

	// update the keys and uuid inside the owner's accesspoint
	file_owner.Addr = new_uuid
	file_owner.Ek = new_ek
	file_owner.Ak = new_ak
	
	owner, err  := json.Marshal(file_owner)
	if err != nil {
		return errors.New("revoke: can't serialize the owner accesspoint")
	}
	err = Encode(storageKey, owner, encryptKey, authKey)
	if err != nil {
		return errors.New("revoke: couldn't encode owner accesspoint")
	}

	// PART 2: Update the share list and share keys with direct children by changing keys in accesspoint
	// Generate keys(UserUUID + filename + 'sharelist') to unlock the share accesspoint
	passphrase = userdata.UserUuid.String()+ filename + "sharelist"
	salt = string((userlib.Hash([]byte(passphrase))))
	share_storageK, share_ek, share_ak, err := GenerateKeys(passphrase, salt)
	if err != nil {
		return errors.New("revoke: cannot generate keys for sharelist")
	}
	serialShare, err := Decode(share_storageK, share_ek, share_ak)
	if err != nil {
		return errors.New("revoke: cannot decode sharelist from the datastore")
	}

	
	// De-serialize the share struct
	var sharelist Sharelist
	err = json.Unmarshal(serialShare, &sharelist)
	if err != nil {
		// userlib.DebugMsg(fmt.Sprintf("Content: %s", sharelist))
		// userlib.DebugMsg(fmt.Sprintf("Content: %s", err))
		return errors.New ("revoke: cannot de-serialize the sharelist")
	}

	// userlib.DebugMsg(fmt.Sprintf("Content: %s", sharelist))
	for i, child := range sharelist.List {
		// userlib.DebugMsg("sharelist: %s: %s", i, child)
		// Remove the revoked child from the list
		if child == recipientUsername {
			if i + 1 >= len(sharelist.List) {
				sharelist.List = sharelist.List[:len(sharelist.List)-1]
			} else {
				sharelist.List = append(sharelist.List[:i], sharelist.List[i+1:]...)
			}
		} else {
			// GenerateKeys(childName + filename + Userdata.uuid) to unlock the AtoB accesspoint.
			passphrase := child + filename + userdata.UserUuid.String()
			salt := string((userlib.Hash([]byte(passphrase))))
			child_storageK, child_ek, child_ak, err:= GenerateKeys(passphrase, salt)
			if err != nil {
				return errors.New("revoke: cannot generate keys for child accesspoint")
			}

			serialChildAp, err := Decode(child_storageK, child_ek, child_ak)
			if err != nil {
				return errors.New("revoke: cannot generate keys for child accesspoint")
			}

			// De-serialize the child's ap
			var childAp Accesspoint
			err = json.Unmarshal(serialChildAp, &childAp)
			// userlib.DebugMsg(fmt.Sprintf("Content: %s", err))
			if err != nil {
				// userlib.DebugMsg(fmt.Sprintf("Content: %s", err))
				return errors.New("revoke. cannot de-serialize childAp")
			}
			// Update the keys and uuid with the new keys and uuid
			childAp.Addr = new_uuid
			childAp.Ek = new_ek
			childAp.Ak = new_ak

			// Re-serialize the child's AP struct
			serialChildAp, err = json.Marshal(childAp)
			if err != nil {
				return errors.New("revoke: cannot re-serialize the child's ap struct")
			}
			err = Encode(child_storageK, serialChildAp, child_ek, child_ak)
			if err != nil {
				return errors.New("revoke: cannot re-encode serialChilAp")
			}
		}
	}

	return nil
}