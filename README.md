# Project 2 Starter Code

## Project Description
This project involves designing a client application for a secure file sharing system, similar to Dropbox, but with cryptographic protections against server intrusion.

The client allows users to:

- Authenticate using a username and password.
- Save, load, overwrite, and append to files on the server.
- Share files with other users and revoke their access.
  
The goal is to use the provided resources and security knowledge to create a client that meets all design requirements.

## Design process
The design concept relies on a tree structure that operates like a centralized hub-and-spoke model with the file sharer at the core.Thumbnail

<img src="assets/encryption-diagram.png" width="80%" />

* Central Hub (Root Node):
The file sharer (owner) sets up this central point. This hub contains information required to generate encryption and authentication keys, ensuring that only authorized individuals can access the stored file. A deterministic data, is utilized to generate or derive these keys, ensuring that even if the central hub is exposed, the file data remains secure.

* Child Nodes (Spokes):
Each child node represents an individual user (or group of users) that has been granted access to the file by the sharer. The sharer grants access by encrypting the necessary key information from the central hub using the recipient's public key. Only the recipient, with their private key, can decrypt this information to gain access to the file.

* Asymmetric Key Sharing:
When the sharer wants to grant access to a user, they use the user's public key to encrypt the necessary information (derived from the central hub) for accessing the file. The recipient user uses their private key to decrypt this information. Once decrypted, they can derive or obtain the keys to decrypt and authenticate the file.

## Key concepts
1. The files are stored using deterministic keys derived from user data, filename, and UUID.
2. Encryption and authentication are clearly paramount. Multiple keys are involved, including both deterministic keys (from user data) and random keys.
3. For storing new files, the logic creates a new entry, whereas for appending to a file, the logic identifies the tail of the file's data chain and appends new content to the end.
4. There are multiple layers of encoding and decoding, probably to ensure data security and integrity.

## Methods
<u>GenerateKeys</u>: This function generates a set of deterministic keys based on the provided username and password. The usage of Argon2 for key derivation is good, as it's a memory-hard function resistant to GPU-based attacks. Multiple derivatives are created from the main passphrase to generate separate keys.

<u>Encode</u>: This is a helper function that handles encryption and authentication of data. SymEnc and HMACEval are used for encrypting and creating a MAC tag, respectively.

<u>Decode</u>: This functi on decrypts and authenticates data. An HMAC is evaluated and compared against a stored tag to ensure the integrity of the data. The function returns decrypted data after validation.

<u>InitUser</u>: This function initializes a new user with a set of cryptographic keys. It also serializes, encrypts, and stores user data. Public keys are stored in the key store.

<u>GetUser</u>: Retrieves user data, decrypts it, and deserializes it back into a user structure.

<u>StoreFile</u>: Stores a given file content in a data store for a user. If the file does not already exist, it creates an initial file, generates random encryption and authentication keys for it, and encodes it for storage. If the file exists, it retrieves the file, updates its content, and re-encodes it for storage.

<u>AppendToFile</u>: Appends content to an existing file for a user. If the file does not have any appended data yet, it creates the "next" link in the file chain and stores the new content. If the file has previous appendages, it retrieves the tail of the appendages and links a new chunk of data to the tail.

## Potential Areas of Improvements
- Clarity: The code might benefit from further modularization. For instance, operations such as getting the tail of a file chain or encoding and decoding data could be separate methods to make the main methods more readable.
- Repetition: There's repetition in the logic for traversing the file chain and decoding file chunks, especially in the AppendToFile method. Refactoring this into a separate function would make the code DRYer (Don't Repeat Yourself).
- Concurrency: For future iteration, we need to account for potential concurrent accesses or modifications to the file. To address multi-threaded or distributed access, adding some synchronization or conflict resolution needed to be in-place.
- Error Messages: The error can be handled differently without compromising any details that might expose some internal logic information.
