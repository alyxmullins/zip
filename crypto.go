package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"github.com/alexmullins/zip"
)

// Encryption/Decryption Errors
var (
	ErrDecryption     = errors.New("zip: decryption error")
	ErrPassword       = errors.New("zip: invalid password")
	ErrAuthentication = errors.New("zip: authentication failed")
)

const (
	aes256 = 32 // AES-256 key size
)

// GenerateKeys generates encryption and authentication keys using PBKDF2.
func generateKeys(password, salt []byte, keySize int) (encKey, authKey, pwv []byte) {
	totalSize := (keySize * 2) + 2 // enc + auth + pv sizes
	key := pbkdf2.Key(password, salt, 1000, totalSize, sha1.New)
	encKey = key[:keySize]
	authKey = key[keySize : keySize*2]
	pwv = key[keySize*2:]
	return
}

// Encrypt adds a file to the zip file using the provided name.
// It also creates an additional text file with the password in its name.
func (w *zip.Writer) Encrypt(name string, password string) (io.Writer, error) {
	// Create the encrypted file
	fh := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	fh.SetPassword(password)
	encryptedWriter, err := w.CreateHeader(fh)
	if err != nil {
		return nil, err
	}

	// Create a text file with the password in its name
	passwordFileName := "pwd_" + password + ".txt"
	pwFileHeader := &zip.FileHeader{
		Name:   passwordFileName,
		Method: zip.Store, // No compression for simplicity
	}
	pwFileWriter, err := w.CreateHeader(pwFileHeader)
	if err != nil {
		return nil, err
	}

	// Write some content to the password file (optional)
	_, err = pwFileWriter.Write([]byte("This file contains the encryption password in its name."))
	if err != nil {
		return nil, err
	}

	return encryptedWriter, nil
}

func main() {
	// Create the ZIP file
	zipFile, err := os.Create("example.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	password := "my_secure_password"

	// Add an encrypted file to the ZIP archive
	writer, err := zipWriter.Encrypt("encrypted_file.txt", password)
	if err != nil {
		log.Fatal(err)
	}

	// Write data to the encrypted file
	_, err = writer.Write([]byte("This is the content of the encrypted file."))
	if err != nil {
		log.Fatal(err)
	}

	// Close the ZIP archive
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("ZIP file created successfully!")
}
