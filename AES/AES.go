package AES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	uuid "github.com/satori/go.uuid"
)

func TestAES() {
	key := []byte(uuid.Must(uuid.NewV4()).String()[:16])
	fmt.Println("AES Key is:")
	fmt.Println(key)
	originData := []byte("Tom")
	fmt.Println("Origin Data is:")
	fmt.Println("Tom")
	en := encryptAES(originData, key)
	fmt.Println("The result is:")
	fmt.Println(en)
	de := decryptAES(en, key)
	fmt.Println("The result is:")
	fmt.Println(string(de))
}

func generateRandomKeyOfAES() []byte {
	return []byte(uuid.Must(uuid.NewV4()).String()[:16])
}

func decryptAES(cipherText, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	originData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(originData, cipherText)
	originData = PKCS7UnPadding(originData)
	return originData
}

func PKCS7UnPadding(originData []byte) []byte {
	length := len(originData)
	position := int(originData[length-1])
	return originData[:length-position]
}

func encryptAES(originData, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	originData = PKCS7Padding(originData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	cipherText := make([]byte, len(originData))
	blockMode.CryptBlocks(cipherText, originData)
	return cipherText
}

func PKCS7Padding(originData []byte, blockSize int) []byte {
	padding := blockSize - len(originData)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(originData, padText...)
}
