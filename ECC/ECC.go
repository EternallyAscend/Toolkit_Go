package ECC

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	uuid "github.com/satori/go.uuid"
	mathRand "math/rand"
	"os"
	"strings"
	"time"
)

func TestECC() {
	privateKey, publicKey, err := GenerateRandomKeyStringOfECC()
	if nil != err {
		fmt.Println(err)
		return
	}
	fmt.Println("Public Key is:")
	fmt.Println(publicKey)
	privateKeyECIES, publicKeyECIES, err := GetKeyByString(privateKey, publicKey)
	if nil != err {
		fmt.Println(err)
		return
	}
	originData := "Tom"
	fmt.Println("Origin Data is:")
	fmt.Println("Tom")

	cryptoData, err := EncryptECC(originData, publicKeyECIES)
	if nil != err {
		fmt.Println(err)
		return
	}

	fmt.Println("The result is:")
	fmt.Println(cryptoData)
	resultData, err := DecryptECC(cryptoData, privateKeyECIES)
	if nil != err {
		fmt.Println(err)
		return
	}
	fmt.Println("The result is:")
	fmt.Println(resultData)
}

func createRandomSalt(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+?=-"
	bytes := []byte(str)
	var result []byte
	r := mathRand.New(mathRand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func GenerateRandomKeyByteArrayOfECC() ([]byte, []byte, error) {randKey := createRandomSalt(55)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(randKey))
	if nil != err {
		return nil, nil, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if nil != err {
		return nil, nil, err
	}
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: privateBytes,
	}

	var path string
	//path = "./"
	path = uuid.Must(uuid.NewV4()).String()
	path += "-private.pem"

	privateFileOutput, err := os.Create(path)
	if nil != err {
		return nil, nil, err
	}
	defer privateFileOutput.Close()

	err = pem.Encode(privateFileOutput, &privateBlock)
	if nil != err {
		return nil, nil, err
	}

	privateFileInput, err := os.Open(path)
	if nil != err {
		return nil, nil, err
	}
	defer privateFileInput.Close()
	privateKeyContent, err := privateFileInput.Stat()
	if nil != err {
		return nil, nil, err
	}
	privateKeyBuffer := make([]byte, privateKeyContent.Size())
	_, err = privateFileInput.Read(privateKeyBuffer)
	if nil != err {
		return nil, nil, err
	}

	go RemovePemFile(path)

	publicKey := privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if nil != err {
		return nil, nil, err
	}
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: publicBytes,
	}

	//path = "./"
	path = uuid.Must(uuid.NewV4()).String()
	path += "-public.pem"

	publicFileOutput, err := os.Create(path)
	if nil != err {
		return nil, nil, err
	}
	defer publicFileOutput.Close()
	err = pem.Encode(publicFileOutput, &publicBlock)
	if nil != err {
		return nil, nil, err
	}

	publicFileInput, err := os.Open(path)
	if nil != err {
		return nil, nil, err
	}
	defer publicFileInput.Close()
	publicKeyContent, err := publicFileInput.Stat()
	if nil != err {
		return nil, nil, err
	}

	publicKeyBuffer := make([]byte, publicKeyContent.Size())
	_, err = publicFileInput.Read(publicKeyBuffer)
	if nil != err {
		return nil, nil, err
	}

	go RemovePemFile(path)

	return privateKeyBuffer, publicKeyBuffer, nil
}

func GenerateRandomKeyOfECC() (*ecies.PrivateKey, *ecies.PublicKey, error) {
	randKey := createRandomSalt(55)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(randKey))
	if err != nil {
		return nil, nil, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: privateBytes,
	}

	var path string
	path = "./"
	path += uuid.Must(uuid.NewV4()).String()
	path += "-private.pem"

	privateFileOutput, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	defer privateFileOutput.Close()

	err = pem.Encode(privateFileOutput, &privateBlock)
	if err != nil {
		return nil, nil, err
	}

	privateFileInput, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer privateFileInput.Close()
	privateKeyContent, err := privateFileInput.Stat()
	if err != nil {
		return nil, nil, err
	}
	privateKeyBuffer := make([]byte, privateKeyContent.Size())
	_, err = privateFileInput.Read(privateKeyBuffer)
	if err != nil {
		return nil, nil, err
	}
	privateReaderBlock, _ := pem.Decode(privateKeyBuffer)

	privateKeyBytes, err := x509.ParseECPrivateKey(privateReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyBytes)

	go RemovePemFile(path)

	publicKey := privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: publicBytes,
	}

	path = "./"
	path += uuid.Must(uuid.NewV4()).String()
	path += "-public.pem"

	publicFileOutput, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	defer publicFileOutput.Close()
	err = pem.Encode(publicFileOutput, &publicBlock)
	if err != nil {
		return nil, nil, err
	}

	publicFileInput, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer publicFileInput.Close()
	publicKeyContent, err := publicFileInput.Stat()
	if err != nil {
		return nil, nil, err
	}

	publicKeyBuffer := make([]byte, publicKeyContent.Size())
	_, err = publicFileInput.Read(publicKeyBuffer)
	if err != nil {
		return nil, nil, err
	}

	publicReaderBlock, _ := pem.Decode(publicKeyBuffer)

	publicKeyBytes, err := x509.ParsePKIXPublicKey(publicReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKeyInner := publicKeyBytes.(*ecdsa.PublicKey)
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyInner)

	go RemovePemFile(path)

	return privateKeyECIES, publicKeyECIES, nil
}

func GenerateRandomKeyStringOfECC() (string, string, error) {
	randKey := createRandomSalt(55)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(randKey))
	if err != nil {
		return "", "", err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: privateBytes,
	}

	var path string
	//path = "./"
	path = uuid.Must(uuid.NewV4()).String()
	path += "-private.pem"

	privateFileOutput, err := os.Create(path)
	if err != nil {
		return "", "", err
	}
	defer privateFileOutput.Close()

	err = pem.Encode(privateFileOutput, &privateBlock)
	if err != nil {
		return "", "", err
	}

	privateFileInput, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer privateFileInput.Close()
	privateKeyContent, err := privateFileInput.Stat()
	if err != nil {
		return "", "", err
	}
	privateKeyBuffer := make([]byte, privateKeyContent.Size())
	_, err = privateFileInput.Read(privateKeyBuffer)
	if err != nil {
		return "", "", err
	}

	go RemovePemFile(path)

	publicKey := privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return "", "", err
	}
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: publicBytes,
	}

	//path = "./"
	path = uuid.Must(uuid.NewV4()).String()
	path += "-public.pem"

	publicFileOutput, err := os.Create(path)
	if err != nil {
		return "", "", err
	}
	defer publicFileOutput.Close()
	err = pem.Encode(publicFileOutput, &publicBlock)
	if err != nil {
		return "", "", err
	}

	publicFileInput, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer publicFileInput.Close()
	publicKeyContent, err := publicFileInput.Stat()
	if err != nil {
		return "", "", err
	}

	publicKeyBuffer := make([]byte, publicKeyContent.Size())
	_, err = publicFileInput.Read(publicKeyBuffer)
	if err != nil {
		return "", "", err
	}

	go RemovePemFile(path)

	return string(privateKeyBuffer), string(publicKeyBuffer), nil
}

func GenerateRandomPemOfECC() (string, string, error) {
	randKey := createRandomSalt(55)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(randKey))
	if err != nil {
		return "", "", err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: privateBytes,
	}

	var privatePath string
	//path = "./"
	privatePath = uuid.Must(uuid.NewV4()).String()
	privatePath += "-private.pem"

	privateFileOutput, err := os.Create(privatePath)
	if err != nil {
		return "", "", err
	}
	defer privateFileOutput.Close()

	err = pem.Encode(privateFileOutput, &privateBlock)
	if err != nil {
		return "", "", err
	}

	publicKey := privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return "", "", err
	}
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: publicBytes,
	}

	var publicPath string
	//path = "./"
	publicPath = uuid.Must(uuid.NewV4()).String()
	publicPath += "-public.pem"

	publicFileOutput, err := os.Create(publicPath)
	if err != nil {
		return "", "", err
	}
	defer publicFileOutput.Close()
	err = pem.Encode(publicFileOutput, &publicBlock)
	if err != nil {
		return "", "", err
	}



	return privatePath, publicPath, nil
}

func RemovePemFile(path string){
	for nil != os.Remove(path) {
	}
}

func GetKeyByByteArray(privateKeyBuffer []byte, publicKeyBuffer []byte) (*ecies.PrivateKey, *ecies.PublicKey, error) {
	privateReaderBlock, _ := pem.Decode(privateKeyBuffer)
	privateKeyBytes, err := x509.ParseECPrivateKey(privateReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyBytes)
	publicReaderBlock, _ := pem.Decode(publicKeyBuffer)
	publicKeyBytes, err := x509.ParsePKIXPublicKey(publicReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKeyInner := publicKeyBytes.(*ecdsa.PublicKey)
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyInner)
	return privateKeyECIES, publicKeyECIES, err
}

func GetKeyByString(privateKeyString string, publicKeyString string) (*ecies.PrivateKey, *ecies.PublicKey, error) {
	privateKeyBuffer := []byte(privateKeyString)
	publicKeyBuffer := []byte(publicKeyString)

	privateReaderBlock, _ := pem.Decode(privateKeyBuffer)
	privateKeyBytes, err := x509.ParseECPrivateKey(privateReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyBytes)
	publicReaderBlock, _ := pem.Decode(publicKeyBuffer)
	publicKeyBytes, err := x509.ParsePKIXPublicKey(publicReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKeyInner := publicKeyBytes.(*ecdsa.PublicKey)
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyInner)
	return privateKeyECIES, publicKeyECIES, err
}

func GetKeyByPemFile(privatePath string, publicPath string) (*ecies.PrivateKey, *ecies.PublicKey, error) {
	privateFileInput, err := os.Open(privatePath)
	if nil != err {
		return nil, nil, err
	}
	defer privateFileInput.Close()
	privateKeyContent, err := privateFileInput.Stat()
	if nil != err {
		return nil, nil, err
	}
	privateKeyBuffer := make([]byte, privateKeyContent.Size())
	_, err = privateFileInput.Read(privateKeyBuffer)
	if nil != err {
		return nil, nil, err
	}

	publicFileInput, err := os.Open(publicPath)
	if nil != err {
		return nil, nil, err
	}
	defer publicFileInput.Close()
	publicKeyContent, err := publicFileInput.Stat()
	if nil != err {
		return nil, nil, err
	}

	publicKeyBuffer := make([]byte, publicKeyContent.Size())
	_, err = publicFileInput.Read(publicKeyBuffer)
	if nil != err {
		return nil, nil, err
	}
	privateReaderBlock, _ := pem.Decode(privateKeyBuffer)
	privateKeyBytes, err := x509.ParseECPrivateKey(privateReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyBytes)
	publicReaderBlock, _ := pem.Decode(publicKeyBuffer)
	publicKeyBytes, err := x509.ParsePKIXPublicKey(publicReaderBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKeyInner := publicKeyBytes.(*ecdsa.PublicKey)
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyInner)
	return privateKeyECIES, publicKeyECIES, err
}

func EncryptECC(srcData string, publicKey *ecies.PublicKey) (cryptData string, err error) {

	//公钥加密数据
	encryptBytes, err := ecies.Encrypt(rand.Reader, publicKey, []byte(srcData), nil, nil)
	if err != nil {
		return "", err
	}

	cryptData = hex.EncodeToString(encryptBytes)

	return
}

func DecryptECC(cryptData string, privateKey *ecies.PrivateKey) (srcData string, err error) {

	//私钥解密数据
	cryptBytes, err := hex.DecodeString(cryptData)
	srcByte, err := privateKey.Decrypt(cryptBytes, nil, nil)
	if err != nil {
		fmt.Println("解密错误：", err)
		return "", err
	}
	srcData = string(srcByte)

	return
}

