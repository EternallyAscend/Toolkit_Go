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

func generateRandomKeyOfECC() (*ecies.PrivateKey, *ecies.PublicKey, error) {
	randKey := createRandomSalt(40)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(randKey))
	if err != nil {
		return nil, nil, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateBlock := pem.Block {
		Type: "ecc private key",
		Bytes: privateBytes,
	}

	var path string
	path = "./PTD/"
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

	err = os.Remove(path)
	if nil != err {
		return nil, nil, err
	}

	publicKey := privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicBlock := pem.Block {
		Type: "ecc public key",
		Bytes: publicBytes,
	}

	path ="./PTD/"
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

	// Maybe not save or close correctly here.


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

	err = os.Remove(path)
	if nil != err {
		return nil, nil, err
	}

	fmt.Println(privateKeyECIES)
	fmt.Println(publicKeyECIES)

	return privateKeyECIES, publicKeyECIES, nil
}

func getRandomECCKey() (*ecies.PrivateKey, *ecies.PublicKey, error) {
	randKey := createRandomSalt(128)
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), strings.NewReader(randKey))
	if err != nil {
		return nil, nil, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	//fmt.Println(privateBytes)

	//将私钥字符串设置到pem格式块中
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: privateBytes,
	}

	var path string
	path = "./PTD/"
	path += uuid.Must(uuid.NewV4()).String()
	path += "-private.pem"

	//通过pem将设置好的数据进行编码，并写入磁盘文件
	privateFiles, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	defer privateFiles.Close()
	err = pem.Encode(privateFiles, &privateBlock)
	if err != nil {
		return nil, nil, err
	}

	privateFile, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer privateFile.Close()

	fileInfo, err := privateFile.Stat()
	if err != nil {
		return nil, nil, err
	}

	buffer := make([]byte, fileInfo.Size())
	_, err = privateFile.Read(buffer)
	if err != nil {
		return nil, nil, err
	}
	//将得到的字符串解码
	block, _ := pem.Decode(buffer)

	prik, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyForEcies := ecies.ImportECDSA(prik)

	//二、生成公钥文件
	//从得到的私钥对象中将公钥信息取出
	publicKey := privateKey.PublicKey

	//通过x509标准将得到的ecc公钥序列化为ASN.1的DER编码字符串
	publicBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}
	//将公钥字符串设置到pem格式块中
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: publicBytes,
	}

	path = "./PTD/"
	path += uuid.Must(uuid.NewV4()).String()
	path += "-public.pem"

	//通过pem将设置好的数据进行编码，并写入磁盘文件
	publicFiles, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(publicFiles, &publicBlock)
	if err != nil {
		return nil, nil, err
	}

	publicFile, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer publicFile.Close()

	pubfileInfo, err := publicFile.Stat()
	if err != nil {
		return nil, nil, err
	}

	buffers := make([]byte, pubfileInfo.Size())
	_, err = publicFile.Read(buffers)
	if err != nil {
		return nil, nil, err
	}
	//将得到的字符串解码
	blocks, _ := pem.Decode(buffer)

	//使用x509将编码之后的公钥解析出来
	pubInner, err := x509.ParsePKIXPublicKey(blocks.Bytes)
	if err != nil {
		return nil, nil, err
	}

	pubk := pubInner.(*ecdsa.PublicKey)
	publicKeyForEcies := ecies.ImportECDSAPublic(pubk)

	return privateKeyForEcies, publicKeyForEcies, nil
}

func encryptECC(srcData string, publicKey *ecies.PublicKey) (cryptData string, err error) {

	//公钥加密数据
	encryptBytes, err := ecies.Encrypt(rand.Reader, publicKey, []byte(srcData), nil, nil)
	if err != nil {
		return "", err
	}

	cryptData = hex.EncodeToString(encryptBytes)

	return
}

func decryptECC(cryptData string, privateKey *ecies.PrivateKey) (srcData string, err error) {

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

func TestECC() {
	fmt.Println("\nTestECC")

	//privateKey, publicKey, err := getRandomECCKey()
	privateKey, publicKey, err := generateRandomKeyOfECC()
	if nil != err {
		fmt.Println(err)
		return
	}

	//加密前源信息
	srcInfo := "Tom"
	fmt.Println("原文：", srcInfo)

	//加密信息
	cryptData, e := encryptECC(srcInfo, publicKey)
	if e != nil {
		fmt.Println(e)
	}
	fmt.Println("ECIES加密后为：", cryptData)

	//解密信息
	srcData, e := decryptECC(cryptData, privateKey)
	if e != nil {
		fmt.Println(e)
	}
	fmt.Println("ECIES解密后为：", srcData)

}

func GenerateECCKey(c elliptic.Curve, privatePath, publicPath string) {
	// 生成密钥
	privateKey, _ := ecdsa.GenerateKey(c, rand.Reader)
	// 保存密钥
	// x509编码
	x509PrivateKey, _ := x509.MarshalECPrivateKey(privateKey)

	fmt.Println()
	fmt.Print(x509PrivateKey)
	fmt.Println(len(x509PrivateKey))

	//pem编码编码
	block := pem.Block{
		Type:  "ecc private key",
		Bytes: x509PrivateKey,
	}

	//保存到文件中
	privateFile, _ := os.Create(privatePath)
	pem.Encode(privateFile, &block)

	defer privateFile.Close()

	////////////////////保存公钥//////////////////////
	// x509编码
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	// pem编码
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: x509PublicKey,
	}

	fmt.Println()
	fmt.Print(x509PublicKey)
	fmt.Println(len(x509PublicKey))

	publicFile, _ := os.Create(publicPath)
	defer publicFile.Close()

	pem.Encode(publicFile, &publicBlock)
}

func initECCKey() ([]byte, []byte) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	x509PrivateKey, _ := x509.MarshalECPrivateKey(privateKey)
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	return x509PrivateKey, x509PublicKey
}

func testGenECC() {
	GenerateECCKey(elliptic.P521(), "eccPri.pem", "eccPub.pem")
}