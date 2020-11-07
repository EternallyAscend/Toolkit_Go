package CSR
import (
	AmbulandAES "../AES"
	"errors"
	uuid "github.com/satori/go.uuid"
)

type Result struct {
	Uuid 	   string
	key  	   string
	JsonString string
}

func TransferResultStringToJsonString(input string) (string, error) {
	if 32 > len(input) {
		return "", errors.New("Wrong Input From Client. ")
	}
	request := &Result{
		Uuid:       "",
		key:        "",
		JsonString: "",
	}
	var cursor int
	cursor = 0
	for ; cursor < 31; cursor += 2 {
		request.Uuid += input[cursor : cursor+1]
		request.key += input[cursor+1 : cursor+2]
	}
	println(request.key)
	println(input)
	println(input[32:])
	information := string(AmbulandAES.DecryptAES([]byte(input[32:]), []byte(request.key)))
	request.JsonString = information
	return request.JsonString, nil
}

func AutoAddHeaderBeforeRequestByAES(typeCode string, info string) (string, error) {
	randomId := uuid.Must(uuid.NewV4()).String()[0:16]
	randomKey := uuid.Must(uuid.NewV4()).String()[0:16]
	var result string
	result = ""
	var cursor int
	cursor = 0
	for ; cursor < 16; cursor++ {
		result += randomId[cursor : cursor+1]
		result += randomKey[cursor : cursor+1]
	}
	println(randomId)
	println(randomKey)
	println(typeCode)
	println(info)
	result += "-"
	result += typeCode
	result += "-"
	information := string(AmbulandAES.EncryptAES([]byte(info), []byte(randomKey)))
	result += information
	println(result)
	println(string(AmbulandAES.DecryptAES([]byte(information), []byte(randomKey))))
	return result, nil
}
