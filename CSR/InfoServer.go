package CSR

import (
	AmbulandAES "../AES"
	"errors"
	"fmt"
	uuid "github.com/satori/go.uuid"
)

type Request struct {
	Uuid       string
	key        string
	TypeCode   string
	JsonString string
}

func TransferStringToRequest(input string) (*Request, error) {
	if 35 > len(input) {
		return nil, errors.New("Wrong Input From Client. ")
	}
	request := &Request{
		Uuid:       "",
		key:        "",
		TypeCode:   "",
		JsonString: "",
	}
	var cursor int
	cursor = 0
	for ; cursor < 31; cursor += 2 {
		request.Uuid += input[cursor : cursor+1]
		request.key += input[cursor+1 : cursor+2]
	}
	request.TypeCode = input[33:34]
	fmt.Println(request.key)
	fmt.Println(input[35:])
	information := string(AmbulandAES.DecryptAES([]byte(input[35:]), []byte(request.key)))
	request.JsonString = information
	return request, nil
}

func AutoAddHeaderBeforeReturnByAES(info string) (string, error) {
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
	information := AmbulandAES.EncryptAES([]byte(info), []byte(randomKey))
	result += string(information)
	println(randomKey)
	println(info)
	println(string(information))
	return result, nil
}
