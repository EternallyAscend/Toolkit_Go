package ISP

import (
	AmbulandCSR "../CSR"
	"fmt"
	"net"
)

// InfoServer Package, to Client.

// Execute Function return string, error; input *AmbulandCSR.Request.
func DealRequestFromClient(command string, execute func(request *AmbulandCSR.Request)(string, error)) (string, error) {
	request, err := AmbulandCSR.TransferStringToRequest(command)
	if nil != err {
		return "", err
	}
	info, err := execute(request)
	if nil != err {
		return "", err
	}
	info, err = AmbulandCSR.AutoAddHeaderBeforeReturnByAES(info)
	if nil != err {
		return "", err
	}
	return info, nil
}

func ListenRequestFromClientAndDeal(port string, execute func(request *AmbulandCSR.Request)(string, error)) {
	listen, err := net.Listen("tcp", port)
	if nil != err {
		fmt.Println(err.Error())
		fmt.Printf("Socket Running Error at %s.\n", port)
		return
	}
	defer listen.Close()
	for {
		message := ""
		connect, err := listen.Accept()
		if err != nil {
			fmt.Println("Client Connect Error.")
			continue
		}
		fmt.Printf("Connect to %s.\n", connect.RemoteAddr().String())
		data := make([]byte, 255)
		length, err := connect.Read(data)
		if length == 0 || err != nil {
			fmt.Println("Read error.")
		} else {
			message = string(data[0:length])
		}

		if message == "" {
			connect.Write([]byte("Empty request."))
			connect.Close()
			continue
		}
		ip := connect.RemoteAddr().String()
		for cursor := 0; cursor < len(ip); cursor++ {
			if ip[cursor] == ':' {
				ip = ip[0:cursor]
				break
			}
		}
		fmt.Println(message)
		message, err = DealRequestFromClient(message, execute)
		if nil != err {
			connect.Write([]byte(err.Error()))
			connect.Close()
			continue
		}
		connect.Write([]byte(message))
		connect.Close()
	}
}
