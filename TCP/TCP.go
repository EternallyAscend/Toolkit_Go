package TCP

import (
	"fmt"
	"net"
	"strconv"
)

func ExecTCP(port int) ([]string, error) {
	return nil, nil
}

type request struct{
	ip string
	command byte
	authorID string
	parameter string
}

func (re *request)init(ip string,message string) bool {
	commendLength := 6
	authorIDLength := 64
	re.ip = ip
	if len(message) < commendLength+authorIDLength{
		return false
	}
	switch message[0:commendLength] {
	case "Verify":
		re.command = 1
		break
	case "Query ":
		re.command = 2
		break
	case "Write ":
		re.command = 3
		break
	default:
		re.command=0
		return false
	}
	re.authorID = message[commendLength:commendLength+authorIDLength]
	re.parameter = message[commendLength+authorIDLength:len(message)]
	return true
}

type userServer struct{
	portNum uint
}

func (us *userServer)start(port string) {
	if us.portNum > 1000{
		fmt.Println("Too many socket running.")
		return
	}
	listen_socket, error := net.Listen("tcp", port)
	defer listen_socket.Close()
	if error != nil {
		fmt.Printf("Socket Running Error at %s.\n", port)
		return
	}
	us.portNum++
	for{
		message := ""
		connect, err := listen_socket.Accept()
		defer connect.Close()
		if err != nil{
			fmt.Println("Client Connect Error.")
			continue
		}
		fmt.Printf("Connect to %s.\n",connect.RemoteAddr().String())
		data := make([]byte, 255)
		msg_read, err := connect.Read(data)
		if msg_read == 0 || err != nil {
			fmt.Println("Read error.")
		} else {
			message = string(data[0:msg_read])
		}

		if message=="" {
			continue
		}
		ip:=connect.RemoteAddr().String()
		for cursor := 0; cursor < len(ip); cursor++ {
			if ip[cursor] == ':' {
				ip = ip[0:cursor]
				break
			}
		}
		fmt.Println(ip)
		for cursor:=0; cursor<len(message); cursor++ {
			if message[cursor] == ';' {
				ip += ":"
				ip += message[0:cursor]
				message = message[(cursor+1):len(message)]
				break
			}
		}
		fmt.Println(ip)
		re := &request{
			ip:        "",
			command:   0,
			authorID:  "",
			parameter: "",
		}
		result := re.init(ip, message)
		if !result {
			fmt.Printf("Client Send a Wrong Message at %s.\n", connect.RemoteAddr())
			connect.Write([]byte("Error - Wrong Message."))
			continue
		}
		connect.Write([]byte(ip))
		// us.request_queue.insert(re)
		go us.deal(re)
	}

}

func (us *userServer)deal(re *request) {
	var message string
	message = ""
	message += strconv.Itoa(int(re.command))
	message += re.authorID
	message += re.parameter
	go us.returnInfo(re.ip, message)
}

func (us *userServer)returnInfo(ip string,data string) {
	fmt.Printf("Start Transport to %s.\n", ip)
	connect,err:=net.Dial("tcp", ip)
	defer connect.Close()
	if err != nil {
		fmt.Printf("Return failed to ip %s.", ip)
		return
	}
	connect.Write([]byte(data))
	fmt.Printf("Finished Wirte to %s.\n", ip)
}

func TestTCP() {
	us := &userServer{
		portNum: 0,
	}
	us.start(":9000")
	us.start("10000")
}
