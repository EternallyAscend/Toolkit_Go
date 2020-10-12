package SSH

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func Exec(command string) (string, error) {
	fmt.Println(command)
	return "", nil
}

//	You can use these code to download the package 'golang.org/x/crypto/ssh'.
//	mkdir -p $GOPATH/src/golang.org/x/
//	cd $GOPATH/src/golang.org/x/
//	git clone https://github.com/golang/crypto.git

// Connect to SSH with primary key not password.
func connectSSH(username string, ip string, port int, command string) (string, error) {
	if 22 != port {
		return "Wrong Port", nil
	}
	link := username + "@" + ip
	cmd := exec.Command("ssh", link, command)
	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	err := cmd.Run()
	if nil != err {
		fmt.Printf("cmd exec failed: %s : %s", fmt.Sprint(err), stdErr.String())
	}
	ret, err := strconv.Atoi(strings.Replace(stdOut.String(), "\n", "", -1))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d, %s\n", ret, stdErr.String())
	return stdOut.String(), err
}

// Connect to SSH with password.
func SSHConnect(user, password, host string, port int) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	hostKeyCallbk := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	clientConfig = &ssh.ClientConfig{
		User: user,
		Auth: auth,
		// Timeout:             30 * time.Second,
		HostKeyCallback: hostKeyCallbk,
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

func Execute(command string, user string, password string, host string, port int) (string, string) {

	var stdOut, stdErr bytes.Buffer

	session, err := SSHConnect(user, password, host, port)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	session.Stdout = &stdOut
	session.Stderr = &stdErr

	session.Run(command)

	fmt.Print(stdErr.String())
	fmt.Print(stdOut.String())
	return stdOut.String(), stdErr.String()
}
