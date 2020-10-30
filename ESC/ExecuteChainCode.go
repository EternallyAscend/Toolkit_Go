package ESC

import (
	AmbulandSSH "../SSH"
	"errors"
)

func GetAuthority(userId string, targetServer string, targetPort int, targetUser string, targetPassword string,
				  smartContract *SmartContract) (string, error) {
	command := "peer chaincode invoke -o "
	command += smartContract.domain
	command += ":"
	command += smartContract.port
	command += " -C "
	command += smartContract.channel
	command += " -n "
	command += smartContract.smartContractName
	command += "-v"
	command += smartContract.smartContractVersion
	command += " -c "
	command += "'{\"Args:\":[\"invoke\",\"getAuthority\",\""
	command += userId
	command += "\"]}'"
	authority, err := AmbulandSSH.Execute(command, targetUser, targetPassword, targetServer, targetPort)
	if "" != err {
		return authority, errors.New(err)
	} else {
		return authority, nil
	}
}

func GetPublicKey(userId string, targetServer string, targetPort int, targetUser string, targetPassword string,
				  smartContract *SmartContract) (string, error) {
	command := "peer chaincode invoke -o "
	command += smartContract.domain
	command += ":"
	command += smartContract.port
	command += " -C "
	command += smartContract.channel
	command += " -n "
	command += smartContract.smartContractName
	command += "-v"
	command += smartContract.smartContractVersion
	command += " -c "
	command += "'{\"Args:\":[\"invoke\",\"getPublicKey\",\""
	command += userId
	command += "\"]}'"
	authority, err := AmbulandSSH.Execute(command, targetUser, targetPassword, targetServer, targetPort)
	if "" != err {
		return authority, errors.New(err)
	} else {
		return authority, nil
	}
}

func GetPrivateKey(userId string, targetServer string, targetPort int, targetUser string, targetPassword string,
				   smartContract *SmartContract) (string, error) {
	command := "peer chaincode invoke -o "
	command += smartContract.domain
	command += ":"
	command += smartContract.port
	command += " -C "
	command += smartContract.channel
	command += " -n "
	command += smartContract.smartContractName
	command += "-v"
	command += smartContract.smartContractVersion
	command += " -c "
	command += "'{\"Args:\":[\"invoke\",\"getPrivateKey\",\""
	command += userId
	command += "\"]}'"
	authority, err := AmbulandSSH.Execute(command, targetUser, targetPassword, targetServer, targetPort)
	if "" != err {
		return authority, errors.New(err)
	} else {
		return authority, nil
	}
}
