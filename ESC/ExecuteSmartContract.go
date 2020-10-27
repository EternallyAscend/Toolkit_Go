package ESC

type SmartContractCommand struct {
	method string
	args   []string
}

func GenerateSmartContractCommand(scc *SmartContractCommand, method string) {
	scc = &SmartContractCommand{
		method: method,
		args:   []string{},
	}
}

func ModifyMethodSmartContractCommand(scc *SmartContractCommand, newMethod string) {
	scc.method = newMethod
}

func SetArgsForSmartContractCommand(scc *SmartContractCommand, args []string) {
	scc.args = args
}

func GetCommandOfSmartContractCommand(scc *SmartContractCommand) string {
	var command string
	command = "'{\"args\":[\""
	command += scc.method
	for arg := range scc.args {
		command += "\", \""
		command += scc.args[arg]
	}
	command += "\"]}'"
	return command
}
