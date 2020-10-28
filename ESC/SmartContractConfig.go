package ESC

type SmartContract struct {
	domain string
	port string
	channel string
	smartContractName string
	smartContractVersion string
}

func ConfigSmartContract(domain, port, channel, name, version string) *SmartContract {
	smartContract := &SmartContract{
		domain:               domain,
		port:                 port,
		channel:              channel,
		smartContractName:    name,
		smartContractVersion: version,
	}
	return smartContract
}
