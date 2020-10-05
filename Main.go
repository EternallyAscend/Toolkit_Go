package main

import (
	AmbulandJson "./Json"
	"fmt"
)

func main() {
	AmbulandJson.TestJson()
	str := `{"name": "C语言中文网", "website": "http://c.biancheng.net/", "course": ["Golang", "PHP", "JAVA", "C"]}`
	AmbulandJson.ListItemInJson(str)
	fmt.Println("---")
	res, err := AmbulandJson.SearchItemInJson(str, "name")
	if nil != err {
		fmt.Println(err)
	} else {
		fmt.Println(res)
	}
	fmt.Println("---")
	result, err := AmbulandJson.TransferStringToJson(str)
	if nil != err {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
}
