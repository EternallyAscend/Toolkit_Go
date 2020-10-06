package main

import (
	AmbulandJson "./Json"
	"fmt"
)

func main() {
	AmbulandJson.TestJson()
	str := `{"name": "Course", "website": "https://coursera.com/", "course": ["Golang", "Rust", "JAVA", "C"]}`
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
