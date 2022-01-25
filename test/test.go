package test

import "fmt"

type Test struct {
}

//Test is a test function
func (t *Test) Test() {
	fmt.Println("This is test function")
}
