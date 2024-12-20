package main

import (
	"fmt"
	"time"
)

type Person interface {
	Run()
}

type Stu struct {
	name string
	age  int
}
type Tea struct {
	name string
	age  int
}

func (stu *Stu) Run() {
	fmt.Println("stu run")
}
func (tea *Tea) Run() {
	fmt.Println("tea run")
}

func main() {
	s1 := Stu{"aa", 1}
	s2 := Stu{"bb", 2}

	s3 := Stu{"aa", 1}

	switch s3 {
	case s1:
		fmt.Println("s1")
	case s2:
		fmt.Println("s2")

	default:
		fmt.Println("no")
	}
	var p Person = &s1
	switch p.(type) {
	case *Stu:
		fmt.Println("stu")
	case *Tea:
		fmt.Println("tea")
	}
	intChan := make(chan int)
	go func() {

		time.Sleep(time.Second * 5)
		intChan <- 5

	}()

	t := time.After(time.Second * 10)
	var a int
loop:
	for {
		select {
		case <-t:
			fmt.Println("超时")
			return
		case a = <-intChan:
			break loop

		}
	}
	fmt.Println(a)

	time.Sleep(1000)
}
