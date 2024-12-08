package main

import (
	"fmt"
	"unsafe"
)

func main() {
	// 定义一个 16 位整数
	var test uint16 = 0x0102
	// 将整数地址转换为字节数组
	ptr := (*[2]byte)(unsafe.Pointer(&test))

	if ptr[0] == 0x01 {
		fmt.Println("当前系统是大端字节序")
	} else if ptr[0] == 0x02 {
		fmt.Println("当前系统是小端字节序")
	} else {
		fmt.Println("无法确定字节序")
	}
}
