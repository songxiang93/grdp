package main

import (
	"encoding/hex"
	"fmt"
)

const (
	NTLMSSP_NEGOTIATE_56                       = 0x80000000
	NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000
	NTLMSSP_NEGOTIATE_128                      = 0x20000000
	NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
	NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
	NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
	NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000
	NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000
	NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
	NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080
	NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040
	NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020
	NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010
	NTLMSSP_REQUEST_TARGET                     = 0x00000004
	NTLM_NEGOTIATE_OEM                         = 0x00000002
	NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001
)

func main() {
	// 假设这是你的 NTLM 消息的第一部分
	ntlmMessage := "4e544c4d5353500001000000978208e2000000000000000000000000000000000a00ba470000000f"

	// 将 NTLM 消息转换为字节数组
	ntlmBytes, err := hex.DecodeString(ntlmMessage)
	if err != nil {
		fmt.Println("解码错误:", err)
		return
	}

	// NTLM 消息的标志位于字节数组的第 12 到 15 个字节
	flags := uint32(ntlmBytes[15])<<24 | uint32(ntlmBytes[14])<<16 | uint32(ntlmBytes[13])<<8 | uint32(ntlmBytes[12])
	parseNTLMFlags(flags)

	// 定义一些常见的 NTLM 标志

}

// 解析 NTLM 标志字段
func parseNTLMFlags(flags uint32) {
	if flags&NTLMSSP_NEGOTIATE_56 != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_56 is set")
	}
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_KEY_EXCH is set")
	}
	if flags&NTLMSSP_NEGOTIATE_128 != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_128 is set")
	}
	if flags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_VERSION is set")
	}
	if flags&NTLMSSP_NEGOTIATE_TARGET_INFO != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_TARGET_INFO is set")
	}
	if flags&NTLMSSP_REQUEST_NON_NT_SESSION_KEY != 0 {
		fmt.Println("NTLMSSP_REQUEST_NON_NT_SESSION_KEY is set")
	}
	if flags&NTLMSSP_NEGOTIATE_IDENTIFY != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_IDENTIFY is set")
	}
	if flags&NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set")
	}
	if flags&NTLMSSP_TARGET_TYPE_SERVER != 0 {
		fmt.Println("NTLMSSP_TARGET_TYPE_SERVER is set")
	}
	if flags&NTLMSSP_TARGET_TYPE_DOMAIN != 0 {
		fmt.Println("NTLMSSP_TARGET_TYPE_DOMAIN is set")
	}
	if flags&NTLMSSP_NEGOTIATE_ALWAYS_SIGN != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_ALWAYS_SIGN is set")
	}
	if flags&NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED is set")
	}
	if flags&NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED is set")
	}
	if flags&NTLMSSP_NEGOTIATE_NTLM != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_NTLM is set")
	}
	if flags&NTLMSSP_NEGOTIATE_LM_KEY != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_LM_KEY is set")
	}
	if flags&NTLMSSP_NEGOTIATE_DATAGRAM != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_DATAGRAM is set")
	}
	if flags&NTLMSSP_NEGOTIATE_SEAL != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_SEAL is set")
	}
	if flags&NTLMSSP_NEGOTIATE_SIGN != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_SIGN is set")
	}
	if flags&NTLMSSP_REQUEST_TARGET != 0 {
		fmt.Println("NTLMSSP_REQUEST_TARGET is set")
	}
	if flags&NTLM_NEGOTIATE_OEM != 0 {
		fmt.Println("NTLM_NEGOTIATE_OEM is set")
	}
	if flags&NTLMSSP_NEGOTIATE_UNICODE != 0 {
		fmt.Println("NTLMSSP_NEGOTIATE_UNICODE is set")
	}
}
