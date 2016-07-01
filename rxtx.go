package main

import (
	"crypto/rand"
	"io"
	"log"
	"net"
	"os"
	"syscall"
)

func checkNetErr(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*net.OpError); ok {
		if e, ok := e.Err.(*os.SyscallError); ok &&
			e.Err == syscall.ECONNREFUSED {

			return true
		}
	}
	log.Fatal("Network error: ", err)
	panic(nil)
}

const headerLen = 8 + 1 + 1 + 2

type header struct {
	Id      uint64 // Schould have a random initial value.
	FragN   byte
	FargNum byte
	Length  uint16
}

func (h *header) Encode(buf []byte) {
	id := h.Id
	for i := 0; i < 8; i++ {
		buf[i] = byte(id & 0xff)
		id >>= 8
	}
	buf[8] = h.FragN
	buf[9] = h.FragNum
	buf[10] = byte(h.Length & 0xff)
	buf[11] = byte(h.Length >> 8)
}

func tunRead(tun io.Reader, con io.Writer, cfg *config) {
	buf := make([]byte, 8192)
	_, err := rand.Read(buf[:8])
	checkErr(err)
	var h header
	for _, b := range buf[:8] {
		h.Id = h.Id<<8 | uint64(b)
	}
	encr := make([]byte, headerLen+cfg.MaxPay+2*blockCipher.Size())
	blkMask := blockCipher.Size() - 1 // BUG?: Assumes that size is power of two.
	for {
		n, err := tun.Read(buf[headerLen:])
		checkErr(err)
		pkt := buf[:headerLen+n]

		h.FragNum = (n + cfg.MaxPay - 1) / cfg.MaxPay

		pktLen := (n/h.FragNum + headerLen + blkMask) &^ blkMask
		payLen := pktLen - headerLen

		for h.FragN = 0; h.FragN < h.FragNum; h.FragN++ {
			h.Lenght = payLen
			h.Encode(pkt)

			copy(encr, pkt[:pktLen])

			_, err := con.Write(encr[:pktLen])
			if checkNetErr(err) {
				break
			}

			pkt = pkt[payLen:]
			if len(pkt) < pktLen {
				pktLen = len(pkt)
				payLen = pktLen - headerLen
				pktLen = (pktLen + blkMask) &^ blkMask
			}
		}
		id++
	}
}

func getMTU(iname string) int {
	dev, err := net.InterfaceByName(iname)
	checkErr(err)
	return dev.MTU
}

func tunWrite(tun io.Writer, con io.Reader, cfg *config) {
	mtu := getMTU(cfg.Dev)
	log.Printf("%s MTU is %d bytes.", cfg.Dev, mtu)
	buf := make([]byte, 8192)
	for {
		n, err := con.Read(buf)
		checkNetErr(err)
		switch {
		case n >= headerLen+20:
			for {
				_, err := tun.Write(buf[:n])
				if pathErr, ok := err.(*os.PathError); ok &&
					pathErr.Err == syscall.EINVAL {

					log.Printf("%s: Invalid IP datagram.\n", cfg.Dev)
					break
				}
				checkErr(err)
			}
		case n > 0:
			log.Printf("%s: Received packet is to short.", cfg.Dev)
		}
	}
}
