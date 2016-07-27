package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

func checkNetErr(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*net.OpError); ok {
		if e, ok := e.Err.(*os.SyscallError); ok {
			switch e.Err {
			case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
				return true
			}
		}
	}
	log.Fatal("Network error: ", err)
	panic(nil)
}

type header struct {
	Id      uint64 // Schould have a random initial value.
	FragN   byte
	FragNum byte
	Len     uint16
}

const (
	headerLen = 12
	idLen     = 8
)

func (h *header) Encode(buf []byte) {
	id := h.Id
	buf[0] = byte(id)
	buf[1] = byte(id >> 8)
	buf[2] = byte(id >> 16)
	buf[3] = byte(id >> 24)
	buf[4] = byte(id >> 32)
	buf[5] = byte(id >> 40)
	buf[6] = byte(id >> 48)
	buf[7] = byte(id >> 56)
	buf[8] = h.FragN
	buf[9] = h.FragNum
	buf[10] = byte(h.Len)
	buf[11] = byte(h.Len >> 8)
}

func (h *header) Decode(buf []byte) {
	h.Id = uint64(buf[0]) | uint64(buf[1])<<8 |
		uint64(buf[2])<<16 | uint64(buf[5])<<24 |
		uint64(buf[4])<<32 | uint64(buf[3])<<40 |
		uint64(buf[6])<<48 | uint64(buf[7])<<56
	h.FragN = buf[8]
	h.FragNum = buf[9]
	h.Len = uint16(buf[10]) | uint16(buf[11])<<8
}

func blkAlignUp(n int) int {
	return (n + blkMask) &^ blkMask
}

var lastSent int64

func senderUDP(tun io.Reader, con *net.UDPConn, cfg *config, raddr *net.UDPAddr, rac <-chan *net.UDPAddr) {
	buffer := make([]byte, 8192)
	var h header

	// Initialize h.Id to random number.
	_, err := rand.Read(buffer[:idLen])
	checkErr(err)
	h.Decode(buffer)

	pkt := make([]byte, headerLen+cfg.MaxPay+2*blkCipher.BlockSize())
	for {
		buf := buffer
		n, err := tun.Read(buf[headerLen:])
		checkErr(err)
		if n == 0 {
			continue
		}

		h.FragNum = byte((n + cfg.MaxPay - 1) / cfg.MaxPay)

		// Calculate lengths to equally fill all h.FragNum packets.
		payLen := (n + int(h.FragNum) - 1) / int(h.FragNum)
		usedLen := headerLen + payLen
		pktLen := blkAlignUp(usedLen)

		buf = buf[:n+headerLen]

		for h.FragN = 0; h.FragN < h.FragNum; h.FragN++ {
			if len(buf) < usedLen {
				usedLen = len(buf)
				payLen = usedLen - headerLen
				pktLen = blkAlignUp(usedLen)
			}
			h.Len = uint16(payLen)
			h.Encode(buf)

			cipher.NewCBCEncrypter(blkCipher, iv).CryptBlocks(pkt, buf[:pktLen])

			if rac != nil {
				select {
				case raddr = <-rac:
					log.Printf("%s: Remote address changed to %v.", cfg.Dev, raddr)
				default:
				}
			}
			if raddr == nil {
				break
			}
			if cfg.Hello > 0 {
				atomic.StoreInt64(&lastSent, nanosec())
			}
			_, err := con.WriteToUDP(pkt[:pktLen], raddr)
			if checkNetErr(err) {
				break
			}
			buf = buf[payLen:]
		}
		h.Id++
	}
}

func hello(con *net.UDPConn, raddr *net.UDPAddr, hello time.Duration) {
	buf := make([]byte, blkAlignUp(headerLen+idLen))
	var h header
	// Initialize h.Id to random number.
	_, err := rand.Read(buf[:idLen])
	checkErr(err)
	h.Decode(buf)
	h.Len = idLen
	for {
		last := atomic.LoadInt64(&lastSent)
		now := nanosec()
		idle := now - last
		wait := hello - time.Duration(idle)
		if wait <= 0 {
			h.Encode(buf)
			copy(buf[headerLen:], buf[:idLen])
			cipher.NewCBCEncrypter(blkCipher, iv).CryptBlocks(buf, buf)
			_, err := con.WriteToUDP(buf, raddr)
			checkNetErr(err)
			h.Id++
			atomic.StoreInt64(&lastSent, now)
			wait = hello
		}
		time.Sleep(wait)
	}
}

type defrag struct {
	Id    uint64
	Frags [][]byte
}

var lastRecv int64

func receiverUDP(tun io.Writer, con *net.UDPConn, cfg *config, rac chan<- *net.UDPAddr) {
	buf := make([]byte, 8192)
	dtab := make([]*defrag, 3)
	for i := range dtab {
		dtab[i] = &defrag{Frags: make([][]byte, 0, (8192+cfg.MaxPay-1)/cfg.MaxPay)}
	}
	var (
		h   header
		pra = new(net.UDPAddr)
	)
	for {
		var (
			n     int
			err   error
			raddr *net.UDPAddr
		)
		if rac == nil {
			n, err = con.Read(buf)
		} else {
			n, raddr, err = con.ReadFromUDP(buf)
		}
		if checkNetErr(err) {
			continue
		}

		switch {
		case n < headerLen+idLen:
			log.Printf("%s: Received packet is to short.", cfg.Dev)
		case n&blkMask != 0:
			log.Printf(
				"%s: Received packet length %d is not multiple of block size %d.",
				cfg.Dev, n, blkCipher.BlockSize(),
			)
		default:
			cipher.NewCBCDecrypter(blkCipher, iv).CryptBlocks(buf, buf)
			h.Decode(buf)

			pktLen := blkAlignUp(headerLen + int(h.Len))
			if n != pktLen {
				log.Printf("%s: Bad packet size: %d != %d.", cfg.Dev, n, pktLen)
				continue
			}
			if h.FragNum == 0 {
				// Hello packet.
				if h.Len != idLen ||
					!bytes.Equal(buf[:idLen], buf[headerLen:headerLen+idLen]) {

					log.Printf("%s: Bad hello packet.", cfg.Dev)
					continue
				}
				if cfg.LogDown > 0 {
					atomic.StoreInt64(&lastRecv, nanosec())
				}
				break
			}
			if h.FragN >= h.FragNum {
				log.Printf("%s: Bad header (FragN >= FragNum).", cfg.Dev)
				continue
			}
			if cfg.LogDown > 0 {
				atomic.StoreInt64(&lastRecv, nanosec())
			}
			if h.FragNum > 1 {
				var (
					cur *defrag
					cn  int
				)
				for i, d := range dtab {
					if d.Id == h.Id {
						cur = d
						cn = i
						break
					}
				}
				if cur == nil {
					cur = dtab[len(dtab)-1]
					copy(dtab[1:], dtab)
					dtab[0] = cur
				}
				if len(cur.Frags) != int(h.FragNum) {
					if len(cur.Frags) != 0 {
						log.Printf(
							"%s: Header do not match previous fragment.",
							cfg.Dev,
						)
						continue
					}
					cur.Id = h.Id
					cur.Frags = cur.Frags[:h.FragNum]
				}
				frag := cur.Frags[h.FragN]
				if frag == nil {
					frag = make([]byte, 0, cfg.MaxPay)
				}
				frag = frag[:h.Len]
				cur.Frags[h.FragN] = frag
				copy(frag, buf[headerLen:])
				for _, frag = range cur.Frags {
					if len(frag) == 0 {
						// Found lack of fragment.
						break
					}
				}
				if len(frag) == 0 {
					// Lack of some fragment.
					continue
				}
				// All fragments received.
				n = headerLen
				for i, frag := range cur.Frags {
					n += copy(buf[n:], frag)
					cur.Frags[i] = frag[:0]
				}
				cur.Frags = cur.Frags[:0]
				copy(dtab[cn:], dtab[cn+1:])
				dtab[len(dtab)-1] = cur
			}
			_, err = tun.Write(buf[headerLen:n])
			if err != nil {
				if pathErr, ok := err.(*os.PathError); ok &&
					pathErr.Err == syscall.EINVAL {

					log.Printf("%s: Invalid IP datagram.", cfg.Dev)
					continue
				}
				checkErr(err)
			}
		}
		// Received correct Hello packet or TUN/TAP payload.
		if rac != nil && (!pra.IP.Equal(raddr.IP) || pra.Port != raddr.Port) {
			// Inform senderUDP about remote address.
			select {
			case rac <- raddr:
				pra = raddr
			default:
			}
		}
	}
}

func logUpDown(dev string, logDown time.Duration) {
	atomic.StoreInt64(&lastRecv, nanosec()-int64(logDown))
	var up bool
	for {
		last := atomic.LoadInt64(&lastRecv)
		now := nanosec()
		idle := now - last
		wait := logDown - time.Duration(idle)
		if wait <= 0 {
			if up {
				log.Printf("%s: Remote is down.", dev)
				up = false
			}
			wait = logDown / 4
		} else {
			if !up {
				log.Printf("%s: Remote is up.", dev)
				up = true
			}
		}
		time.Sleep(wait)
	}
}
