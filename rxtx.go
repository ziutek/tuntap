package main

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
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

type header struct {
	Id      uint32 // Schould have a random initial value.
	FragN   byte
	FragNum byte
	Len     uint16
}

const headerLen = 8

func (h *header) Encode(buf []byte) {
	id := h.Id
	buf[0] = byte(id)
	buf[1] = byte(id >> 8)
	buf[2] = byte(id >> 16)
	buf[3] = byte(id >> 24)
	buf[4] = h.FragN
	buf[5] = h.FragNum
	buf[6] = byte(h.Len & 0xff)
	buf[7] = byte(h.Len >> 8)
}

func (h *header) Decode(buf []byte) {
	h.Id = uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	h.FragN = buf[4]
	h.FragNum = buf[5]
	h.Len = uint16(buf[6]) | uint16(buf[7])<<8
}

func blkAlignUp(n int) int {
	return (n + blkMask) &^ blkMask
}

func tunRead(tun io.Reader, con io.Writer, cfg *config) {
	buffer := make([]byte, 8192)
	var h header

	// Initialize h.Id to random number.
	_, err := rand.Read(buffer[:8])
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
			//copy(pkt, buf[:usedLen]) // Encrypt here.

			atomic.StoreUint32(&active, 1)
			_, err := con.Write(pkt[:pktLen])
			if checkNetErr(err) {
				break
			}
			buf = buf[payLen:]
		}
		h.Id++
	}
}

/*func getMTU(iname string) int {
	dev, err := net.InterfaceByName(iname)
	checkErr(err)
	return dev.MTU
}*/

type defrag struct {
	Id    uint32
	Frags [][]byte
}

func tunWrite(tun io.Writer, con io.Reader, cfg *config) {
	buf := make([]byte, 8192)
	dtab := make([]*defrag, 3)
	for i := range dtab {
		dtab[i] = &defrag{Frags: make([][]byte, 0, (8192+cfg.MaxPay-1)/cfg.MaxPay)}
	}
	var h header
	for {
		n, err := con.Read(buf)
		checkNetErr(err)
		switch {
		case n == 0:
			// Hello packet
		case n < headerLen+20:
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
						log.Printf("%s: Header do not match previous fragment.", cfg.Dev)
						continue
					}
					cur.Id = h.Id
					cur.Frags = cur.Frags[:h.FragNum]
				}
				if h.FragN >= h.FragNum {
					log.Printf("%s: Bad header (FragN >= FragNum).", cfg.Dev)
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
			_, err := tun.Write(buf[headerLen:n])
			if pathErr, ok := err.(*os.PathError); ok &&
				pathErr.Err == syscall.EINVAL {

				log.Printf("%s: Invalid IP datagram.\n", cfg.Dev)
				break
			}
			checkErr(err)
		}
	}
}
