package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	blkCipher cipher.Block
	blkMask   int
	iv        []byte
	active    uint32
)

func main() {
	if len(os.Args) != 2 {
		os.Stderr.WriteString("Usage: tun CONFIG_FILE\n")
		os.Exit(1)
	}
	cfg, err := readConfig(os.Args[1])
	checkErr(err)
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	checkErr(err)

	var ifr ifreq

	if len(cfg.Dev) >= len(ifr.name) {
		log.Fatalf("Device name %s is too long.", cfg.Dev)
	}

	blkCipher, err = aes.NewCipher([]byte(cfg.Key))
	checkErr(err)
	
	// Header has 32 bit counter with random initial value so use empty
	// constant initial vector should not be too much harm for CBC.
	iv = make([]byte, blkCipher.BlockSize()) 
	
	// BlockSize must be power of two.
	blkMask = blkCipher.BlockSize() - 1

	copy(ifr.name[:], cfg.Dev)
	ifr.flags = IFF_TUN | IFF_NO_PI

	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		tun.Fd(),
		TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if e != 0 {
		log.Fatalf("Can not allocate %s device: %v.", cfg.Dev, e)
	}

	cfg.Dev = string(ifr.name[:bytes.IndexByte(ifr.name[:], 0)])

	log.Printf("Using %s device.", cfg.Dev)

	saddr, err := net.ResolveUDPAddr("udp", cfg.Src)
	checkErr(err)
	daddr, err := net.ResolveUDPAddr("udp", cfg.Dst)
	checkErr(err)
	con, err := net.DialUDP("udp", saddr, daddr)
	checkErr(err)

	if cfg.Hello > 0 {
		go hello(con, time.Duration(cfg.Hello)*time.Second)
	}
	go tunRead(tun, con, cfg)
	tunWrite(tun, con, cfg)
}

func hello(con io.Writer, hello time.Duration) {
	for {
		if atomic.SwapUint32(&active, 0) == 0 {
			_, err := con.Write(nil)
			checkNetErr(err)
		}
		time.Sleep(hello)
	}
}
