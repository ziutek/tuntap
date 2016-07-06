package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	blkCipher cipher.Block
	blkMask   int
	iv        []byte
)

func main() {
	if len(os.Args) != 2 {
		os.Stderr.WriteString("Usage: tuntap CONFIG_FILE\n")
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

	// Header has 64 bit counter with random initial value so use
	// constant initial vector (iv) should not be too much harm for CBC.
	iv = make([]byte, blkCipher.BlockSize())

	// BlockSize must be power of two.
	blkMask = blkCipher.BlockSize() - 1

	copy(ifr.name[:], cfg.Dev)
	if cfg.TAP {
		ifr.flags = IFF_TAP | IFF_NO_PI
	} else {
		ifr.flags = IFF_TUN | IFF_NO_PI
	}

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

	laddr, err := net.ResolveUDPAddr("udp", cfg.Local)
	checkErr(err)
	con, err := net.ListenUDP("udp", laddr)
	checkErr(err)

	var raddr *net.UDPAddr
	if cfg.Remote != "" {
		raddr, err = net.ResolveUDPAddr("udp", cfg.Remote)
		checkErr(err)
	}

	log.Printf("%s: Local: %v, remote: %v.", cfg.Dev, con.LocalAddr(), raddr)

	var rac chan *net.UDPAddr

	if raddr == nil {
		rac = make(chan *net.UDPAddr, 1)
	} else if cfg.Hello > 0 {
		go hello(con, raddr, int64(cfg.Hello))
	}

	go senderUDP(tun, con, cfg, raddr, rac)
	receiverUDP(tun, con, cfg, rac)
}
