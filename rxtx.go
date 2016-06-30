package main

import (
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

func tunRead(tun io.Reader, con io.Writer, cfg *config) {
	buf := make([]byte, 8192)
	for {
		n, er := tun.Read(buf)
		m := (n + cfg.MaxPay - 1) / cfg.MaxPay
		siz := n / m
		for i := 0; i < n; i += siz {
			if n-i < siz {
				siz = n - i
			}
			_, err := con.Write(buf[i : i+siz])
			if checkNetErr(err) {
				break
			}
		}
		checkErr(er)

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
		n, er := con.Read(buf)
		if n > 0 {
			_, err := tun.Write(buf[:n])
			checkErr(err)
		}
		checkNetErr(er)
	}

}
