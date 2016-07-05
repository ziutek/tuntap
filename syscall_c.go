package main

/*
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
*/
import "C"

const (
	IFF_TUN   = C.IFF_TUN
	IFF_TAP   = C.IFF_TAP
	IFF_NO_PI = C.IFF_NO_PI
	TUNSETIFF = C.TUNSETIFF
)

type ifreq struct {
	name  [C.IFNAMSIZ]byte
	flags uint16
	_     [C.IFNAMSIZ - 2]byte
}
