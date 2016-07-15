package main

import (
	"log"
	"time"
)

func checkErr(err error) {
	if err == nil {
		return
	}
	log.Fatal(err)
}

var start = time.Now()

func nanosec() int64 {
	return int64(time.Now().Sub(start))
}
