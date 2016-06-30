package main

import (
	"log"
)

func checkErr(err error) {
	if err == nil {
		return
	}
	log.Fatal(err)
}
