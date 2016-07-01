package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"unicode"
)

type config struct {
	Dev    string // TUN device name.
	Src    string // Source address
	Dst    string // Destination address
	MaxPay int    // Maximum payload size.
	Key    string // 16, 24 or 32 chars
}

func readConfig(filename string) (*config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf []byte
	if inf, err := f.Stat(); err == nil && inf.Size() > 0 {
		// Preallocate buffer if file size is known.
		buf = make([]byte, 0, inf.Size())
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := bytes.TrimLeftFunc(sc.Bytes(), unicode.IsSpace)
		if len(line) > 0 && line[0] != '#' {
			buf = append(buf, line...)
		}
		buf = append(buf, '\n')
	}
	if err = sc.Err(); err != nil {
		return nil, err
	}
	var cfg config
	d := json.NewDecoder(bytes.NewBuffer(buf))
	d.UseNumber()
	err = d.Decode(&cfg)
	if err != nil {
		if e, ok := err.(*json.SyntaxError); ok {
			return nil, fmt.Errorf(
				"%s:%d %s",
				filename,
				bytes.Count(buf[:e.Offset], []byte{'\n'})+1,
				err.Error(),
			)
		}
		return nil, err
	}
	if cfg.MaxPay <= 0 {
		return nil, errors.New("MaxPay <= 0")
	}
	return &cfg, nil
}
