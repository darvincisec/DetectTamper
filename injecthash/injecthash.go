// Copyright (c) 2017, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// Most of the below code are taken from
// https://github.com/google/boringssl/blob/master/util/fipstools/inject_hash/inject_hash.go
// injecthash generates HMAC Key and calculates the HMAC on the text_start
// text_end symbols. Similarly HMAC is computed on rodata_start and rodata_end
// and the hash is injected into the binary

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
)

func main() {
	var perm os.FileMode
	var rodatahashValue = [32]byte{
		0x2a, 0xbd, 0xa6, 0xf3, 0xec, 0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83, 0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f, 0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80, 0xa2, 0xd4, 0xc3,
	}
	var texthashValue = [32]byte{
		0xae, 0x2c, 0xea, 0x2a, 0xbd, 0xa6, 0xf3, 0xec, 0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83, 0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f, 0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80,
	}
	var hmackey = [32]byte{
		0xb6, 0x2a, 0xd0, 0xe8, 0x82, 0x6f, 0xfd, 0x9a, 0x31, 0x85, 0x9d, 0xc5, 0x35, 0xdd, 0xac, 0xd6, 0xb3, 0xd7, 0x3e, 0x4a, 0xc1, 0x5e, 0x78, 0x9a, 0x77, 0xc4, 0x45, 0xe8, 0xad, 0xa7, 0x02, 0xeb,
	}

	inputfile := os.Args[1]

	objbytes, err := ioutil.ReadFile(inputfile)
	if err != nil {
		panic(err)
	}

	elfobj, err := elf.NewFile(bytes.NewReader(objbytes))
	if err != nil {
		panic(err)
	}

	var textSection, rodataSection *elf.Section
	var textSectionIndex, rodataSectionIndex elf.SectionIndex

	for i, section := range elfobj.Sections {
		switch section.Name {
		case ".text":
			textSectionIndex = elf.SectionIndex(i)
			textSection = section
		case ".rodata":
			rodataSectionIndex = elf.SectionIndex(i)
			rodataSection = section
		}
	}

	var textStart, textEnd, rodataStart, rodataEnd *uint64
	symbols, err := elfobj.Symbols()
	if err != nil {
		panic(err)
	}
	for _, symbol := range symbols {
		var base uint64
		switch symbol.Section {
		case textSectionIndex:
			base = textSection.Addr
		case rodataSectionIndex:
			if rodataSection == nil {
				continue
			}
			base = rodataSection.Addr
		default:
			continue
		}
		value := symbol.Value - base
		switch symbol.Name {
		case "text_start":
			textStart = &value
		case "text_end":
			textEnd = &value
		case "rodata_start":
			rodataStart = &value
		case "rodata_end":
			rodataEnd = &value
		default:
			continue
		}
	}

	if textStart == nil || textEnd == nil {
		err = errors.New("could not find .text module boundaries in object")
		panic(err)
	}

	if rodataStart == nil || rodataEnd == nil {
		err = errors.New("could not find .rodata module boundaries in object")
		panic(err)
	}

	text := textSection.Open()
	if _, err := text.Seek(int64(*textStart), 0); err != nil {
		panic(err)
	}
	fmt.Printf("TextSize:%x\n", (*textEnd - *textStart))

	moduleText := make([]byte, *textEnd-*textStart)
	if _, err := io.ReadFull(text, moduleText); err != nil {
		panic(err)
	}
	var memsize uint64 = textSection.Size
	fmt.Printf("TextSection size:%x\n", memsize)
	fmt.Printf("RODATA Section size:%x\n", rodataSection.Size)

	key := make([]byte, 32)
	rand.Read(key)
	fmt.Printf("HMAC Key:%x\n", key)
	hashFunc := sha256.New

	mac := hmac.New(hashFunc, key[:])
	mac.Write(moduleText)
	texthash := mac.Sum(nil)
	fmt.Printf("Text Signature:%x\n", texthash)

	offset := bytes.Index(objbytes, texthashValue[:])
	if offset < 0 {
		panic(errors.New("did not find text hash value in object file"))
	}
	copy(objbytes[offset:], texthash)

	offset1 := bytes.Index(objbytes, hmackey[:])
	if offset1 < 0 {
		panic(errors.New("did not find hmackey in object file"))
	}
	copy(objbytes[offset1:], key)

	rodata := rodataSection.Open()
	if _, err := rodata.Seek(int64(*rodataStart), 0); err != nil {
		panic(err)
	}
	fmt.Printf("RODATASize:%x\n", (*rodataEnd - *rodataStart))

	moduleRodata := make([]byte, *rodataEnd-*rodataStart)
	if _, err := io.ReadFull(rodata, moduleRodata); err != nil {
		panic(err)
	}
	rodatamac := hmac.New(hashFunc, key[:])
	rodatamac.Write(moduleRodata)
	rodatahash := rodatamac.Sum(nil)
	fmt.Printf("RODATA Signature:%x\n", rodatahash)

	rodataoffset := bytes.Index(objbytes, rodatahashValue[:])
	if rodataoffset < 0 {
		panic(errors.New("did not find rodata hash value in object file"))
	}
	copy(objbytes[rodataoffset:], rodatahash)
	ioutil.WriteFile(inputfile, objbytes, perm&0777)
}
