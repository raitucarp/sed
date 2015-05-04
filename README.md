# sed
simple encryption and decryption for golang

# How to use

## Instalation
```
go get github.com/raitucarp/sed
```

## Encrypt and Decrypt usage
```
package main

import (
    "github.com/raitucarp/sed"
    "fmt"
)

func main() {
    key := "secret key"
    txt := "is this works?"
    e := sed.Encrypt(txt, key, sed.HEX)
    d := sed.Decrypt(e, key, sed.HEX)
    fmt.Println("byte comparison", []byte(d), []byte(txt))
    fmt.Println("is this works?" == txt)
    fmt.Println("encrypt =", e)
    fmt.Println("decrypt =", d)
}
```

## Encrypt(text string, key string, output int)
output is BASE32, BASE64 or HEX

## Decrypt(text string, key string, output int)