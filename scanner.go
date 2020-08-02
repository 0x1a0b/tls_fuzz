package main

import (

  "crypto/tls"

)

const (

)


var (

)



func main () () {



}

func fuzzTlsHost (sni string) () {
    ciphers := tls.InsecureCipherSuites()
    for cipher := range ciphers {
        conf := getConfigForCipher(cipher, sni)
        performHandshake(&conf)
    }
}

func performHandshake (conf *tls.Config) () {
  conn, err := tls.Dial("tcp", tlsExpiryScanner.Connect, conf)
}

func getConfigForCipher (cypher *tls.CipherSuite, sni string) (config tls.Config) {
    config = tls.Config{
        InsecureSkipVerify: true,
        MinVersion: tls.VersionTLS10,
        MaxVersion: tls.VersionTLS13,
        ServerName: sni,
        CipherSuites: []tls.CipherSuite{cypher},
    }
    return
}
