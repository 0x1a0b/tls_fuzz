package main

import (

  "crypto/tls"
  "os"

  log "github.com/sirupsen/logrus"

)

const (

)


var (

)



func main() () {

  scan := parseCli(os.Args)
  fuzzTlsHost(scan)

}

type Scanner struct {
  TransportHost string
  TlsSNI string
}

func parseCli(args []string) (s Scanner) {
  var transportHost string
  var tlsSni string

  if args[1] == "" {
    showUsage()
  } else {
    if args[3] == "" {
      tlsSni = args[1]
    } else {
      tlsSni = args[3]
    }

    if args[2] == "" {
      transportHost = args[1] + ":443"
    } else {
      transportHost = args[1] + ":" + args[2]
    }

    s = Scanner{
      TransportHost: transportHost,
      TlsSNI: tlsSni,
    }
  }

  return s

}

func showUsage() () {
  usage := `
  Usage:
  - Argument 1: Transport Host
  - Argument 2: Transport Port (optional, default -> 443)
  - Argument 3: SNI Host (optional, default -> same as transport host)
  `
  log.Errorf("provide one or more arguments.. %v", usage)

  os.Exit(3)
  return

}

func fuzzTlsHost(s Scanner) () {
    {
      ciphers := tls.InsecureCipherSuites()
      for cipher := range ciphers {
          conf := getConfigForCipher(uint16(cipher), s.TlsSNI)
          performHandshake(&conf, s.TransportHost)
      }
    }

    {
      ciphers := tls.CipherSuites()
      for cipher := range ciphers {
          conf := getConfigForCipher(uint16(cipher), s.TlsSNI)
          performHandshake(&conf, s.TransportHost)
      }
    }

    return
}

func performHandshake(conf *tls.Config, l3host string) () {

    conn, err := tls.Dial("tcp", l3host, conf)
    defer conn.Close()
    state := conn.ConnectionState()

    if err != nil {
      log.Errorf("error dialing: %v", err)
    } else {
      if state.NegotiatedProtocolIsMutual == true {
        cipher := state.CipherSuite
        ciphername := tls.CipherSuiteName(cipher)
        log.Debugf("got mutual cipher %v", ciphername)
      } else {
        cipher := conf.CipherSuites[0]
        ciphername := tls.CipherSuiteName(cipher)
        log.Debugf("did not agree on cipher this run %v", ciphername)
      }
    }

    return
}

func getConfigForCipher(cypher uint16, l5host string) (config tls.Config) {

    config = tls.Config{
        InsecureSkipVerify: true,
        MinVersion: tls.VersionTLS10,
        MaxVersion: tls.VersionTLS13,
        ServerName: l5host,
        CipherSuites: []uint16{cypher},
    }

    return
}
