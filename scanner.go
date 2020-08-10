package main

import (

  "crypto/tls"
  "os"
  "flag"

  log "github.com/sirupsen/logrus"

)

func init() () {
  log.SetFormatter(&log.JSONFormatter{})
  log.SetReportCaller(true)
  log.SetLevel(log.TraceLevel)
}


func main() () {

  cliTransportHost := flag.String("connect", "", "L3 host to dial")
  cliTransportPort := flag.String("port", "443", "L4 port to dial")
  cliTlsSniHost    := flag.String("sni", "", "L5 TLS SNI Host")
  flag.Parse()

  cli := Cli{
    TransportHost: *cliTransportHost,
    TransportPort: *cliTransportPort,
    SniHost: *cliTlsSniHost,
  }

  scan := parseCli(cli)
  fuzzTlsHost(scan)

}

type Cli struct {
  TransportHost string
  TransportPort string
  SniHost string
}

type Scanner struct {
  Transport string
  TlsSNI string
}

func parseCli(cli Cli) (s Scanner) {
  var transportHost string
  var tlsSni string

  if cli.TransportHost == "" {
    showUsage()
  } else {
    if cli.SniHost == "" {
      tlsSni = cli.TransportHost
    } else {
      tlsSni = cli.SniHost
    }

    if cli.TransportPort == "" {
      transportHost = cli.TransportHost + ":443"
    } else {
      transportHost = cli.TransportHost + ":" + cli.TransportPort
    }

    s = Scanner{
      Transport: transportHost,
      TlsSNI: tlsSni,
    }
  }

  return s

}

func showUsage() () {

  log.Error("provide one or more arguments.. ")

  log.Error("-connect=xxx.com")
  log.Error("-port=1234 (if different than 443)")
  log.Error("-sni=yyy.com (if different than -connect)")

  os.Exit(3)
  return

}

func fuzzTlsHost(s Scanner) () {

	var allCiphers = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

  for _, cipher := range allCiphers {
      cipherText := tls.CipherSuiteName(cipher)
      log.Debugf("about to try with %v should be %v", cipher, cipherText)
      conf := getConfigForCipher(cipher, s.TlsSNI)
      performHandshake(&conf, s.Transport)
  }

    return
}

func performHandshake(conf *tls.Config, l3host string) () {

    conn, err := tls.Dial("tcp", l3host, conf)

    if err != nil {
      log.Errorf("error dialing: %v", err)
    } else {
      defer conn.Close()
      state := conn.ConnectionState()

      if state.NegotiatedProtocolIsMutual == true {
        cipher := state.CipherSuite
        ciphername := tls.CipherSuiteName(cipher)
        log.WithFields(log.Fields{
          "cipher": ciphername,
          "mutual": "true",
        }).Debugf("got mutual cipher %v", ciphername)
      } else {
        cipher := conf.CipherSuites[0]
        ciphername := tls.CipherSuiteName(cipher)
        log.WithFields(log.Fields{
          "cipher": ciphername,
          "mutual": "false",
        }).Debugf("did not agree on cipher this run %v", ciphername)
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
