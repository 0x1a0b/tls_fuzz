package main

import (
	"crypto/tls"
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
	log.SetLevel(log.TraceLevel)
}

func main() {

	cliTransportHost := flag.String("connect", "", "L3 host to dial")
	cliTransportPort := flag.String("port", "443", "L4 port to dial")
	cliTlsSniHost := flag.String("sni", "", "L5 TLS SNI Host")
	flag.Parse()

	cli := Cli{
		TransportHost: *cliTransportHost,
		TransportPort: *cliTransportPort,
		SniHost:       *cliTlsSniHost,
	}

	scan := parseCli(cli)
	fuzzTlsHost(scan)

}

type Cli struct {
	TransportHost string
	TransportPort string
	SniHost       string
}

type Scanner struct {
	Transport string
	TlsSNI    string
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
			TlsSNI:    tlsSni,
		}
	}

	return s

}

func showUsage() {

	log.Error("provide one or more arguments.. ")

	log.Error("-connect=xxx.com")
	log.Error("-port=1234 (if different than 443)")
	log.Error("-sni=yyy.com (if different than -connect)")

	os.Exit(3)
	return

}

type Cipher struct {
	Name            string
	Tlscode         uint16
	Rfc             string
	Csinfolink      string
	Csinfoapi       string
	Tlsminversion   string
	Tlsmaxversion   string
	Gocryptonative  bool
	Gocryptocipher  uint16
	Gocryptomintlsv uint16
	Gocryptomaxtlsv uint16
}

func GetCiphers() (ciphers []Cipher) {
	// golang native tls does only implement a subset
	ciphers = []Cipher{
		// TLS1.3
		Cipher{
			Name:            "TLS_AES_256_GCM_SHA384",
			Rfc:             "8446",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_AES_256_GCM_SHA384/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_AES_256_GCM_SHA384/",
			Tlsminversion:   "TLS1.3",
			Tlsmaxversion:   "TLS1.3",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_AES_256_GCM_SHA384,
			Gocryptomintlsv: tls.VersionTLS13,
			Gocryptomaxtlsv: tls.VersionTLS13,
		},
		Cipher{
			Name:            "TLS_AES_128_GCM_SHA256",
			Rfc:             "8446",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_AES_128_GCM_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_AES_128_GCM_SHA256/",
			Tlsminversion:   "TLS1.3",
			Tlsmaxversion:   "TLS1.3",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_AES_128_GCM_SHA256,
			Gocryptomintlsv: tls.VersionTLS13,
			Gocryptomaxtlsv: tls.VersionTLS13,
		},
		Cipher{
			Name:            "TLS_CHACHA20_POLY1305_SHA256",
			Rfc:             "8446",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_CHACHA20_POLY1305_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_CHACHA20_POLY1305_SHA256/",
			Tlsminversion:   "TLS1.3",
			Tlsmaxversion:   "TLS1.3",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_CHACHA20_POLY1305_SHA256,
			Gocryptomintlsv: tls.VersionTLS13,
			Gocryptomaxtlsv: tls.VersionTLS13,
		},
		// others
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			Rfc:             "7905",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			Rfc:             "7905",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			Rfc:             "5289",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.1",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS11,
		},
		Cipher{
			Name:            "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_RC4_128_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_RSA_WITH_RC4_128_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			Rfc:             "8422",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_AES_256_GCM_SHA384",
			Rfc:             "5288",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_GCM_SHA384/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_AES_256_GCM_SHA384/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_AES_128_GCM_SHA256",
			Rfc:             "5288",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_AES_128_GCM_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_AES_128_GCM_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_AES_128_CBC_SHA256",
			Rfc:             "5246",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_AES_128_CBC_SHA256/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_AES_128_CBC_SHA256/",
			Tlsminversion:   "TLS1.2",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			Gocryptomintlsv: tls.VersionTLS12,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_AES_256_CBC_SHA",
			Rfc:             "5246",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_AES_256_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_AES_128_CBC_SHA",
			Rfc:             "5246",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_AES_128_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_AES_128_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			Rfc:             "5246",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_3DES_EDE_CBC_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_3DES_EDE_CBC_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.1",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS11,
		},
		Cipher{
			Name:            "TLS_RSA_WITH_RC4_128_SHA",
			Rfc:             "5246",
			Csinfolink:      "https://ciphersuite.info/cs/TLS_RSA_WITH_RC4_128_SHA/",
			Csinfoapi:       "https://ciphersuite.info/api/cs/TLS_RSA_WITH_RC4_128_SHA/",
			Tlsminversion:   "TLS1.0",
			Tlsmaxversion:   "TLS1.2",
			Gocryptonative:  true,
			Gocryptocipher:  tls.TLS_RSA_WITH_RC4_128_SHA,
			Gocryptomintlsv: tls.VersionTLS10,
			Gocryptomaxtlsv: tls.VersionTLS12,
		},
	}
	return ciphers
}

func fuzzTlsHost(s Scanner) {

	var allCiphers = GetCiphers()

	for _, cipher := range allCiphers {
		log.Debugf("about to try with %v should be %v", cipher.Gocryptocipher, cipher.Name)
		conf := getConfigForCipher(cipher.Gocryptocipher, s.TlsSNI)
		performHandshake(&conf, s.Transport)
	}

	return
}

func performHandshake(conf *tls.Config, l3host string) {

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
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         l5host,
		CipherSuites:       []uint16{cypher},
	}

	return
}
