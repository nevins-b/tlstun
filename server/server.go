package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/jsimonetti/tlstun/cert"
	"github.com/jsimonetti/tlstun/log"

	golog "log"

	socks5 "github.com/armon/go-socks5"
	"golang.org/x/net/websocket"
)

type Config struct {
	Port         int
	Address      string
	Verbose      bool
	RegisterPass string
	CA           string
	Certificate  string
	Key          string
}

type server struct {
	listenAddr   string // local ip:port to bind to
	tlsConfig    *tls.Config
	socksServer  *socks5.Server
	log          *log.Logger
	registerPass string
	certificate  string
	key          string
	ca           string

	server *http.Server

	connections int32
}

func NewServer(config Config) *server {
	addr := fmt.Sprintf("%s:%d", config.Address, config.Port)
	s := &server{
		listenAddr:   addr,
		log:          log.NewLogger(config.Verbose),
		registerPass: config.RegisterPass,
		certificate:  config.Certificate,
		key:          config.Key,
		ca:           config.CA,
	}
	s.getTlsConfig()
	return s
}

func (s *server) Start() {
	var err error

	conf := &socks5.Config{
		Logger: golog.New(s.log, "", 0),
		Rules: &socks5.PermitCommand{
			EnableConnect:   true,
			EnableBind:      false,
			EnableAssociate: false,
		},
	}
	s.socksServer, err = socks5.New(conf)
	if err != nil {
		s.log.Fatal(err)
	}

	http.Handle("/tlstun/socket/", websocket.Handler(func(w *websocket.Conn) {
		s.sockHandler(w)
	}))
	http.HandleFunc("/tlstun/poison/", func(w http.ResponseWriter, r *http.Request) {
		s.servePoison(w, r)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.serveHome(w, r)
	})

	server := &http.Server{
		Addr:      s.listenAddr,
		TLSConfig: s.tlsConfig,
	}

	s.server = server

	s.log.Printf("listening start on %s\n", s.listenAddr)
	if s.registerPass != "" {
		s.log.Print("registration enabled!")
	}

	err = server.ListenAndServeTLS(s.certificate, s.key)
	if err != nil {
		s.log.Fatalf("ListenAndServeTLS: %s", err)
	}
}

func (s *server) getTlsConfig() {
	certf, keyf := s.certificate, s.key
	if certf == "" {
		certf = "server.crt"
		keyf = "server.key"
	}
	tlsConfig, err := cert.TLSConfig(certf, keyf)
	if err != nil {
		s.log.Fatal(err)
	}

	if s.ca != "" {
		s.log.Printf("loading ca %s", s.ca)
		certBytes, err := ioutil.ReadFile(s.ca)
		if err != nil {
			s.log.Fatal(err)
		}
		certpem, _ := pem.Decode(certBytes)
		cert, err := x509.ParseCertificate(certpem.Bytes)
		if err != nil {
			s.log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		s.log.Fatal("ca required")
	}
	tlsConfig.BuildNameToCertificate()
	s.tlsConfig = tlsConfig
}
