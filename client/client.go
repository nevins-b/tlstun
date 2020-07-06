package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jsimonetti/tlstun/cert"
	"github.com/jsimonetti/tlstun/log"
	"github.com/pkg/errors"
	"golang.org/x/net/websocket"

	"github.com/hashicorp/yamux"
)

type Config struct {
	Port          int
	Address       string
	ServerAddress string
	Verbose       bool
	CA            string
	Certificate   string
	Key           string
	Insecure      bool
	NoPoison      bool
}

type client struct {
	ProxyAddress string
	listenAddr   string
	serverAddr   string
	log          *log.Logger
	tlsConfig    *tls.Config
	certificate  string
	key          string
	ca           string
	insecure     bool
	nopoison     bool

	connections int32

	listener net.Listener

	lock      sync.Mutex
	session   *yamux.Session
	webSocket *websocket.Conn
}

func NewClient(config Config) *client {
	addr := fmt.Sprintf("%s:%d", config.Address, config.Port)

	c := &client{
		ProxyAddress: fmt.Sprintf("socks5://%s", addr),
		listenAddr:   addr,
		serverAddr:   config.ServerAddress,
		log:          log.NewLogger(config.Verbose),
		certificate:  config.Certificate,
		key:          config.Key,
		ca:           config.CA,
		insecure:     config.Insecure,
		nopoison:     config.NoPoison,
	}
	c.getTlsConfig()
	return c
}

func (c *client) Stop() error {
	c.session.Close()
	c.webSocket.Close()
	return c.listener.Close()
}

func (c *client) Start() error {
	if !c.nopoison {
		c.poison()
	}

	c.log.Printf("listening start on %s\n", c.listenAddr)
	ln, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return errors.Wrap(err, "error listening")
	}
	err = c.openSession()
	if err != nil {
		return errors.Wrap(err, "error opening session")
	}
	c.listener = ln
	go c.hanldeConnections()
	time.Sleep(1)
	return nil
}

func (c *client) hanldeConnections() {
	for {
		conn, err := c.listener.Accept()
		if nil != err {
			c.log.Printf("error accepting connection: %s, open connections: %d\n", err, atomic.LoadInt32(&c.connections))
			return
		}
		atomic.AddInt32(&c.connections, 1)
		c.log.Printf("accepted connection from: %s, open connections: %d\n", conn.RemoteAddr(), atomic.LoadInt32(&c.connections))
		go c.handleSession(conn)
	}
}

func (c *client) getTlsConfig() {
	certf, keyf := c.certificate, c.key
	if certf == "" {
		certf = "client.crt"
		keyf = "client.key"
	}

	tlsConfig, err := cert.TLSConfig(certf, keyf)
	if err != nil {
		c.log.Fatal(err)
	}

	if c.ca != "" {
		certBytes, err := ioutil.ReadFile(c.ca)
		if err != nil {
			c.log.Fatal(err)
		}
		certpem, _ := pem.Decode(certBytes)
		cert, err := x509.ParseCertificate(certpem.Bytes)
		if err != nil {
			c.log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		tlsConfig.RootCAs = pool
	}

	if c.insecure {
		tlsConfig.InsecureSkipVerify = c.insecure
	}

	tlsConfig.BuildNameToCertificate()
	c.tlsConfig = tlsConfig
}

func (c *client) poison() {
	c.log.Print("starting to poison firewall ...")

	uri := fmt.Sprintf("https://%s/tlstun/poison/", c.serverAddr)

	tr := &http.Transport{
		TLSClientConfig: c.tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	hc := http.Client{Transport: tr}

	for i := 1; i <= 30; i++ {
		sent := fmt.Sprintf("%2d", i)
		result, err := hc.Get(uri + sent)
		if err != nil {
			c.log.Fatal(err)
		}
		response := []byte{0, 0}
		_, err = io.ReadFull(result.Body, response)
		defer result.Body.Close()
		if err != nil {
			c.log.Printf("error reading poison: %s", err)
		}

		if sent != fmt.Sprintf("%s", response) {
			c.log.Fatalf("Unexpected response; want: %s, got %s", sent, response)
		}
	}
}
