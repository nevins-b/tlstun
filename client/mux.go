package client

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pkg/errors"
	"golang.org/x/net/websocket"
)

func (c *client) handleSession(conn net.Conn) {
	var sent, received int64

	defer func(sent, received *int64) {
		atomic.AddInt32(&c.connections, -1)
		c.log.Printf("closed connection from: %s, sent: %d, received: %d, open connections: %d\n", conn.RemoteAddr(), *sent, *received, atomic.LoadInt32(&c.connections))
		conn.Close()
	}(&sent, &received)

	stream, err := c.getStream()
	if err != nil {
		c.log.Print("failed creating stream: %s", err)
		return
	}

	received, sent = Pipe(stream, conn)
}

func (c *client) getStream() (net.Conn, error) {
	stream, err := c.session.Open()
	if err != nil {
		if err == yamux.ErrSessionShutdown {
			err = c.openSession()
			if err != nil {
				return nil, errors.Wrap(err, "error opening session")
			}
		}
		stream, err = c.session.Open()
		if err != nil {
			return nil, errors.Wrap(err, "error opening stream")
		}
	}
	return stream, err
}

func (c *client) openSession() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.webSocket == nil {
		err := c.openWebsocket()
		if err != nil {
			return err
		}
	}

	// Setup client side of yamux
	session, err := yamux.Client(c.webSocket, nil)
	if err != nil {
		return err
	}

	c.session = session
	return nil
}

func (c *client) openWebsocket() error {
	wsurl := "wss://" + c.serverAddr + "/tlstun/socket/"
	origin := wsurl

	wsConfig, err := websocket.NewConfig(wsurl, origin)
	if err != nil {
		return err
	}
	wsConfig.TlsConfig = c.tlsConfig
	wsConfig.Dialer = &net.Dialer{
		KeepAlive: 30 * time.Second,
	}

	wsconn, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return err
	}

	c.log.Printf("connected to server: %s", wsurl)
	c.webSocket = wsconn
	return nil
}
