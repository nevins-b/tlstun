package server

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/yamux"
	"golang.org/x/net/websocket"
)

func (s *server) sockHandler(w *websocket.Conn) {
	atomic.AddInt32(&s.connections, 1)

	s.log.Printf("serving client connection, raddr: %s, connections: %d", w.Request().RemoteAddr, atomic.LoadInt32(&s.connections))

	session, err := yamux.Server(w, nil)
	if err != nil {
		s.log.Printf("could not initialise yamux session: %s", err)
		return
	}

	var streams int32

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err != io.EOF {
				s.log.Printf("error acception stream: %s, connections: %d, ", err, atomic.LoadInt32(&s.connections))
			}
			break
		}
		atomic.AddInt32(&streams, 1)
		id := stream.StreamID()
		s.log.Printf("accepted stream for id: %d, connections: %d, streams: %d", id, atomic.LoadInt32(&s.connections), streams)

		go func() {
			//no error handling needed, socks package allready logs errors
			s.socksServer.ServeConn(stream)
			atomic.AddInt32(&streams, -1)
			s.log.Printf("ended stream for id: %d, connections: %d, streams: %d", id, atomic.LoadInt32(&s.connections), atomic.LoadInt32(&streams))
			stream.Close()
		}()
	}

	atomic.AddInt32(&s.connections, -1)
	s.log.Printf("connection closed, raddr: %s, connections: %d", w.Request().RemoteAddr, atomic.LoadInt32(&s.connections))
	w.Close()
	return
}

func (s *server) servePoison(w http.ResponseWriter, r *http.Request) {
	s.log.Printf("served poison: %s", r.URL.Path)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strings.TrimPrefix(r.URL.Path, "/tlstun/poison/")))
	return
}

func (s *server) serveHome(w http.ResponseWriter, r *http.Request) {
	s.log.Printf("served page: %s", r.URL.Path)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(TrustedResponse()))
	return
}
