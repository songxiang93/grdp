package core

import (
	"crypto/rsa"
	"github.com/tomatome/grdp/glog"
	"math/big"

	"github.com/huin/asn1ber"

	//"crypto/tls"
	"errors"
	"github.com/icodeface/tls"
	"net"
)

type SocketLayer struct {
	conn    net.Conn
	tlsConn *tls.Conn
}

func NewSocketLayer(conn net.Conn) *SocketLayer {
	l := &SocketLayer{
		conn:    conn,
		tlsConn: nil,
	}
	return l
}

func (s *SocketLayer) Read(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Read(b)
	}
	return s.conn.Read(b)
}

func (s *SocketLayer) Write(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Write(b)
	}
	return s.conn.Write(b)
}

func (s *SocketLayer) Close() error {
	if s.tlsConn != nil {
		err := s.tlsConn.Close()
		if err != nil {
			return err
		}
	}
	return s.conn.Close()
}

func (s *SocketLayer) StartTLS() error {
	config := &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS10,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: false,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	s.tlsConn = tls.Client(s.conn, config)
	err := s.tlsConn.Handshake()
	if err == nil {
		state := s.tlsConn.ConnectionState()
		glog.Infof("state .CipherSuite %d", state.CipherSuite)
	}
	return err
}

type PublicKey struct {
	N *big.Int `asn1:"explicit,tag:0"` // modulus
	E int      `asn1:"explicit,tag:1"` // public exponent
}

func (s *SocketLayer) TlsPubKey() ([]byte, error) {
	if s.tlsConn == nil {
		return nil, errors.New("TLS conn does not exist")
	}
	pub := s.tlsConn.ConnectionState().PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	return asn1ber.Marshal(*pub)

}
