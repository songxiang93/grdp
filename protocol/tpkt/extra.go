package tpkt

import (
	"encoding/hex"
	"fmt"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
)

func (t *TPKT) StartNtlmMessageOneWithClientData(negData []byte) ([]byte, error) {

	//发起NTLM第一阶段：
	req := nla.EncodeNegByteToDERTRequest(negData, nil, nil)
	_, err := t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return nil, err
	}

	resp := make([]byte, 1024)
	//这里是已经解了tls了,Conn是SocketLayer层，在SocketLayer层里封装了tls：
	n, err := t.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read %w", err)
	} else {
		glog.Debug("StartNLA Read success")
	}
	//收到服务端发起的挑战值:
	return t.getChallenge(resp[:n])
}

func (t *TPKT) StartNtlmMessageOne() ([]byte, error) {

	//发起NTLM第一阶段：
	req := nla.EncodeDERTRequest([]nla.Message{t.ntlm.GetNegotiateMessage()}, nil, nil)
	_, err := t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return nil, err
	}

	resp := make([]byte, 1024)
	//这里是已经解了tls了,Conn是SocketLayer层，在SocketLayer层里封装了tls：
	n, err := t.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read %w", err)
	} else {
		glog.Debug("StartNLA Read success")
	}
	//收到服务端发起的挑战值:
	return t.getChallenge(resp[:n])
}

func (t *TPKT) getChallenge(data []byte) ([]byte, error) {
	glog.Trace("recvChallenge", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return nil, err
	}
	glog.Debugf("tsreq:%+v", tsreq)
	return tsreq.NegoTokens[0].Data, nil
}

func (t *TPKT) AuthByClientChallenge(challengeData []byte) error {

	pubkey, err := t.Conn.TlsPubKey()
	glog.Debugf("pubkey=%+v", pubkey)

	ntlmSec := t.ntlm.GetNlaSec()
	encryptPubkey := ntlmSec.GssEncrypt(pubkey)

	req := nla.EncodeAuthByteToDERTRequest(challengeData, nil, encryptPubkey)

	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}
	resp := make([]byte, 1024)
	_, err = t.Conn.Read(resp)
	if err != nil {
		glog.Error("Read:", err)
		return fmt.Errorf("read error %w", err)
	} else {
		glog.Debug("recvChallenge Read success")
		return nil
	}
}
