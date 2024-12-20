package tpkt

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/lunixbochs/struc"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
)

func (t *TPKT) StartNtlmMessageOneWithClientData(negData []byte) ([]byte, error) {

	buff := &bytes.Buffer{}
	buff.Write(negData)

	negMsg := &nla.NegotiateMessage{}

	err := struc.Unpack(buff, negMsg)

	if err != nil {
		glog.Info("struc.Pack neg message error", err)
		return nil, fmt.Errorf("start ntlm message one error %w", err)
	}
	//这里需要设置
	t.ntlm.SetNegotiateMessage(negMsg)

	//发起NTLM第一阶段：
	req := nla.EncodeNegByteToDERTRequest(negData, nil, nil)
	_, err = t.Conn.Write(req)
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
	glog.Info("neg2:" + hex.EncodeToString(t.ntlm.GetNegotiateMessage().Serialize()))

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

func (t *TPKT) AuthByClientChallenge(challenge []byte, info *nla.AuthInfo) error {

	pubkey, err := t.Conn.TlsPubKey()
	glog.Debugf("pubkey=%+v", pubkey)

	//authMsg, ntlmSec := t.ntlm.GetAuthenticateMessageExtra(challenge, info)
	//t.ntlmSec = ntlmSec
	//encryptPubkey := ntlmSec.GssEncrypt(pubkey)

	//把publicKeyAuth的验证去掉:
	//req := nla.EncodeDERTRequest([]nla.Message{authMsg}, nil, nil)

	req := nla.EncodeAuthByteToDERTRequest(info.All, nil, nil)

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

/*
*
测试用
*/
func (t *TPKT) AuthByLocalNtlmHash(data []byte) ([]byte, error) {

	return t.recvChallengeExtra(data)
}

/*
*
测试用
*/
func (t *TPKT) recvChallengeExtra(data []byte) ([]byte, error) {
	glog.Trace("recvChallenge", hex.EncodeToString(data))

	pubkey, err := t.Conn.TlsPubKey()
	glog.Debugf("pubkey=%+v", pubkey)

	authMsg, ntlmSec := t.ntlm.GetAuthenticateMessage(data)

	//ntlmSec := t.ntlm.GetNlaSec()
	t.ntlm.GetNlaSec()
	t.ntlmSec = ntlmSec

	encryptPubkey := ntlmSec.GssEncrypt(pubkey)
	req := nla.EncodeDERTRequest([]nla.Message{authMsg}, nil, encryptPubkey)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return nil, err
	}
	resp := make([]byte, 1024)
	_, err = t.Conn.Read(resp)
	if err != nil {
		glog.Error("Read:", err)
		return nil, fmt.Errorf("read %s", err)
	} else {
		glog.Debug("recvChallenge Read success")
	}
	return authMsg.Serialize(), nil
}
