package nla

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"github.com/lunixbochs/struc"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"time"
)

type AuthInfo struct {
	All        []byte
	Username   []byte
	NtResponse []byte
	LmResponse []byte
	SessionKey []byte
	Payload    []byte
}

func (n *NTLMv2) GetAuthenticateMessageExtra(challengeInfo []byte, authInfo *AuthInfo) (*AuthenticateMessage, *NTLMv2Security) {
	challengeMsg := &ChallengeMessage{}
	r := bytes.NewReader(challengeInfo)
	err := struc.Unpack(r, challengeMsg)
	if err != nil {
		glog.Error("read challengeMsg", err)
		return nil, nil
	}
	if challengeMsg.NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		version := NVersion{}
		err := struc.Unpack(r, &version)
		if err != nil {
			glog.Error("read version", err)
			return nil, nil
		}
		challengeMsg.Version = version
	}
	challengeMsg.Payload, _ = core.ReadBytes(r.Len(), r)
	n.challengeMessage = challengeMsg
	glog.Debugf("challengeMsg:%+v", challengeMsg)

	serverName := challengeMsg.getTargetName()
	serverInfo := challengeMsg.getTargetInfo()
	timestamp := challengeMsg.getTargetInfoTimestamp(serverInfo)
	computeMIC := false
	if timestamp == nil {
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	} else {
		computeMIC = true
	}
	glog.Infof("serverName=%+v", core.UnicodeDecode(serverName))
	serverChallenge := challengeMsg.ServerChallenge[:]
	clientChallenge := core.Random(8)
	_, _, SessionBaseKey := n.ComputeResponseV2(
		n.respKeyNT, n.respKeyLM, serverChallenge, clientChallenge, timestamp, serverInfo)

	exchangeKey := SessionBaseKey
	exportedSessionKey := core.Random(16)
	EncryptedRandomSessionKey := make([]byte, len(exportedSessionKey))
	rc, _ := rc4.NewCipher(exchangeKey)
	rc.XORKeyStream(EncryptedRandomSessionKey, exportedSessionKey)

	if challengeMsg.NegotiateFlags&NTLMSSP_NEGOTIATE_UNICODE != 0 {
		n.enableUnicode = true
	}

	glog.Infof("user: %s, passwd:%s", n.user, n.password)
	domain, user, _ := n.GetEncodedCredentials()
	glog.Infof("user: %s, passwd:%s", domain, user)
	buff := &bytes.Buffer{}
	buff.Write(authInfo.All)
	//n.authenticateMessage = NewAuthenticateMessage(challengeMsg.NegotiateFlags,
	//	domain, user, []byte(""), authInfo.LmResponse, authInfo.NtResponse, authInfo.SessionKey)

	authMsg := &AuthenticateMessage{}
	errParse := struc.Unpack(buff, authMsg)
	authMsg.Payload = authInfo.Payload
	if err != nil {
		glog.Error("parse authenticateMessage error", errParse)
		return nil, nil
	}

	n.authenticateMessage = authMsg

	if computeMIC {
		copy(n.authenticateMessage.MIC[:], MIC(exportedSessionKey, n.negotiateMessage, n.challengeMessage, n.authenticateMessage)[:16])
	}

	md := md5.New()
	//ClientSigningKey
	a := concat(exportedSessionKey, clientSigning)
	md.Write(a)
	ClientSigningKey := md.Sum(nil)
	//ServerSigningKey
	md.Reset()
	a = concat(exportedSessionKey, serverSigning)
	md.Write(a)
	ServerSigningKey := md.Sum(nil)
	//ClientSealingKey
	md.Reset()
	a = concat(exportedSessionKey, clientSealing)
	md.Write(a)
	ClientSealingKey := md.Sum(nil)
	//ServerSealingKey
	md.Reset()
	a = concat(exportedSessionKey, serverSealing)
	md.Write(a)
	ServerSealingKey := md.Sum(nil)

	glog.Debugf("ClientSigningKey:%s", hex.EncodeToString(ClientSigningKey))
	glog.Debugf("ServerSigningKey:%s", hex.EncodeToString(ServerSigningKey))
	glog.Debugf("ClientSealingKey:%s", hex.EncodeToString(ClientSealingKey))
	glog.Debugf("ServerSealingKey:%s", hex.EncodeToString(ServerSealingKey))

	encryptRC4, _ := rc4.NewCipher(ClientSealingKey)
	decryptRC4, _ := rc4.NewCipher(ServerSealingKey)

	ntlmSec := &NTLMv2Security{encryptRC4, decryptRC4, ClientSigningKey, ServerSigningKey, 0}

	return n.authenticateMessage, ntlmSec
}

func (n *NTLMv2) GetNlaSec() *NTLMv2Security {

	exportedSessionKey := core.Random(16)

	glog.Infof("user: %s, passwd:%s", n.user, n.password)

	md := md5.New()
	//ClientSigningKey
	a := concat(exportedSessionKey, clientSigning)
	md.Write(a)
	ClientSigningKey := md.Sum(nil)
	//ServerSigningKey
	md.Reset()
	a = concat(exportedSessionKey, serverSigning)
	md.Write(a)
	ServerSigningKey := md.Sum(nil)
	//ClientSealingKey
	md.Reset()
	a = concat(exportedSessionKey, clientSealing)
	md.Write(a)
	ClientSealingKey := md.Sum(nil)
	//ServerSealingKey
	md.Reset()
	a = concat(exportedSessionKey, serverSealing)
	md.Write(a)
	ServerSealingKey := md.Sum(nil)

	glog.Debugf("ClientSigningKey:%s", hex.EncodeToString(ClientSigningKey))
	glog.Debugf("ServerSigningKey:%s", hex.EncodeToString(ServerSigningKey))
	glog.Debugf("ClientSealingKey:%s", hex.EncodeToString(ClientSealingKey))
	glog.Debugf("ServerSealingKey:%s", hex.EncodeToString(ServerSealingKey))

	encryptRC4, _ := rc4.NewCipher(ClientSealingKey)
	decryptRC4, _ := rc4.NewCipher(ServerSealingKey)

	ntlmSec := &NTLMv2Security{encryptRC4, decryptRC4, ClientSigningKey, ServerSigningKey, 0}

	return ntlmSec
}
