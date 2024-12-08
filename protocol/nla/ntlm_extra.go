package nla

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
)

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
