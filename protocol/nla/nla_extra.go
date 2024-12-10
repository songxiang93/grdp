package nla

import (
	"encoding/asn1"
	"github.com/tomatome/grdp/glog"
)

func EncodeNegByteToDERTRequest(negByte []byte, authInfo []byte, pubKeyAuth []byte) []byte {

	req := TSRequest{
		Version: 2,
	}

	req.NegoTokens = make([]NegoToken, 0, 1)
	token := NegoToken{negByte}
	req.NegoTokens = append(req.NegoTokens, token)

	if len(authInfo) > 0 {
		req.AuthInfo = authInfo
	}

	if len(pubKeyAuth) > 0 {
		req.PubKeyAuth = pubKeyAuth
	}

	result, err := asn1.Marshal(req)
	if err != nil {
		glog.Error(err)
	}
	return result
}

func EncodeAuthByteToDERTRequest(authBytes []byte, authInfo []byte, pubKeyAuth []byte) []byte {
	req := TSRequest{
		Version: 2,
	}
	req.NegoTokens = make([]NegoToken, 0, 1)
	token := NegoToken{authBytes}
	req.NegoTokens = append(req.NegoTokens, token)

	if len(authInfo) > 0 {
		req.AuthInfo = authInfo
	}

	if len(pubKeyAuth) > 0 {
		req.PubKeyAuth = pubKeyAuth
	}

	result, err := asn1.Marshal(req)
	if err != nil {
		glog.Error(err)
	}
	return result
}
