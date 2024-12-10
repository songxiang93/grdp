package x224

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/lunixbochs/struc"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/tpkt"
)

func (x *X224) ConnectNlaAndWait() error {
	if x.transport == nil {
		return errors.New("no transport")
	}
	cookie := "Cookie: mstshash=test"

	//这个PDU包含了整个X.224层的数据包
	message := NewClientConnectionRequestPDU([]byte(cookie), x.requestedProtocol)

	message.ProtocolNeg.Type = TYPE_RDP_NEG_REQ
	message.ProtocolNeg.Result = uint32(x.requestedProtocol)

	glog.Info("x224 sendConnectionRequest", hex.EncodeToString(message.Serialize()))
	// x.transport 是 X.224层
	_, err := x.transport.Write(message.Serialize())
	if err != nil {
		return err
	}

	x.transport.Once("data", x.recvNlaConnectionConfirm)

	startTlsResult := <-x.startTlsChan
	return startTlsResult.err
}

func (x *X224) recvNlaConnectionConfirm(s []byte) {
	glog.Info("x224 recvConnectionConfirm ", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	ln, _ := core.ReadUInt8(r)
	if ln > 6 {
		message := &ServerConnectionConfirm{}
		if err := struc.Unpack(bytes.NewReader(s), message); err != nil {
			glog.Error("ReadServerConnectionConfirm err", err)
			return
		}
		glog.Infof("message: %+v", *message.ProtocolNeg)
		if message.ProtocolNeg.Type == TYPE_RDP_NEG_FAILURE {
			glog.Error(fmt.Sprintf("NODE_RDP_PROTOCOL_X224_NEG_FAILURE with code: %d,see https://msdn.microsoft.com/en-us/library/cc240507.aspx",
				message.ProtocolNeg.Result))
			//only use Standard RDP Security mechanisms
			if message.ProtocolNeg.Result == 2 {
				glog.Info("Only use Standard RDP Security mechanisms, Reconnect with Standard RDP")
			}
			x.Close()
			return
		}

		if message.ProtocolNeg.Type == TYPE_RDP_NEG_RSP {
			glog.Info("TYPE_RDP_NEG_RSP")
			x.selectedProtocol = message.ProtocolNeg.Result
		}
	} else {
		x.selectedProtocol = PROTOCOL_RDP
	}

	if x.selectedProtocol != PROTOCOL_HYBRID {
		glog.Error("Only Support  PROTOCOL_HYBRID NLA Security")
		return
	}
	//x.transport.On("data", x.recvData)
	glog.Info("*** NLA Security selected ***")

	err := x.transport.(*tpkt.TPKT).StartTLS()

	//credssp流程未结束，不接受下一包tpkt
	x.transport.(*tpkt.TPKT).NoReceiveNextTpktPackage = true

	x.startTlsChan <- &TlsResult{
		err: err,
	}

	if err != nil {
		glog.Info("start tls failed", err)
		return
	}
}
