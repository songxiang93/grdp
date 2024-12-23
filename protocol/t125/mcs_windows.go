//go:build windows

package t125

import "github.com/tomatome/grdp/plugin/cliprdr"

func (c *MCSClient) SetClientCliprdr() {
	c.clientNetworkData.AddVirtualChannel(cliprdr.ChannelName, cliprdr.ChannelOption)
}
