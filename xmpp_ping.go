package xmpp

const (
	PingC2SID   = "c2s1"
	PingS2SID   = "s2s1"
	pingPayload = "<ping xmlns='urn:xmpp:ping'/>"
)

// PingC2S sends a ping from client to server.
func (c *BasicClient) PingC2S(from, server string) error {
	if from == "" {
		from = c.jid
	}
	if server == "" {
		server = c.host
	}

	_, err := c.SendIQ(IQ{
		To:      server,
		From:    from,
		ID:      PingC2SID,
		Type:    "get",
		Payload: pingPayload,
	})
	return err
}

// PingS2S sends a ping from server to server.
func (c *BasicClient) PingS2S(fromServer, toServer string) error {
	_, err := c.SendIQ(IQ{
		To:      toServer,
		From:    fromServer,
		ID:      PingS2SID,
		Type:    "get",
		Payload: pingPayload,
	})
	return err
}
