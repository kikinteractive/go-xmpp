package xmpp

import (
	"fmt"
)

func (c *BasicClient) ApproveSubscription(jid string) {
	fmt.Fprintf(c.conn, "<presence to='%s' type='subscribed'/>",
		xmlEscape(jid))
}

func (c *BasicClient) RevokeSubscription(jid string) {
	fmt.Fprintf(c.conn, "<presence to='%s' type='unsubscribed'/>",
		xmlEscape(jid))
}

func (c *BasicClient) RequestSubscription(jid string) {
	fmt.Fprintf(c.conn, "<presence to='%s' type='subscribe'/>",
		xmlEscape(jid))
}
