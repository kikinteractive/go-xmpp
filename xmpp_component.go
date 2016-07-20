// Jabber Component implementaqtion for jabber:component:accept namespace, see http://www.xmpp.org/extensions/xep-0114.html.
package xmpp

import (
	"crypto/sha1"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

const nsComponentAccept = "jabber:component:accept"

// ComponentOptions specify additional options for component client.
type ComponentOptions struct {
	Options
	// Name holds the mandatory component name.
	Name string
}

// ComponentClient holds XMPP connection opitons for component client.
type ComponentClient struct {
	*BasicClient
	// Name holds the mandatory component name.
	Name string
}

// NewClient establishes a new component Client connection based on a set of Options.
func (o ComponentOptions) NewClient() (Client, error) {
	host := o.Host
	conn, err := connect(host, "", "")
	if err != nil {
		return nil, err
	}

	if strings.LastIndex(o.Host, ":") > 0 {
		host = host[:strings.LastIndex(o.Host, ":")]
	}

	c := &ComponentClient{
		BasicClient: &BasicClient{
			conn:  conn,
			host:  host,
			user:  o.User,
			debug: o.Debug,
		},
		Name: o.Name,
	}

	// XEP-0114 3. Protocol Flow.
	// Declare intent to be a jabber client and gather stream features.
	streamID, err := c.startStream()
	if err != nil {
		return nil, err
	}

	// Component handshake.
	if err := c.doHandshake(streamID, o.Password); err != nil {
		return nil, err
	}

	return c, nil
}

// NewComponentClient creates a new connection to a host given as "hostname" or "hostname:port"
// and initializes a component client.
func NewComponentClient(host, cname, secret string, debug bool) (Client, error) {
	if host == "" {
		return nil, fmt.Errorf("host not specified")
	}
	if cname == "" {
		return nil, fmt.Errorf("component name not specified")
	}
	if secret == "" {
		return nil, fmt.Errorf("handshake secret not specified")
	}

	opts := ComponentOptions{
		Options: Options{
			Host:     host,
			User:     "admin@" + cname,
			Password: secret,
			Debug:    debug,
			Session:  false,
		},
		Name: cname,
	}
	return opts.NewClient()
}

// startStream creates a new jabber:component:accept stream and returns stream ID.
func (c *ComponentClient) startStream() (string, error) {
	if c.debug {
		c.p = xml.NewDecoder(tee{c.conn, os.Stderr})
	} else {
		c.p = xml.NewDecoder(c.conn)
	}

	str := fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='%s' xmlns:stream='%s' version='1.0'>\n",
		xmlEscape(c.Name), nsComponentAccept, nsStream)

	if _, err := c.SendOrg(str); err != nil {
		return "", err
	}

	// We expect the server to start a <stream>.
	se, err := nextStart(c.p)
	if err != nil {
		return "", err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return "", fmt.Errorf("expected <stream> but got <%v> in %v", se.Name.Local, se.Name.Space)
	}

	// Find the stream id.
	var streamID string
	for _, attr := range se.Attr {
		if attr.Name.Local == "id" {
			streamID = attr.Value
			break
		}
	}

	if streamID == "" {
		return "", fmt.Errorf("component stream id not found")
	}

	return streamID, nil
}

// doHandshake performs the XEP-0114 component handshake on the provided component stream.
// If successful, the XML decoder is recreated with a default jabber::client namespace.
func (c *ComponentClient) doHandshake(streamID, secret string) error {
	// Create a hash with streamID and a secret.
	hash := sha1.New()
	hash.Write([]byte(streamID))
	hash.Write([]byte(secret))

	// Send handshake.
	hnd := fmt.Sprintf("<handshake>%x</handshake>\n", hash.Sum(nil))
	if _, err := c.SendOrg(hnd); err != nil {
		return err
	}

	// Read handshake reply.
	se, err := nextStart(c.p)
	if err != nil {
		return err
	}

	if se.Name.Local != "handshake" {
		if se.Name.Local == "error" {
			se, err = nextStart(c.p)
			if err != nil {
				return err
			}
			return fmt.Errorf("handshake error: %s", se.Name.Local)
		}
		return fmt.Errorf("unexpected handshake error, expected <handshake> but got <%s>", se.Name.Local)
	}

	// Handshake successful, recreate the XML decoder with a default client namespace.
	if c.debug {
		c.p = xml.NewDecoder(tee{c.conn, os.Stderr})
	} else {
		c.p = xml.NewDecoder(c.conn)
	}

	return nil
}

// Send sends the message wrapped inside an XMPP message stanza body.
// xep-0114 says that "from" should always be specified.
func (c *ComponentClient) Send(chat Chat) (n int, err error) {
	str := fmt.Sprintf("<message to='%s' from='%s' id='%s' type='%s' subject='%s' xmlns='%s' xml:lang='en'><body>%s</body></message>\n",
		xmlEscape(chat.Remote), xmlEscape(c.Name), chat.ID, xmlEscape(chat.Type), xmlEscape(chat.Subject), nsClient, xmlEscape(chat.Text))
	return c.SendOrg(str)
}
