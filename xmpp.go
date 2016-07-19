// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO(rsc):
//	More precise error handling.
//	Presence functionality.
// TODO(mattn):
//  Add proxy authentication.

// Package xmpp implements a simple Google Talk client
// using the XMPP protocol described in RFC 3920 and RFC 3921.
package xmpp

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	nsStream  = "http://etherx.jabber.org/streams"
	nsTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	nsClient  = "jabber:client"
	nsSession = "urn:ietf:params:xml:ns:xmpp-session"
)

// DefaultConfig contains default TLS configuration options.
var DefaultConfig tls.Config

// Cookie is a unique XMPP session identifier
type Cookie uint64

func getCookie() Cookie {
	var buf [8]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return Cookie(binary.LittleEndian.Uint64(buf[:]))
}

// Client interface.
type Client interface {
	JID() string
	Host() string
	User() string
	IsEncrypted() bool
	Roster() error
	Recv() (stanza interface{}, err error)
	Send(chat Chat) (n int, err error)
	SendOrg(org string) (n int, err error)
	SendPresence(presence Presence) (n int, err error)
	SendIQ(iq IQ) (n int, err error)
	PingC2S(jid, server string) error
	PingS2S(fromServer, toServer string) error
	Close() error
}

// BasicClient imnplements an XMPP client in jabber:client namespace.
type BasicClient struct {
	conn  net.Conn // connection to server
	jid   string   // Jabber ID for our connection
	host  string
	user  string
	p     *xml.Decoder
	debug bool
}

// JID returns the client Jabber ID.
func (c *BasicClient) JID() string {
	return c.jid
}

// Host returns XMPP connection host.
func (c *BasicClient) Host() string {
	return c.host
}

// User returns XMPP connection user.
func (c *BasicClient) User() string {
	return c.user
}

func connect(host, user, passwd string) (net.Conn, error) {
	addr := host

	if strings.TrimSpace(host) == "" {
		a := strings.SplitN(user, "@", 2)
		if len(a) == 2 {
			addr = a[1]
		}
	}
	a := strings.SplitN(host, ":", 2)
	if len(a) == 1 {
		addr += ":5222"
	}
	proxy := os.Getenv("HTTP_PROXY")
	if proxy == "" {
		proxy = os.Getenv("http_proxy")
	}
	if proxy != "" {
		url, err := url.Parse(proxy)
		if err == nil {
			addr = url.Host
		}
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if proxy != "" {
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n", host)
		fmt.Fprintf(c, "Host: %s\r\n", host)
		fmt.Fprintf(c, "\r\n")
		br := bufio.NewReader(c)
		req, _ := http.NewRequest("CONNECT", host, nil)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			return nil, errors.New(f[1])
		}
	}
	return c, nil
}

// Options are used to specify additional options for new clients, such as a Resource.
type Options struct {
	// Host specifies what host to connect to, as either "hostname" or "hostname:port"
	// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
	// Default the port to 5222.
	Host string

	// User specifies what user to authenticate to the remote server.
	User string

	// Password supplies the password to use for authentication with the remote server.
	Password string

	// Resource specifies an XMPP client resource, like "bot", instead of accepting one
	// from the server.  Use "" to let the server generate one for your client.
	Resource string

	// OAuthScope provides go-xmpp the required scope for OAuth2 authentication.
	OAuthScope string

	// OAuthToken provides go-xmpp with the required OAuth2 token used to authenticate
	OAuthToken string

	// OAuthXmlNs provides go-xmpp with the required namespaced used for OAuth2 authentication.  This is
	// provided to the server as the xmlns:auth attribute of the OAuth2 authentication request.
	OAuthXmlNs string

	// TLS Config
	TLSConfig *tls.Config

	// InsecureAllowUnencryptedAuth permits authentication over a TCP connection that has not been promoted to
	// TLS by STARTTLS; this could leak authentication information over the network, or permit man in the middle
	// attacks.
	InsecureAllowUnencryptedAuth bool

	// NoTLS directs go-xmpp to not use TLS initially to contact the server; instead, a plain old unencrypted
	// TCP connection should be used. (Can be combined with StartTLS to support STARTTLS-based servers.)
	NoTLS bool

	// StartTLS directs go-xmpp to STARTTLS if the server supports it; go-xmpp will automatically STARTTLS
	// if the server requires it regardless of this option.
	StartTLS bool

	// Debug output
	Debug bool

	// Use server sessions
	Session bool

	// Presence Status
	Status string

	// Status message
	StatusMessage string
}

// NewClient establishes a new Client connection based on a set of Options.
func (o Options) NewClient() (Client, error) {
	host := o.Host
	c, err := connect(host, o.User, o.Password)
	if err != nil {
		return nil, err
	}

	if strings.LastIndex(o.Host, ":") > 0 {
		host = host[:strings.LastIndex(o.Host, ":")]
	}

	client := &BasicClient{
		host:  host,
		user:  o.User,
		debug: o.Debug,
	}

	if o.NoTLS {
		client.conn = c
	} else {
		var tlsconn *tls.Conn
		if o.TLSConfig != nil {
			tlsconn = tls.Client(c, o.TLSConfig)
		} else {
			DefaultConfig.ServerName = host
			tlsconn = tls.Client(c, &DefaultConfig)
		}
		if err = tlsconn.Handshake(); err != nil {
			return nil, err
		}
		insecureSkipVerify := DefaultConfig.InsecureSkipVerify
		if o.TLSConfig != nil {
			insecureSkipVerify = o.TLSConfig.InsecureSkipVerify
		}
		if !insecureSkipVerify {
			if err = tlsconn.VerifyHostname(host); err != nil {
				return nil, err
			}
		}
		client.conn = tlsconn
	}

	if err := client.init(&o); err != nil {
		client.Close()
		return nil, err
	}

	return client, nil
}

// NewClient creates a new connection to a host given as "hostname" or "hostname:port".
// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
// Default the port to 5222.
func NewClient(host, user, passwd string, debug bool) (Client, error) {
	opts := Options{
		Host:     host,
		User:     user,
		Password: passwd,
		Debug:    debug,
		Session:  false,
	}
	return opts.NewClient()
}

// NewClientNoTLS creates a new client without TLS
func NewClientNoTLS(host, user, passwd string, debug bool) (Client, error) {
	opts := Options{
		Host:     host,
		User:     user,
		Password: passwd,
		NoTLS:    true,
		Debug:    debug,
		Session:  false,
	}
	return opts.NewClient()
}

// Close closes the XMPP connection
func (c *BasicClient) Close() error {
	if c.conn != (*tls.Conn)(nil) {
		return c.conn.Close()
	}
	return nil
}

func saslDigestResponse(username, realm, passwd, nonce, cnonceStr, authenticate, digestURI, nonceCountStr string) string {
	h := func(text string) []byte {
		h := md5.New()
		h.Write([]byte(text))
		return h.Sum(nil)
	}
	hex := func(bytes []byte) string {
		return fmt.Sprintf("%x", bytes)
	}
	kd := func(secret, data string) []byte {
		return h(secret + ":" + data)
	}

	a1 := string(h(username+":"+realm+":"+passwd)) + ":" + nonce + ":" + cnonceStr
	a2 := authenticate + ":" + digestURI
	response := hex(kd(hex(h(a1)), nonce+":"+nonceCountStr+":"+cnonceStr+":auth:"+hex(h(a2))))
	return response
}

func cnonce() string {
	randSize := big.NewInt(0)
	randSize.Lsh(big.NewInt(1), 64)
	cn, err := rand.Int(rand.Reader, randSize)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", cn)
}

func (c *BasicClient) init(o *Options) error {

	var domain string
	var user string
	a := strings.SplitN(o.User, "@", 2)
	if len(o.User) > 0 {
		if len(a) != 2 {
			return errors.New("xmpp: invalid username (want user@domain): " + o.User)
		}
		user = a[0]
		domain = a[1]
	} // Otherwise, we'll be attempting ANONYMOUS

	// Declare intent to be a jabber client and gather stream features.
	f, err := c.startStream(domain)
	if err != nil {
		return err
	}

	// If the server requires we STARTTLS, attempt to do so.
	if f, err = c.startTLSIfRequired(f, o, domain); err != nil {
		return err
	}

	if o.User == "" && o.Password == "" {
		foundAnonymous := false
		for _, m := range f.Mechanisms.Mechanism {
			if m == "ANONYMOUS" {
				fmt.Fprintf(c.conn, "<auth xmlns='%s' mechanism='ANONYMOUS' />\n", nsSASL)
				foundAnonymous = true
				break
			}
		}
		if !foundAnonymous {
			return fmt.Errorf("ANONYMOUS authentication is not an option and username and password were not specified")
		}
	} else {
		// Even digest forms of authentication are unsafe if we do not know that the host
		// we are talking to is the actual server, and not a man in the middle playing
		// proxy.
		if !c.IsEncrypted() && !o.InsecureAllowUnencryptedAuth {
			return errors.New("refusing to authenticate over unencrypted TCP connection")
		}

		mechanism := ""
		for _, m := range f.Mechanisms.Mechanism {
			if m == "X-OAUTH2" && o.OAuthToken != "" && o.OAuthScope != "" {
				mechanism = m
				// Oauth authentication: send base64-encoded \x00 user \x00 token.
				raw := "\x00" + user + "\x00" + o.OAuthToken
				enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
				base64.StdEncoding.Encode(enc, []byte(raw))
				fmt.Fprintf(c.conn, "<auth xmlns='%s' mechanism='X-OAUTH2' auth:service='oauth2' "+
					"xmlns:auth='%s'>%s</auth>\n", nsSASL, o.OAuthXmlNs, enc)
				break
			}
			if m == "PLAIN" {
				mechanism = m
				// Plain authentication: send base64-encoded \x00 user \x00 password.
				raw := "\x00" + user + "\x00" + o.Password
				enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
				base64.StdEncoding.Encode(enc, []byte(raw))
				fmt.Fprintf(c.conn, "<auth xmlns='%s' mechanism='PLAIN'>%s</auth>\n", nsSASL, enc)
				break
			}
			if m == "DIGEST-MD5" {
				mechanism = m
				// Digest-MD5 authentication
				fmt.Fprintf(c.conn, "<auth xmlns='%s' mechanism='DIGEST-MD5'/>\n", nsSASL)
				var ch saslChallenge
				if err = c.p.DecodeElement(&ch, nil); err != nil {
					return errors.New("unmarshal <challenge>: " + err.Error())
				}
				b, err := base64.StdEncoding.DecodeString(string(ch))
				if err != nil {
					return err
				}
				tokens := map[string]string{}
				for _, token := range strings.Split(string(b), ",") {
					kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
					if len(kv) == 2 {
						if kv[1][0] == '"' && kv[1][len(kv[1])-1] == '"' {
							kv[1] = kv[1][1 : len(kv[1])-1]
						}
						tokens[kv[0]] = kv[1]
					}
				}
				realm, _ := tokens["realm"]
				nonce, _ := tokens["nonce"]
				qop, _ := tokens["qop"]
				charset, _ := tokens["charset"]
				cnonceStr := cnonce()
				digestURI := "xmpp/" + domain
				nonceCount := fmt.Sprintf("%08x", 1)
				digest := saslDigestResponse(user, realm, o.Password, nonce, cnonceStr, "AUTHENTICATE", digestURI, nonceCount)
				message := "username=\"" + user + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", cnonce=\"" + cnonceStr +
					"\", nc=" + nonceCount + ", qop=" + qop + ", digest-uri=\"" + digestURI + "\", response=" + digest + ", charset=" + charset

				fmt.Fprintf(c.conn, "<response xmlns='%s'>%s</response>\n", nsSASL, base64.StdEncoding.EncodeToString([]byte(message)))

				var rspauth saslRspAuth
				if err = c.p.DecodeElement(&rspauth, nil); err != nil {
					return errors.New("unmarshal <challenge>: " + err.Error())
				}
				b, err = base64.StdEncoding.DecodeString(string(rspauth))
				if err != nil {
					return err
				}
				fmt.Fprintf(c.conn, "<response xmlns='%s'/>\n", nsSASL)
				break
			}
		}
		if mechanism == "" {
			return fmt.Errorf("PLAIN authentication is not an option: %v", f.Mechanisms.Mechanism)
		}
	}
	// Next message should be either success or failure.
	name, val, err := c.next(c.p)
	if err != nil {
		return err
	}
	switch v := val.(type) {
	case *saslSuccess:
	case *saslFailure:
		// v.Any is type of sub-element in failure,
		// which gives a description of what failed.
		return errors.New("auth failure: " + v.Any.Local)
	default:
		return errors.New("expected <success> or <failure>, got <" + name.Local + "> in " + name.Space)
	}

	// Now that we're authenticated, we're supposed to start the stream over again.
	// Declare intent to be a jabber client.
	if f, err = c.startStream(domain); err != nil {
		return err
	}

	// Generate a uniqe cookie
	cookie := getCookie()

	// Send IQ message asking to bind to the local user name.
	if o.Resource == "" {
		fmt.Fprintf(c.conn, "<iq type='set' id='%x'><bind xmlns='%s'></bind></iq>\n", cookie, nsBind)
	} else {
		fmt.Fprintf(c.conn, "<iq type='set' id='%x'><bind xmlns='%s'><resource>%s</resource></bind></iq>\n", cookie, nsBind, o.Resource)
	}
	var iq clientIQ
	if err = c.p.DecodeElement(&iq, nil); err != nil {
		return errors.New("unmarshal <iq>: " + err.Error())
	}
	if &iq.Bind == nil {
		return errors.New("<iq> result missing <bind>")
	}
	c.jid = iq.Bind.Jid // our local id

	if o.Session {
		//if server support session, open it
		// RFC 3921 3. Session Establishment.
		fmt.Fprintf(c.conn, "<iq to='%s' type='set' id='%x'><session xmlns='%s'/></iq>", xmlEscape(domain), cookie, nsSession)
	}

	// We're connected and can now receive and send messages.
	fmt.Fprintf(c.conn, "<presence xml:lang='en'><show>%s</show><status>%s</status></presence>", o.Status, o.StatusMessage)

	return nil
}

// startTlsIfRequired examines the server's stream features and, if STARTTLS is required or supported, performs the TLS handshake.
// f will be updated if the handshake completes, as the new stream's features are typically different from the original.
func (c *BasicClient) startTLSIfRequired(f *streamFeatures, o *Options, domain string) (*streamFeatures, error) {
	// whether we start tls is a matter of opinion: the server's and the user's.
	switch {
	case f.StartTLS == nil:
		// the server does not support STARTTLS
		return f, nil
	case f.StartTLS.Required != nil:
		// the server requires STARTTLS.
	case !o.StartTLS:
		// the user wants STARTTLS and the server supports it.
	}
	var err error

	fmt.Fprintf(c.conn, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n")
	var k tlsProceed
	if err = c.p.DecodeElement(&k, nil); err != nil {
		return f, errors.New("unmarshal <proceed>: " + err.Error())
	}

	tc := o.TLSConfig
	if tc == nil {
		tc = new(tls.Config)
		tc = &DefaultConfig
		//TODO(scott): we should consider using the server's address or reverse lookup
		tc.ServerName = domain
	}
	t := tls.Client(c.conn, tc)

	if err = t.Handshake(); err != nil {
		return f, errors.New("starttls handshake: " + err.Error())
	}
	c.conn = t

	// restart our declaration of XMPP stream intentions.
	tf, err := c.startStream(domain)
	if err != nil {
		return f, err
	}
	return tf, nil
}

// startStream will start a new XML decoder for the connection, signal the start of a stream to the server and verify that the server has
// also started the stream; if o.Debug is true, startStream will tee decoded XML data to stderr.  The features advertised by the server
// will be returned.
// RFC  3290 4. XML Streams.
func (c *BasicClient) startStream(domain string) (*streamFeatures, error) {
	if c.debug {
		c.p = xml.NewDecoder(tee{c.conn, os.Stderr})
	} else {
		c.p = xml.NewDecoder(c.conn)
	}

	_, err := fmt.Fprintf(c.conn, "<?xml version='1.0'?><stream:stream to='%s' xmlns='%s' xmlns:stream='%s' version='1.0'>\n",
		xmlEscape(domain), nsClient, nsStream)
	if err != nil {
		return nil, err
	}

	// We expect the server to start a <stream>.
	se, err := nextStart(c.p)
	if err != nil {
		return nil, err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return nil, fmt.Errorf("expected <stream> but got <%v> in %v", se.Name.Local, se.Name.Space)
	}

	// Now we're in the stream and can use Unmarshal.
	// Next message should be <features> to tell us authentication options.
	// See section 4.6 in RFC 3920.
	f := new(streamFeatures)
	if err = c.p.DecodeElement(f, nil); err != nil {
		return f, errors.New("unmarshal <features>: " + err.Error())
	}

	// Find the stream id.
	for _, attr := range se.Attr {
		if attr.Name.Local == "id" {
			f.StreamID = attr.Value
			break
		}
	}

	return f, nil
}

// IsEncrypted will return true if the client is connected using a TLS transport, either because it used.
// TLS to connect from the outset, or because it successfully used STARTTLS to promote a TCP connection to TLS.
func (c *BasicClient) IsEncrypted() bool {
	_, ok := c.conn.(*tls.Conn)
	return ok
}

// Higher-level objects to communicate with the callers.

// Chat is an incoming or outgoing XMPP chat message.
type Chat struct {
	ID      string
	Remote  string
	From    string
	Type    string
	Subject string
	Text    string
	Roster  Roster
	Other   []string
	Stamp   time.Time
	Error   error
}

// Roster is an array of contacts.
type Roster []Contact

// Contact is an XMPP contact.
type Contact struct {
	Remote string
	Name   string
	Group  []string
}

// Presence is an XMPP presence notification.
type Presence struct {
	ID     string
	From   string
	To     string
	Type   string
	Show   string
	Status string
	Error  error
}

// IQ is an XMPP info/query.
type IQ struct {
	ID      string
	From    string
	To      string
	Type    string
	Payload string
	Error   error
}

type Error struct {
	ID        string
	From      string
	Type      string
	Code      string
	Condition error
	Text      string
}

// Error implements Error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("message %s errored with code %s and condition %s", e.ID, e.Code, e.Condition)
}

// Recv waits to receive the next XMPP stanza.
// Return type is either a presence notification, a chat message or a query result.
func (c *BasicClient) Recv() (interface{}, error) {
	for {
		_, val, err := c.next(c.p)
		if err != nil {
			return nil, err
		}

		// Fill and return a corresponding high-level object.
		switch v := val.(type) {
		case *clientMessage:
			if v.Error != nil {
				return errFromStanza(v.stanza), nil
			}
			stamp, _ := time.Parse(
				time.RFC3339,
				v.Delay.Stamp,
			)
			return Chat{
				ID:      v.ID,
				From:    v.From,
				Type:    v.Type,
				Subject: v.Subject,
				Text:    v.Body,
				Other:   v.Other,
				Stamp:   stamp,
			}, nil
		case *clientQuery:
			var r Roster
			for _, item := range v.Item {
				r = append(r, Contact{item.Jid, item.Name, item.Group})
			}
			return Chat{Type: "roster", Roster: r}, nil
		case *clientPresence:
			if v.Error != nil {
				return errFromStanza(v.stanza), nil
			}
			return Presence{
				ID:     v.ID,
				From:   v.From,
				To:     v.To,
				Type:   v.Type,
				Show:   v.Show,
				Status: v.Status,
			}, nil
		case *clientIQ:
			if v.Error != nil {
				return errFromStanza(v.stanza), nil
			}
			return IQ{
				ID:   v.ID,
				From: v.From,
				To:   v.To,
				Type: v.Type,
			}, nil
		}
	}
}

func errFromStanza(v *stanza) Error {
	return Error{
		ID:        v.ID,
		From:      v.From,
		Type:      v.Error.Type,
		Code:      v.Error.Code,
		Text:      v.Error.Text,
		Condition: mapErrorCondition(v.Error.Any.Local),
	}
}

// SendOrg sends the original text without being wrapped in an XMPP message stanza.
func (c *BasicClient) SendOrg(org string) (n int, err error) {
	if c.debug {
		fmt.Println(org)
	}
	return fmt.Fprint(c.conn, org)
}

// Send sends the message wrapped inside an XMPP message stanza body.
func (c *BasicClient) Send(chat Chat) (n int, err error) {
	str := fmt.Sprintf("<message to='%s' from='%s' id='%s' type='%s' subject='%s' xmlns='%s' xml:lang='en'><body>%s</body></message>\n",
		xmlEscape(chat.Remote), xmlEscape(chat.From), chat.ID, xmlEscape(chat.Type), xmlEscape(chat.Subject), nsClient, xmlEscape(chat.Text))
	return c.SendOrg(str)
}

// SendPresence sends a presence request stanza.
func (c *BasicClient) SendPresence(presence Presence) (n int, err error) {
	str := fmt.Sprintf("<presence from='%s' to='%s' xmlns='%s'/>", xmlEscape(presence.From), xmlEscape(presence.To), nsClient)
	return c.SendOrg(str)
}

// SendIQ sends an information request/reply. stanza.
func (c *BasicClient) SendIQ(iq IQ) (n int, err error) {
	str := fmt.Sprintf("<iq from='%s' to='%s' id='%s' type='%s' xmlns='%s'>%s</iq>",
		xmlEscape(iq.From), xmlEscape(iq.To), iq.ID, iq.Type, nsClient, iq.Payload)
	return c.SendOrg(str)
}

// SendHtml sends the message as HTML as defined by XEP-0071
func (c *BasicClient) SendHtml(chat Chat) (n int, err error) {
	str := fmt.Sprintf("<message to='%s' type='%s' xmlns='%s xml:lang='en'>"+
		"<body>%s</body>"+
		"<html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>%s</body></html></message>",
		xmlEscape(chat.Remote), xmlEscape(chat.Type), nsClient, xmlEscape(chat.Text), chat.Text)
	return c.SendOrg(str)
}

// Roster asks for the chat roster.
func (c *BasicClient) Roster() error {
	str := fmt.Sprintf("<iq from='%s' type='get' id='roster1' xmlns='%s><query xmlns='jabber:iq:roster'/></iq>\n",
		xmlEscape(c.jid), nsClient)
	_, err := c.SendOrg(str)
	return err
}

// RFC 3920 4.6. Stream Features.
type streamFeatures struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams features"`

	StartTLS   *tlsStartTLS
	Mechanisms saslMechanisms
	Bind       bindBind

	// RFC 3920 B.3.
	Session bool `xml:"session,omitempty"`

	StreamID string
}

// RFC 3920 4.7. Stream Errors.
type streamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`

	Error *stanzaError `xml:"error"`
	Text  string       `xml:"text"`

	Any xml.Name `xml:",any"`
}

// RFC 3920 C.3 TLS namespace.
type tlsStartTLS struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`

	Required *string `xml:"required"`
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

// RFC 3920 C.4 SASL namespace.
type saslMechanisms struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanism []string `xml:"mechanism"`
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
}

type saslChallenge string

type saslRspAuth string

type saslResponse string

type saslAbort struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

type saslSuccess struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl success"`
}

type saslFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Any     xml.Name `xml:",any"`
}

// RFC 3920 7. Resource Binding.
type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource,omitempty"`
	Jid      string   `xml:"jid"`
}

// RFC 3920 9.1 Common stanza attributes.
type stanza struct {
	From  string       `xml:"from,attr,omitempty"`
	ID    string       `xml:"id,attr,omitempty"`
	To    string       `xml:"to,attr,omitempty"`
	Type  string       `xml:"type,attr,omitempty"` // chat, error, groupchat, headline, or normal
	Lang  string       `xml:"xml:lang,attr,omitempty"`
	Error *stanzaError `xml:"error,omitempty"`
}

// RFC 3921 2.1 Message stanza.
type clientMessage struct {
	*stanza
	XMLName xml.Name `xml:"jabber:client message"`

	// RFC 3921 2.1.2. Child Elements.
	Subject string `xml:"subject"`
	Body    string `xml:"body"`
	Thread  string `xml:"thread"`

	// Delayed delivery.
	Delay Delay `xml:"delay"`

	// Any hasn't matched element.
	Other []string `xml:",any"`
}

// Delay implements XEP-0203: Delayed Delivery.
type Delay struct {
	Stamp string `xml:"stamp,attr"`
}

type clientText struct {
	Lang string `xml:"lang,attr"`
	Text string `xml:"chardata"`
}

// RFC 3921 2.2 Presence stanza.
type clientPresence struct {
	*stanza          // error, probe, subscribe, subscribed, unavailable, unsubscribe, unsubscribed
	XMLName xml.Name `xml:"jabber:client presence"`

	// RFC 3921 2.2.2. Child Elements.
	Show     string `xml:"show"` // away, chat, dnd, xa
	Status   string `xml:"status"`
	Priority string `xml:"priority"`
}

// RFC 3921 2.3 IQ stanza.
type clientIQ struct {
	*stanza          // error, get, result, set
	XMLName xml.Name `xml:"jabber:client iq"`

	// RFC 3921 3. Session Establishment.
	Bind bindBind
}

// RFC 3921 B.5. jabber:iq:roster namespace.
type clientQuery struct {
	Item []rosterItem
}

type rosterItem struct {
	XMLName      xml.Name `xml:"jabber:iq:roster item"`
	Jid          string   `xml:"jid,attr"`
	Name         string   `xml:"name,attr"`
	Subscription string   `xml:"subscription,attr"`
	Group        []string
}

// RFC 3920 C.7. Stanza error namespace.
type stanzaError struct { // auth, cancel, continue, modify, wait
	XMLName xml.Name `xml:"error"`

	// Error legacy code and type.
	Code string `xml:"code,attr"`
	Type string `xml:"type,attr"`

	Text string `xml:"text"`

	// Condition should be here.
	Any xml.Name `xml:",any"`
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
	for {
		t, err := p.Token()
		if err != nil && err != io.EOF || t == nil {
			return xml.StartElement{}, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			return t, nil
		}
	}
}

// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func (c *BasicClient) next(p *xml.Decoder) (xml.Name, interface{}, error) {
	// Read start element to find out what type we want.
	se, err := nextStart(p)
	if err != nil {
		return xml.Name{}, nil, err
	}

	if se.Name.Space == "" {
		se.Name.Space = nsClient
	}
	// Put it in an interface and allocate one.
	var nv interface{}
	switch se.Name.Space + " " + se.Name.Local {
	case nsStream + " features":
		nv = &streamFeatures{}
	case nsStream + " error":
		nv = &streamError{}
	case nsTLS + " starttls":
		nv = &tlsStartTLS{}
	case nsTLS + " proceed":
		nv = &tlsProceed{}
	case nsTLS + " failure":
		nv = &tlsFailure{}
	case nsSASL + " mechanisms":
		nv = &saslMechanisms{}
	case nsSASL + " challenge":
		nv = ""
	case nsSASL + " response":
		nv = ""
	case nsSASL + " abort":
		nv = &saslAbort{}
	case nsSASL + " success":
		nv = &saslSuccess{}
	case nsSASL + " failure":
		nv = &saslFailure{}
	case nsBind + " bind":
		nv = &bindBind{}
	case nsClient + " message":
		nv = &clientMessage{}
	case nsClient + " presence":
		nv = &clientPresence{}
	case nsClient + " iq":
		nv = &clientIQ{}
	case nsClient + " error":
		nv = &stanzaError{}
	default:
		return xml.Name{}, nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = p.DecodeElement(nv, &se); err != nil {
		return xml.Name{}, nil, err
	}

	return se.Name, nv, err
}

var xmlSpecial = map[byte]string{
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&apos;",
	'&':  "&amp;",
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if s, ok := xmlSpecial[c]; ok {
			b.WriteString(s)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

type tee struct {
	r io.Reader
	w io.Writer
}

func (t tee) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		t.w.Write(p[0:n])
		t.w.Write([]byte("\n"))
	}
	return
}
