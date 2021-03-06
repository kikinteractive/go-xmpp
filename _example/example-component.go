package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kikinteractive/go-xmpp"
)

var server = flag.String("server", "", "server")
var cname = flag.String("cname", "", "component name")
var secret = flag.String("secret", "", "handshake secret")
var debug = flag.Bool("debug", false, "debug output")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: example [options]\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	if *cname == "" || *secret == "" {
		flag.Usage()
	}

	talk, err := xmpp.NewComponentClient(*server, *cname, *secret, *debug)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			chat, err := talk.Recv()
			if err != nil {
				log.Fatal(err)
			}
			switch v := chat.(type) {
			case xmpp.Chat:
				fmt.Println(v.Remote, v.Text)
			case xmpp.Presence:
				fmt.Println(v.From, v.Show)
			default:
				fmt.Println(chat)
			}
		}
	}()
	for {
		in := bufio.NewReader(os.Stdin)
		line, err := in.ReadString('\n')
		if err != nil {
			continue
		}
		line = strings.TrimRight(line, "\n")

		tokens := strings.SplitN(line, " ", 2)
		if len(tokens) == 2 {
			if _, err = talk.Send(xmpp.Chat{Remote: tokens[0], Type: "chat", Text: tokens[1]}); err != nil {
				fmt.Println("send error: " + err.Error())
			}
		}
	}
}
