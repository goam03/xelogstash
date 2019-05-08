package logstash

import (
	"testing"

	"github.com/goam03/xelogstash/config"
)

func TestConnect(t *testing.T) {
	ls, err := NewHost(&config.LogstashConf{
		Addr:           "localhost:5044",
		CACertPath:     "/home/user/go/src/github.com/goam03/xelogstash/lg/ca.crt",
		ClientKeyPath:  "/home/user/go/src/github.com/goam03/xelogstash/lg/beat.key",
		ClientCertPath: "/home/user/go/src/github.com/goam03/xelogstash/lg/beat.crt",
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := ls.Connect()
	if err != nil {
		t.Fatal(err)
	}

	conn.Write([]byte("123"))
}
