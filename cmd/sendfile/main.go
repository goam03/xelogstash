package main

import (
	"io/ioutil"
	"os"
	"regexp"

	"github.com/goam03/xelogstash/config"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"

	"github.com/goam03/xelogstash/log"
	"github.com/goam03/xelogstash/logstash"
)

// This utility was primarily written to test against logz.io
// They require @timestap and a field named "message"
func main() {
	var err error
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetLevel(log.DEBUG)

	log.Info("starting...")
	var opts struct {
		Logstash string `long:"logstash" description:"Logstash host in host:port format (required)"`
		Token    string `long:"token" description:"Token for logz.io testing (optional)"`
		File     string `long:"file" description:"File name of the JSON file to send (required)"`
	}

	var parser = flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	_, err = parser.Parse()
	if err != nil {
		log.Error(errors.Wrap(err, "flags.Parse"))
		os.Exit(1)
	}

	if opts.Logstash == "" {
		log.Error("logstash host is empty")
		os.Exit(1)
	}

	log.Info("logstash:", opts.Logstash)
	// log.Info("token:", opts.Token)

	var ls *logstash.Logstash
	ls, err = logstash.NewHost(&config.LogstashConf{
		Addr: opts.Logstash,
	})
	if err != nil {
		log.Fatal("logstash.newhost:", err)
	}

	f, err := ioutil.ReadFile(opts.File)
	if err != nil {
		log.Fatal("ioutil.readfile:", err)
	}

	fs := string(f)
	// strip \r\n
	re := regexp.MustCompile(`\r?\n`)
	fs = re.ReplaceAllString(fs, " ")
	log.Info(fs)
	err = ls.Writeln(fs)
	if err != nil {
		log.Fatal("ls.writeln:", err)
	}
}
