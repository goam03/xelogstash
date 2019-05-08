package main

import (
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"github.com/pkg/errors"

	"github.com/goam03/xelogstash/applog"
	"github.com/goam03/xelogstash/log"
)

const (
	version = "0.33"
)

func main() {
	err := runApp()

	if log.IsDebug() {
		writeStackDump()
	}

	if err != nil {
		log.Error(fmt.Sprintf("runapp: %s", err.Error()))
		os.Exit(1)
	}

	log.Debug("exiting main")
}

func writeStackDump() {
	var err error

	log.Debug("writing stack dump to stackdump.log")
	w, err := applog.GetLogFile("stackdump.log")
	if err != nil {
		log.Error(errors.Wrap(err, "applog.getlogfile"))
	} else {
		w.WriteString("*******************************************\r\n")
		w.WriteString(fmt.Sprintf("* Timestamp: %s\r\n", time.Now().String()))
		w.WriteString("*******************************************\r\n")
		pprof.Lookup("goroutine").WriteTo(w, 2)
	}
	err = w.Sync()
	if err != nil {
		log.Error(errors.Wrap(err, "w.sync"))
	}
	err = w.Close()
	if err != nil {
		log.Error(errors.Wrap(err, "w.close"))
	}
}
