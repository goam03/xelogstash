package main

/*

This can be tested locally using a simple TCP listener.
I use the one here: https://coderwall.com/p/wohavg/creating-a-simple-tcp-server-in-go

*/

import (
	_ "expvar"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	_ "github.com/alexbrainman/odbc"
	singleinstance "github.com/allan-simon/go-singleinstance"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"

	"github.com/goam03/xelogstash/applog"
	"github.com/goam03/xelogstash/config"
	"github.com/goam03/xelogstash/log"
	"github.com/goam03/xelogstash/summary"
)

var sha1ver string

var opts struct {
	TOMLFile string `long:"config" description:"Read configuration from this TOML file"`
	Log      bool   `long:"log" description:"Also write to log file based on the EXE name"`
	Debug    bool   `long:"debug" description:"Enable debug logging"`
}

var appConfig config.App

func runApp() error {

	var err error

	log.SetFlags(log.LstdFlags | log.LUTC)

	// did we get a full SHA1?
	if len(sha1ver) == 40 {
		sha1ver = sha1ver[0:7]
	}

	if sha1ver == "" {
		sha1ver = "dev"
	}

	var parser = flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	_, err = parser.Parse()
	if err != nil {
		log.Error(errors.Wrap(err, "flags.Parse"))
		return err
	}

	if opts.Debug {
		log.SetLevel(log.DEBUG)
	}

	// Log to file
	if opts.Log {
		var logfilename string
		logfilename, err = getLogFileName()
		if err != nil {
			log.Error("getLogFileName", err)
		}

		var lf *os.File
		lf, err = os.OpenFile(logfilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Error("failed to open log file")
			return err
		}

		multi := io.MultiWriter(os.Stdout, lf)
		log.SetOutput(multi)
	}

	log.Info("==================================================================")

	// use default config file if one isn't specified
	var fn string
	if opts.TOMLFile == "" {
		fn, err = getDefaultConfigFileName()
		if err != nil {
			log.Error(errors.Wrap(err, "getdefaultconfigfilename"))
			return err
		}
		opts.TOMLFile = fn
	}

	var settings config.Config
	settings, err = config.Get(opts.TOMLFile, version)
	if err != nil {
		log.Error(errors.Wrap(err, "config.get"))
		return err
	}

	// if config.App.Debug {
	// 	log.SetLevel(log.DEBUG)
	// }

	if settings.App.Workers == 0 {
		settings.App.Workers = runtime.NumCPU() * 4
	}
	err = applog.Initialize(settings.AppLog)
	if err != nil {
		log.Error(errors.Wrap(err, "applog.init"))
		return err
	}

	var logMessage string
	logMessage = fmt.Sprintf("app-start version: %s; workers %d; default rows: %d", version, settings.App.Workers, settings.Defaults.Rows)
	if sha1ver != "" {
		logMessage += fmt.Sprintf("; sha1: %s", sha1ver)
	}
	log.Info(logMessage)
	err = applog.Info(logMessage)
	if err != nil {
		log.Error("applog to logstash failed:", err)
		return err
	}

	// Log the logstash setting
	if settings.App.Logstash == "" {
		logMessage = "app.logstash is empty.  Not logging SQL Server events to logstash."
	} else {
		logMessage = fmt.Sprintf("app.logstash: %s", settings.App.Logstash)
	}
	log.Info(logMessage)
	err = applog.Info(logMessage)
	if err != nil {
		log.Error("applog.info:", err)
	}

	// Report the app logstash
	if settings.AppLog.Logstash == "" {
		logMessage = "applog.logstash is empty.  Not logging application events to logstash."
	} else {
		logMessage = fmt.Sprintf("applog.logstash: %s", settings.AppLog.Logstash)
	}
	log.Info(logMessage)

	// check the lock file
	lockFileName := opts.TOMLFile + ".lock"
	lockfile, err := singleinstance.CreateLockFile(lockFileName)
	if err != nil {
		msg := fmt.Sprintf("instance running: lock file: %s", lockFileName)
		log.Error(msg)
		applog.Error(msg)
		return err
	}

	appConfig = settings.App

	// Enables a web server on :8080 with basic metrics
	if appConfig.HTTPMetrics {
		go http.ListenAndServe(":8080", http.DefaultServeMux)
	}

	message, cleanRun := processall(settings)
	log.Info(message)
	if cleanRun {
		err = applog.Info(message)
	} else {
		err = applog.Error(message)
	}
	if err != nil {
		log.Error("applog to logstash failed:", err)
	}

	if settings.App.Summary {
		log.Debug("Printing summary...")
		summary.PrintSummary()
	}

	if settings.App.Samples {
		log.Debug("Printing JSON samples...")
		err = summary.PrintSamples()
		if err != nil {
			log.Error(errors.Wrap(err, "summary.printsamples"))
		}
	}

	if settings.AppLog.Samples {
		log.Debug("Printing app log samples...")
		err = applog.PrintSamples()
		if err != nil {
			log.Error(errors.Wrap(err, "applog.samples"))
		}
	}

	log.Debug("Closing lock file...")
	err = closeLockFile(lockfile)
	if err != nil {
		msg := errors.Wrap(err, "closelockfile").Error()
		log.Error(msg)
		applog.Error(msg)
		return err
	}

	log.Debug("Removing lock file...")
	err = removeLockFile(lockFileName)
	if err != nil {
		msg := errors.Wrap(err, "removelockfile").Error()
		log.Error(msg)
		applog.Error(msg)
		return err
	}
	log.Debug("Returned from removing lock file...")

	log.Debug("Cleaning old log files...")
	err = cleanOldLogFiles(7)
	if err != nil {
		log.Error(errors.Wrap(err, "cleanOldLogFiles"))
	}

	if !cleanRun {
		log.Error("*** ERROR ****")
		return err
	}

	return nil
}
