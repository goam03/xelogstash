package main

import (
	"fmt"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/dustin/go-humanize/english"
	"github.com/pkg/errors"

	"github.com/goam03/xelogstash/applog"
	"github.com/goam03/xelogstash/config"
	"github.com/goam03/xelogstash/log"
	"github.com/goam03/xelogstash/status"
	"github.com/goam03/xelogstash/xe"
)

func processSource(wid int, source config.Source) (sourceResult Result, err error) {

	logmsg := fmt.Sprintf("[%d] Source: %s;  Sessions: %d", wid, source.FQDN, len(source.Sessions))
	if source.Exclude17830 {
		logmsg += ";  Excluding 17830 errors"
	}

	if !source.StartAt.IsZero() || source.StopAt != config.DefaultStopAt {
		//log.Info(fmt.Sprintf("[%d] Source: %s;  Start At: %v;  Stop At: %v", wid, source.FQDN, source.StartAt, source.StopAt))
		logmsg += fmt.Sprintf(";  Start at: %v;  Stop at %v", source.StartAt, source.StopAt)
	}
	log.Info(logmsg)

	var textMessage string
	info, err := xe.GetSQLInfo(source.FQDN)
	if err != nil {
		textMessage = fmt.Sprintf("[%d] %s - fqdn: %s err: %v", wid, info.Domain, source.FQDN, err)
		log.Error(textMessage)
		_ = applog.Error(textMessage)
		return sourceResult, errors.Wrap(err, "xe.getsqlinfo")
	}

	defer safeClose(info.DB, &err)

	cleanRun := true
	for i := range source.Sessions {
		log.Debug(fmt.Sprintf("[%d] Starting session: %s on  %s", wid, source.Sessions[i], source.FQDN))
		start := time.Now()

		var result Result
		result, err = processSession(wid, info, source, i)
		runtime := time.Since(start)
		totalSeconds := runtime.Seconds()

		var rowsPerSecond int64
		if totalSeconds > 0.0 {
			rowsPerSecond = int64(float64(result.Rows) / totalSeconds)
		}
		sourceResult.Instance = result.Instance
		sourceResult.Rows += result.Rows

		txtDuration := fmt.Sprintf(" (%s)", roundDuration(runtime, time.Second))
		if runtime.Seconds() < 10 {
			txtDuration = ""
		}

		if errors.Cause(err) == xe.ErrNotFound {
			// TODO: if strict, then warning:
			// textMessage = fmt.Sprintf("[%d] %s - %s - %s is not available.  Skipped.", wid, source.Prefix, result.Instance, result.Session)
			// _ = applog.Warn(textMessage)
			// else
			continue
		} else if err != nil {
			textMessage = fmt.Sprintf("[%d] *** ERROR: Domain: %s - FQDN: %s - %s - %s : %s\r\n", wid, info.Domain, source.FQDN, status.ClassXE, source.Sessions[i], err.Error())
			cleanRun = false
			log.Error(textMessage)
			_ = applog.Error(textMessage)
		} else {
			if rowsPerSecond > 0 && totalSeconds > 1 {
				textMessage = fmt.Sprintf("[%d] %s - %s - %s - %s %s - %s per second%s",
					wid, info.Domain, result.Instance, result.Session,
					humanize.Comma(int64(result.Rows)),
					english.PluralWord(result.Rows, "event", ""),
					humanize.Comma(int64(rowsPerSecond)),
					txtDuration,
				)
			} else {
				textMessage = fmt.Sprintf("[%d] %s - %s - %s - %s %s%s", wid, info.Domain, result.Instance, result.Session,
					humanize.Comma(int64(result.Rows)),
					english.PluralWord(result.Rows, "event", ""),
					txtDuration,
				)
			}
			if result.Rows > 0 {
				_ = applog.Info(textMessage)
			}
			log.Info(textMessage)
		}
	}

	// Process Agent Jobs
	if source.AgentJobs == config.JobsAll || source.AgentJobs == config.JobsFailed {
		start := time.Now()

		var result Result
		result, err = processAgentJobs(wid, source)
		runtime := time.Since(start)
		totalSeconds := runtime.Seconds()
		// TODO - based on the error, generate a message

		var rowsPerSecond int64
		if totalSeconds > 0.0 {
			rowsPerSecond = int64(float64(result.Rows) / totalSeconds)
		}
		sourceResult.Rows += result.Rows

		var textMessage string

		if err != nil {
			textMessage = fmt.Sprintf("[%d] *** ERROR: Domain: %s; FQDN: %s; (%s) %s\r\n", wid, info.Domain, source.FQDN, "Agent Jobs", err.Error())
			cleanRun = false
			_ = applog.Error(textMessage)
			log.Error(textMessage)
		} else {
			if rowsPerSecond > 0 && totalSeconds > 1 {
				textMessage = fmt.Sprintf("[%d] %s - %s - %s - %s %s - %s per second",
					wid, info.Domain, result.Instance, result.Session,
					humanize.Comma(int64(result.Rows)),
					english.PluralWord(result.Rows, "event", ""),
					humanize.Comma(int64(rowsPerSecond)))
			} else {
				textMessage = fmt.Sprintf("[%d] %s - %s - %s - %s %s", wid, info.Domain, result.Instance, result.Session,
					humanize.Comma(int64(result.Rows)),
					english.PluralWord(result.Rows, "event", ""))
			}
			if result.Rows > 0 {
				_ = applog.Info(textMessage)
			}
			log.Info(textMessage)
		}
	}

	if !cleanRun {
		err = errors.New("errors occurred - see previous")
	}
	return sourceResult, err
}
