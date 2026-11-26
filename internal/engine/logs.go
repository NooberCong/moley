package engine

import (
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
)

// Logs keeps the last lines of core and daemon logs in memory for the
// `logs` RPC, and mirrors them to an io.Writer (the daemon's log file).
type Logs struct {
	mu    sync.Mutex
	out   io.Writer
	lines []LogLine
	next  int
	full  bool
	level log.Level
}

type LogLine struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

const logCapacity = 2000

func NewLogs(out io.Writer, debug bool) *Logs {
	l := &Logs{out: out, lines: make([]LogLine, logCapacity), level: log.LevelInfo}
	if debug {
		l.level = log.LevelDebug
	}
	return l
}

// WriteMessage implements sing-box's log.PlatformWriter.
func (l *Logs) WriteMessage(level log.Level, message string) {
	if level > l.level {
		return
	}
	l.add(log.FormatLevel(level), message)
}

func (l *Logs) Info(msg string)  { l.add("info", msg) }
func (l *Logs) Warn(msg string)  { l.add("warn", msg) }
func (l *Logs) Error(msg string) { l.add("error", msg) }

func (l *Logs) add(level, msg string) {
	line := LogLine{Time: time.Now(), Level: level, Message: strings.TrimRight(msg, "\n")}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines[l.next] = line
	l.next = (l.next + 1) % logCapacity
	l.full = l.full || l.next == 0
	if l.out != nil {
		_, _ = io.WriteString(l.out, line.Time.Format("2006-01-02 15:04:05.000")+" "+level+" "+line.Message+"\n")
	}
}

// Since returns lines newer than t, oldest first, at most limit.
func (l *Logs) Since(t time.Time, limit int) []LogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ordered []LogLine
	if l.full {
		ordered = append(ordered, l.lines[l.next:]...)
	}
	ordered = append(ordered, l.lines[:l.next]...)
	var res []LogLine
	for _, ln := range ordered {
		if ln.Time.After(t) {
			res = append(res, ln)
		}
	}
	if limit > 0 && len(res) > limit {
		res = res[len(res)-limit:]
	}
	return res
}

var (
	ansiColor = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// connTag starts each core line about a connection: "[3188027734 9ms] ".
	connTag = regexp.MustCompile(`\[(\d+) [^\]]*\] `)
)

// ConnError is why the core failed the last connection it accepted from
// 127.0.0.1:srcPort, as it logged it: "lookup example.com: NXDOMAIN", say.
// "" if it logged no error for it (yet).
func (l *Logs) ConnError(srcPort uint16) string {
	from := "inbound connection from 127.0.0.1:" + strconv.Itoa(int(srcPort))
	id, cause := "", ""
	for _, ln := range l.Since(time.Time{}, 0) {
		msg := ansiColor.ReplaceAllString(ln.Message, "")
		tag := connTag.FindStringSubmatchIndex(msg)
		if tag == nil {
			continue
		}
		line, lineID := msg[tag[1]:], msg[tag[2]:tag[3]]
		switch {
		case strings.HasSuffix(line, from): // a newer connection from the same port
			id, cause = lineID, ""
		case lineID == id && ln.Level == "error" && cause == "":
			// "connection: open connection to host:443 using outbound/x[x]: cause"
			cause = line
			if _, rest, ok := strings.Cut(line, " using "); ok {
				if _, c, ok := strings.Cut(rest, "]: "); ok {
					cause = c
				}
			}
		}
	}
	return cause
}

type discard struct{}

func (discard) WriteMessage(log.Level, string) {}
