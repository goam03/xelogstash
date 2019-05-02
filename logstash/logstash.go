package logstash

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/goam03/xelogstash/config"
)

// Severity is the severity for a record
type Severity int

const (
	// Error event
	Error Severity = 3
	// Warning event
	Warning Severity = 4
	// Info event
	Info Severity = 6
)

const (
	// keepAlivePeriod is the default keep alive period
	keepAlivePeriod = time.Duration(5) * time.Second

	// defaultTimeout is the default timeout
	defaultTimeout = 180
)

var (
	// ErrNilConnection is the error when connection is nil
	ErrNilConnection = errors.New("conn & err can't both be nil")
)

func (s Severity) String() string {
	switch s {
	case 3:
		return "err"
	case 4:
		return "warning"
	case 6:
		return "info"
	default:
		return "info"
	}
}

type tlsConfig struct {
	caCert     []byte
	clientCert *tls.Certificate
}

// Logstash is the basic struct
type Logstash struct {
	Connection net.Conn
	Timeout    int    //Timeout in seconds
	Host       string // Host in host:port format

	tlsConfig *tlsConfig
}

// NewHost generates a logstash sender from a host:port format
func NewHost(conf *config.LogstashConf) (*Logstash, error) {
	if conf == nil {
		return nil, nil
	}

	var err error
	ls := &Logstash{}

	_, lsportstring, err := net.SplitHostPort(conf.Addr)
	if err != nil {
		return ls, errors.Wrap(err, "net-splithost")
	}

	if _, err = strconv.Atoi(lsportstring); err != nil {
		return ls, errors.Wrap(err, "logstash port isn't numeric")
	}

	if conf.Timeout == 0 {
		conf.Timeout = defaultTimeout
	}

	ls.Host = conf.Addr
	ls.Timeout = conf.Timeout

	if len(conf.CACertPath) > 0 || (len(conf.ClientCertPath) > 0 && len(conf.ClientKeyPath) > 0) {
		ls.tlsConfig = &tlsConfig{}

		if len(conf.ClientCertPath) > 0 && len(conf.ClientKeyPath) > 0 {
			cert, err := tls.LoadX509KeyPair(conf.ClientCertPath, conf.ClientKeyPath)
			if err != nil {
				return nil, err
			}

			ls.tlsConfig.clientCert = &cert
		}

		if len(conf.CACertPath) > 0 {
			caCert, err := ioutil.ReadFile(conf.CACertPath)
			if err != nil {
				return nil, err
			}

			ls.tlsConfig.caCert = caCert
		}
	}

	return ls, nil
}

// SetTimeouts sets the timeout value
func (ls *Logstash) setTimeouts() {
	deadline := time.Now().Add(time.Duration(ls.Timeout) * time.Second)
	ls.Connection.SetDeadline(deadline)
}

// Connect to the host
func (ls *Logstash) Connect() (net.Conn, error) {
	if ls.tlsConfig == nil {
		return ls.connect()
	}

	return ls.connectWithMutualTLS()
}

// connect connects to the host
func (ls *Logstash) connect() (net.Conn, error) {
	var connection *net.TCPConn
	addr, err := net.ResolveTCPAddr("tcp", ls.Host)
	if err != nil {
		return connection, err
	}

	connection, err = net.DialTCP("tcp", nil, addr)
	if err != nil {
		return connection, err
	}

	if connection != nil {
		connection.SetLinger(0)
		connection.SetKeepAlive(true)
		connection.SetKeepAlivePeriod(keepAlivePeriod)

		ls.Connection = connection
		ls.setTimeouts()
	}

	if connection == nil && err == nil {
		return connection, ErrNilConnection
	}

	return connection, err
}

// connectWithMutualTLS connects to the host using mutual TLS authentication
func (ls *Logstash) connectWithMutualTLS() (net.Conn, error) {
	if ls.tlsConfig == nil {
		return nil, nil
	}

	var connection *tls.Conn
	addr, err := net.ResolveTCPAddr("tcp", ls.Host)
	if err != nil {
		return nil, err
	}

	tlscnf := &tls.Config{}

	// Collect CA certificates
	if len(ls.tlsConfig.caCert) > 0 {
		tlscnf.RootCAs = x509.NewCertPool()
		tlscnf.RootCAs.AppendCertsFromPEM(ls.tlsConfig.caCert)
	}

	// Set client cert + PK
	if ls.tlsConfig.clientCert != nil {
		tlscnf.Certificates = []tls.Certificate{*ls.tlsConfig.clientCert}
	}

	// Initialize connection
	dialer := &net.Dialer{
		KeepAlive: keepAlivePeriod,
	}
	connection, err = tls.DialWithDialer(dialer, "tcp", addr.String(), tlscnf)
	if err != nil {
		return nil, err
	}

	// this is required to complete the handshake and populate the connection state
	// we are doing this so we can print the peer certificates prior to reading / writing to the connection
	if err = connection.Handshake(); err != nil {
		return nil, err
	}

	if connection != nil {
		ls.Connection = connection
		ls.setTimeouts()
	}

	if connection == nil && err == nil {
		return nil, ErrNilConnection
	}

	return connection, err
}

// Writeln send a message to the host
func (ls *Logstash) Writeln(message string) error {
	var err error
	if ls.Connection == nil {
		_, err = ls.Connect()
		if err != nil {
			return errors.Wrap(err, "connect")
		}
	}

	message = fmt.Sprintf("%s\n", message)

	_, err = ls.Connection.Write([]byte(message))
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			ls.Connection.Close()
			ls.Connection = nil
			if err != nil {
				return errors.Wrap(err, "write-timeout")
			}
		} else {
			ls.Connection.Close()
			ls.Connection = nil
			return errors.Wrap(err, "write")
		}

		// Successful write! Let's extend the timeoul.
		ls.setTimeouts()
		return nil
	}

	return err
}

// Record holds the parent struct of what we will send to logstash
type Record map[string]interface{}

// NewRecord initializes a new record
func NewRecord() Record {
	r := make(map[string]interface{})
	return r
}

// ToLower sets most fields to lower case.  Fields like message
// and various SQL statements are unchanged
// func (e *Record) ToLower() {
// 	for k, v := range *e {
// 		if k != "message" && k != "timestamp" && k != "sql_text" && k != "statement" && k != "batch_text" {
// 			s, ok := v.(string)
// 			if ok {
// 				(*e)[k] = strings.ToLower(s)
// 			}
// 		}
// 	}
// }

// ToJSON marshalls to a string
func (r *Record) ToJSON() (string, error) {
	jsonBytes, err := json.Marshal(r)
	if err != nil {
		return "", errors.Wrap(err, "marshal")
	}

	jsonString := string(jsonBytes)
	return jsonString, nil
}

// ToJSONBytes marshalls to a byte array
func (r *Record) ToJSONBytes() ([]byte, error) {
	jsonBytes, err := json.Marshal(r)
	if err != nil {
		return []byte{}, errors.Wrap(err, "marshal")
	}
	return jsonBytes, nil
}

// ProcessMods applies adds, renames, and moves to a JSON string
func ProcessMods(json string, adds, copies, moves map[string]string) (string, error) {
	var err error

	// Adds
	for k, v := range adds {
		i := getValue(v)
		if gjson.Get(json, k).Exists() {
			return json, errors.Wrapf(err, "can't overwrite key: %s", k)
		}
		json, err = sjson.Set(json, k, i)
		if err != nil {
			return json, errors.Wrapf(err, "sjson.set: %s %s", k, v)
		}
	}

	// Copies
	for src, dst := range copies {

		if gjson.Get(json, dst).Exists() {
			return json, errors.Wrapf(err, "can't overwrite key: %s", dst)
		}
		r := gjson.Get(json, src)
		if !r.Exists() {
			continue
		}
		json, err = sjson.Set(json, dst, doubleSlashes(r.Value()))
		if err != nil {
			return json, errors.Wrapf(err, "sjson.set: %s %v", dst, r.Value())
		}
		//fmt.Println(r.Value(), doubleSlashes(r.Value()))
	}

	// Moves
	for src, dst := range moves {

		if gjson.Get(json, dst).Exists() {
			return json, errors.Wrapf(err, "can't overwrite key: %s", dst)
		}

		r := gjson.Get(json, src)
		if !r.Exists() {
			continue
		}

		json, err = sjson.Set(json, dst, doubleSlashes(r.Value()))
		if err != nil {
			return json, errors.Wrapf(err, "sjson.set: %s %v", dst, r.Value())
		}

		json, err = sjson.Delete(json, src)
		if err != nil {
			return json, errors.Wrapf(err, "can't delete: %s", src)
		}
	}

	return json, err
}

func doubleSlashes(v interface{}) interface{} {
	x, ok := v.(string)
	if !ok {
		return v
	}
	return strings.Replace(x, "\\", "\\\\", -1)
}

func getValue(s string) (v interface{}) {
	var err error
	v, err = strconv.ParseBool(s)
	if err == nil {
		return v
	}

	v, err = strconv.ParseInt(s, 0, 64)
	if err == nil {
		return v
	}

	v, err = strconv.ParseFloat(s, 64)
	if err == nil {
		return v
	}

	// check for '0.7' => (string) 0.7
	if len(s) >= 2 && strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") {
		s = s[1 : len(s)-1]
	}

	return doubleSlashes(s)
}

// Set assigns a string value to a key in the event
func (r *Record) Set(key string, value interface{}) {
	(*r)[key] = value
}

// Copy value from srckey to newkey
func (r *Record) Copy(srckey, newkey string) {
	v, ok := (*r)[srckey]
	if !ok {
		r.Set(newkey, "")
		return
	}
	(*r)[newkey] = v
}

// Move old key to new key
func (r *Record) Move(oldkey, newkey string) {
	(*r).Copy(oldkey, newkey)
	delete((*r), oldkey)
}

// SetIfEmpty sets a value if one doesn't already exist
func (r *Record) SetIfEmpty(key string, value interface{}) {
	_, exists := (*r)[key]
	if !exists {
		r.Set(key, value)
	}
}
