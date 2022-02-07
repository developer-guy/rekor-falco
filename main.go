package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	rekor "github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
)

// Plugin consts
const (
	PluginRequiredApiVersion        = "0.3.0"
	PluginID                 uint32 = 3
	PluginName                      = "rekor-falco"
	PluginDescription               = "A Falco Plugin to enable analyzing Rekor Transparency Server logs with Falco Rules"
	PluginContact                   = "github.com/falcosecurity/plugins"
	PluginVersion                   = "0.1.0"
	PluginEventSource               = "rekor-falco"
)

///////////////////////////////////////////////////////////////////////////////

type PluginConfig struct {
	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter.
	RekorServer string `json:"rekor_server" jsonschema:"description=Rekor server address (Default: https://rekor.sigstore.dev)"`
}

type RekorFalcoPlugin struct {
	plugins.BasePlugin
	// Contains the init configuration values
	config PluginConfig
}

type MyInstance struct {
	source.BaseInstance
	rekorclient  *rekorclient.Rekor
	currentIndex uint
}

func init() {
	p := &RekorFalcoPlugin{}
	source.Register(p)
	extractor.Register(p)
}

func (p *PluginConfig) setDefault() {
	p.RekorServer = "https://rekor.sigstore.dev"
}

func (m *RekorFalcoPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 PluginID,
		Name:               PluginName,
		Description:        PluginDescription,
		Contact:            PluginContact,
		Version:            PluginVersion,
		RequiredAPIVersion: PluginRequiredApiVersion,
		EventSource:        PluginEventSource,
	}
}

func (m *RekorFalcoPlugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *RekorFalcoPlugin) Init(cfg string) error {
	m.config.setDefault()
	json.Unmarshal([]byte(cfg), &m.config)

	return nil
}

func (m *RekorFalcoPlugin) Destroy() {
	// nothing to do here
}

func (m *RekorFalcoPlugin) Open(prms string) (source.Instance, error) {
	rc, err := rekor.GetRekorClient(m.config.RekorServer)
	if err != nil {
		return nil, err
	}

	li, err := rc.Tlog.GetLogInfo(nil)
	if err != nil {
		return nil, err
	}

	return &MyInstance{
		rekorclient:  rc,
		currentIndex: uint(*li.Payload.TreeSize),
	}, nil
}

func (m *MyInstance) Close() {
	// nothing to do here
}

func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	var n int
	var evt sdk.EventWriter
	for n = 0; n < evts.Len(); n++ {
		evt = evts.Get(n)

		log.Printf("getting log entry with index=%d", m.currentIndex)
		params := entries.NewGetLogEntryByIndexParams().
			WithLogIndex(int64(m.currentIndex)).
			WithTimeout(time.Second * 30)

		e, err := m.rekorclient.Entries.GetLogEntryByIndex(params)
		if err != nil {
			log.Printf("got error while getting log entry: %+v", err)
			continue
		}

		evt.SetTimestamp(uint64(time.Now().UnixNano()))

		p, err := json.Marshal(e.Payload)
		if err != nil {
			return 0, err
		}

		_, err = evt.Writer().Write(p)
		if err != nil {
			return 0, err
		}

		m.currentIndex++
		log.Printf("currentIndex incremented to: %d", m.currentIndex)
	}
	return n, nil
}

func (m *RekorFalcoPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	// The string representation of an event is a json object with the sample
	return fmt.Sprintf("{\"sample\": \"%s\"}", evtStr), nil
}

func (m *RekorFalcoPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "tlog.email", Desc: "The email value in the Rekor Transparency Log"},
		{Type: "string", Name: "tlog.uuid", Desc: "The UUID information of the entry"},
	}
}

func (m *RekorFalcoPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}
	var logEntry models.LogEntry
	if err = json.Unmarshal(evtBytes, &logEntry); err != nil {
		return err
	}

	var (
		email string
		uuid  string
	)

	for entryId, p := range logEntry {
		uuid = entryId
		// (3) Decode body
		decodedBody := make(map[string]interface{})
		err := json.NewDecoder(
			base64.NewDecoder(base64.URLEncoding, strings.NewReader(p.Body.(string))),
		).Decode(&decodedBody)
		if err != nil {
			return err
		}

		//content := decodedBody["spec"].(map[string]interface{})["signature"].(map[string]interface{})["publicKey"].(map[string]interface{})["content"].(string)
		var publicKeyContent string
		if spec, ok := decodedBody["spec"].(map[string]interface{}); ok {
			if signature, ok := spec["signature"].(map[string]interface{}); ok {
				if publicKey, ok := signature["publicKey"].(map[string]interface{}); ok {
					if content, ok := publicKey["content"].(string); ok {
						publicKeyContent = content
					}
				}
			}
		}

		if publicKeyContent == "" {
			return nil
		}

		certPEM, err := base64.StdEncoding.DecodeString(publicKeyContent)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			panic("failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}

		if len(cert.EmailAddresses) > 0 {
			email = cert.EmailAddresses[0]
		} else {
			log.Printf("email not found for uuid=%s", uuid)
		}
	}

	switch req.FieldID() {
	case 0: // tlog.email
		req.SetValue(email)
	case 1: // tlog.uuid
		req.SetValue(uuid)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func main() {}
