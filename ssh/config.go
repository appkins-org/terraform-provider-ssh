package ssh

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type SshConfig struct {
	Host          string     `json:"host"`
	Port          string     `json:"port"`
	User          string     `json:"user"`
	Password      string     `json:"password"`
	Key           string     `json:"key"`
	KeyPassphrase string     `json:"key_passphrase"`
	Bastion       *SshConfig `json:"bastion"`
}

type Config struct {
	DebugLog  string
	debugFile *os.File
	sshConfig *SshConfig
}

func CreateSshConfig(m map[string]interface{}) *SshConfig {
	conf := &SshConfig{
		Host:          m["host"].(string),
		Port:          m["port"].(string),
		User:          m["user"].(string),
		Password:      m["password"].(string),
		Key:           m["key"].(string),
		KeyPassphrase: "",
		Bastion: &SshConfig{
			Host:     m["bastion_host"].(string),
			Port:     m["bastion_port"].(string),
			User:     m["bastion_user"].(string),
			Password: m["bastion_password"].(string),
			Key:      m["bastion_key"].(string),
		},
	}
	if pass, err := schema.EnvDefaultFunc("SSH_PRIVATE_KEY_PASSPHRASE", "")(); err == nil {
		conf.KeyPassphrase = pass.(string)
	} else if pass, ok := m["key_passphrase"].(string); ok {
		conf.KeyPassphrase = pass
	}

	if pass, err := schema.EnvDefaultFunc("SSH_BASTION_PRIVATE_KEY_PASSPHRASE", "")(); err == nil {
		conf.Bastion.KeyPassphrase = pass.(string)
	} else if pass, ok := m["key_passphrase"].(string); ok {
		conf.Bastion.KeyPassphrase = pass
	}
	return conf
}

func GetOrDefault[V comparable](m map[string]interface{}, k string, d V) V {
	if vv, ok := m[k].(V); ok {
		return vv
	} else {
		return d
	}
}

func (c *Config) CreateSsh(m map[string]interface{}) (r *SshConfig) {
	r.Host = GetOrDefault(m, "host", c.sshConfig.Host)
	r.Port = GetOrDefault(m, "port", c.sshConfig.Port)
	r.User = GetOrDefault(m, "user", c.sshConfig.User)
	r.Password = GetOrDefault(m, "password", c.sshConfig.Password)
	r.Bastion.Host = GetOrDefault(m, "bastion_host", c.sshConfig.Bastion.Host)
	r.Bastion.Port = GetOrDefault(m, "bastion_port", c.sshConfig.Bastion.Port)
	r.Bastion.User = GetOrDefault(m, "bastion_user", c.sshConfig.Bastion.User)
	r.Bastion.Password = GetOrDefault(m, "bastion_password", c.sshConfig.Bastion.Password)
	r.Bastion.Key = GetOrDefault(m, "bastion_key", c.sshConfig.Bastion.Key)
	return
}

func MergeSshConfigs(a *SshConfig, b *SshConfig) (m *SshConfig) {
	ja, _ := json.Marshal(a)
	json.Unmarshal(ja, &m)
	jb, _ := json.Marshal(b)
	json.Unmarshal(jb, &m)
	return
}

func (c *Config) Debug(format string, args ...interface{}) (int, error) {
	if c.debugFile != nil {
		output := fmt.Sprintf(format, args...)
		return c.debugFile.WriteString(output)
	}
	return fmt.Printf(format, args...)
}
