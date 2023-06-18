package ssh

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	DebugLog   = "SSH_DEBUG_LOG"
	CONNECTION = "connection"
	DEBUG_LOG  = "debug_log"
)

// Provider
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			CONNECTION: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "22",
						},
						"private_key_passphrase": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"bastion_host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"bastion_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "22",
						},
						"user": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"bastion_user": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"password": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"bastion_password": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"private_key": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"key_pass_phrase": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"bastion_private_key": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"agent": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},
			DEBUG_LOG: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "File to write debugging info to",
				DefaultFunc: schema.EnvDefaultFunc(DebugLog, ""),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"ssh_resource":           resourceResource(),
			"ssh_sensitive_resource": sensitiveResourceResource(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	config := &Config{
		sshConfig: CreateSshConfig(d.Get(CONNECTION).(map[string]interface{})),
	}

	var diags diag.Diagnostics

	config.DebugLog = d.Get(DEBUG_LOG).(string)

	if config.DebugLog != "" {
		debugFile, err := os.OpenFile(config.DebugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			config.debugFile = nil
		} else {
			config.debugFile = debugFile
		}
	}

	return config, diags
}
