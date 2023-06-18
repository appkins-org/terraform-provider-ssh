package ssh

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/loafoe/easyssh-proxy/v2"
)

type SshResourceManager struct {
	config  *Config
	connect *SshConfig
}

func resourceResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 4,
		CreateContext: resourceResourceCreate,
		ReadContext:   resourceResourceRead,
		UpdateContext: resourceResourceUpdate,
		DeleteContext: resourceResourceDelete,
		CustomizeDiff: customDiff,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		StateUpgraders: []schema.StateUpgrader{},
		Schema:         sshResourceSchema(false),
	}
}

func customDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	if d.HasChange("file") || d.HasChange("commands") {
		_ = d.SetNewComputed("result")
	}
	return nil
}

func sshResourceSchema(sensitive bool) map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"triggers": {
			Description: "A map of arbitrary strings that, when changed, will force the 'hsdp_container_host_exec' resource to be replaced, re-running any associated commands.",
			Type:        schema.TypeMap,
			Optional:    true,
			ForceNew:    true,
		},
		"timeout": {
			Type:     schema.TypeString,
			Optional: true,
			Default:  "5m",
		},
		"retry_delay": {
			Type:     schema.TypeString,
			Optional: true,
			Default:  "10s",
		},
		"connect": {
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
		"create": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"pre_commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
					"commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},
		"update": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"pre_commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
					"commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},
		"destroy": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"pre_commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
					"commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},
		"read": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"scripts": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
					"commands": {
						Type:     schema.TypeList,
						MaxItems: 100,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},
		"file": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"source": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"content": {
						Type:      schema.TypeString,
						Optional:  true,
						Sensitive: sensitive,
					},
					"destination": {
						Type:     schema.TypeString,
						Required: true,
					},
					"permissions": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"owner": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"group": {
						Type:     schema.TypeString,
						Optional: true,
					},
				},
			},
		},
		"result": {
			Type:      schema.TypeString,
			Computed:  true,
			Sensitive: sensitive,
		},
	}
}

func resourceResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	diags, _ = mainRun(ctx, d, m, "destroy")
	if !hasErrors(diags) {
		d.SetId("")
	}
	return diags
}

func hasErrors(diags diag.Diagnostics) bool {
	for _, d := range diags {
		if d.Severity == diag.Error {
			return true
		}
	}
	return false
}

func (m *SshResourceManager) validateResource(d *schema.ResourceData) diag.Diagnostics {
	var diags diag.Diagnostics
	var commands []string

	if m.connect == nil {
		m.connect = m.config.CreateSsh(d.Get("connect").(map[string]interface{}))
	}

	timeout := d.Get("timeout").(string)
	user := d.Get("user").(string)
	agent := d.Get("agent").(bool)
	retryDelay := d.Get("retry_delay").(string)

	timeoutValue, err := time.ParseDuration(timeout)
	if err != nil {
		return diag.FromErr(fmt.Errorf("timeout value: %w", err))
	}
	retryDelayValue, err := time.ParseDuration(retryDelay)
	if err != nil {
		return diag.FromErr(fmt.Errorf("retry_delay value: %w", err))
	}
	if retryDelayValue >= timeoutValue {
		return diag.FromErr(fmt.Errorf("retry_delay cannot be greater than timeout (%d >= %d)", retryDelayValue, timeoutValue))
	}
	_, diags = collectFilesToCreate(d)
	if len(diags) > 0 {
		return diags
	}
	commands, diags = collectLifecycle(d, "create", "commands")
	if len(diags) > 0 {
		return diags
	}
	if len(commands) > 0 {
		if user == "" {
			return diag.FromErr(fmt.Errorf("user must be set when 'commands' is specified"))
		}
		if !agent && m.connect.Key == "" && m.connect.Password == "" {
			return diag.FromErr(fmt.Errorf("'mgr.connect.Key' must be set when 'commands' is specified and 'agent' is false and no 'mgr.connect.Password' is given"))
		}
	}
	if agent && (m.connect.Key != "" || m.connect.Password != "") {
		return diag.FromErr(fmt.Errorf("agent mode is enabled, not expecting a mgr.connect.Password or private key"))
	}
	return diags
}

func mainRun(_ context.Context, d *schema.ResourceData, m interface{}, stage string) (diag.Diagnostics, *SshResourceManager) {
	mgr := &SshResourceManager{
		config: m.(*Config),
	}

	if md, ok := d.GetOk("connect"); ok {
		if mdd, ok := md.(map[string]interface{}); ok {
			mgr.connect = mgr.config.CreateSsh(mdd)
		}
	} else {
		mgr.connect = mgr.config.sshConfig
	}

	if diags := mgr.validateResource(d); len(diags) > 0 {
		return diags, mgr
	}

	privateKeyPassphrase, _ := schema.EnvDefaultFunc("SSH_PRIVATE_KEY_PASSPHRASE", "")()
	bastionPrivateKeyPassphrase, _ := schema.EnvDefaultFunc("SSH_BASTION_PRIVATE_KEY_PASSPHRASE", "")()

	timeout := d.Get("timeout").(string)
	retryDelay := d.Get("retry_delay").(string)

	timeoutValue, _ := time.ParseDuration(timeout)
	retryDelayValue, _ := time.ParseDuration(retryDelay)

	// Pre commands
	preCommands, diags := collectLifecycle(d, stage, "pre_commands")
	if len(diags) > 0 {
		return diags, mgr
	}
	// Fetch files first before starting provisioning
	createFiles, diags := collectFilesToCreate(d)
	if len(diags) > 0 {
		return diags, mgr
	}
	// And commands
	commands, diags := collectLifecycle(d, stage, "commands")
	if len(diags) > 0 {
		return diags, mgr
	}

	// Collect SSH details
	ssh := &easyssh.MakeConfig{
		User:       mgr.connect.User,
		Server:     mgr.connect.Host,
		Port:       mgr.connect.Port,
		Key:        mgr.connect.Key,
		Passphrase: privateKeyPassphrase.(string),
		Proxy:      http.ProxyFromEnvironment,
		Bastion: easyssh.DefaultConfig{
			User:       mgr.connect.Bastion.User,
			Server:     mgr.connect.Bastion.Host,
			Passphrase: bastionPrivateKeyPassphrase.(string),
			Port:       mgr.connect.Bastion.Port,
		},
	}
	if mgr.connect.Password != "" {
		ssh.Password = mgr.connect.Password
	}
	if mgr.connect.Bastion.Password != "" {
		ssh.Bastion.Password = mgr.connect.Bastion.Password
	}
	if mgr.connect.Bastion.User != "" {
		ssh.Bastion.User = mgr.connect.Bastion.User
	}
	if mgr.connect.Key != "" {
		ssh.Bastion.Key = mgr.connect.Key
	}
	if mgr.connect.Bastion.Key != "" {
		ssh.Bastion.Key = mgr.connect.Bastion.Key
	}

	onUpdate := stage == "update"

	if onUpdate && !(d.HasChange("file") || d.HasChange(stage)) {
		return diags, mgr
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutValue)
	defer cancel()

	// Run pre commands
	if len(preCommands) > 0 {
		_, errDiags, err := runCommands(ctx, retryDelayValue, preCommands, timeoutValue, ssh, m)
		if err != nil {
			return errDiags, mgr
		}
	}
	// Provision files
	if err := copyFiles(ctx, retryDelayValue, ssh, mgr.config, createFiles); err != nil {
		return diag.FromErr(fmt.Errorf("copying files to remote: %w", ctx.Err())), mgr
	}

	if onUpdate && len(commands) == 0 {
		return diags, mgr
	}

	// Run commands
	stdout, errDiags, err := runCommands(ctx, retryDelayValue, commands, timeoutValue, ssh, m)
	if err != nil {
		return errDiags, mgr
	}

	if stage == "read" {
		_ = d.Set("result", stdout)
	}

	return diags, mgr
}

func resourceResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	diags, _ = mainRun(ctx, d, m, "update")
	return diags
}

func resourceResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	diags, _ = mainRun(ctx, d, m, "read")

	return diags
}

func resourceResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	diags, _ = mainRun(ctx, d, m, "create")

	if !hasErrors(diags) {
		d.SetId(fmt.Sprintf("%d", rand.Int()))
	}
	return diags
}

func runCommands(ctx context.Context, retryDelay time.Duration, commands []string, timeout time.Duration, ssh *easyssh.MakeConfig, m interface{}) (string, diag.Diagnostics, error) {
	var diags diag.Diagnostics
	var stdout, stderr string
	var done bool
	var err error
	config := m.(*Config)

	for i := 0; i < len(commands); i++ {
		for {
			stdout, stderr, done, err = ssh.Run(commands[i], timeout)
			_, _ = config.Debug("command: %s\ndone: %t\nstdout:\n%s\nstderr:\n%s\nerror: %v\n", commands[i], done, stdout, stderr, err)
			if err == nil {
				break
			}
			if strings.Contains(err.Error(), "no supported methods remain") {
				diags = append(diags, diag.FromErr(err)...)
				return stdout, diags, err
			}

			select {
			case <-time.After(retryDelay):
				// Retry

			case <-ctx.Done():
				_, _ = config.Debug("error: %v\n", err)
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  fmt.Sprintf("execution of command '%s' failed: %s: %s", commands[i], ctx.Err(), err),
					Detail:   stdout,
				})
				if stderr != "" {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Error,
						Summary:  "stderr output",
						Detail:   stderr,
					})
				}
				return stdout, diags, err
			}
		}
	}
	return stdout, diags, nil
}

func copyFiles(ctx context.Context, retryDelay time.Duration, ssh *easyssh.MakeConfig, config *Config, createFiles []provisionFile) error {
	for _, f := range createFiles {
		copyFile := func(f provisionFile) error {
			if f.Source != "" {
				src, srcErr := os.Open(f.Source)
				if srcErr != nil {
					_, _ = config.Debug("Failed to open source file %s: %v\n", f.Source, srcErr)
					return srcErr
				}
				srcStat, statErr := src.Stat()
				if statErr != nil {
					_, _ = config.Debug("Failed to stat source file %s: %v\n", f.Source, statErr)
					_ = src.Close()
					return statErr
				}
				_ = ssh.WriteFile(src, srcStat.Size(), f.Destination)
				_, _ = config.Debug("Copied %s to remote file %s:%s: %d bytes\n", f.Source, ssh.Server, f.Destination, srcStat.Size())
				_ = src.Close()
			} else {
				buffer := bytes.NewBufferString(f.Content)
				if err := ssh.WriteFile(buffer, int64(buffer.Len()), f.Destination); err != nil {
					_, _ = config.Debug("Failed to copy content to remote file %s:%s:%s: %v\n", ssh.Server, ssh.Port, f.Destination, err)
					return err
				}
				_, _ = config.Debug("Created remote file %s:%s:%s: %d bytes\n", ssh.Server, ssh.Port, f.Destination, len(f.Content))
			}
			// Permissions change
			if f.Permissions != "" {
				outStr, errStr, _, err := ssh.Run(fmt.Sprintf("chmod %s \"%s\"", f.Permissions, f.Destination))
				_, _ = config.Debug("Permissions file %s:%s: %v %v\n", f.Destination, f.Permissions, outStr, errStr)
				if err != nil {
					return err
				}
			}
			// Owner
			if f.Owner != "" {
				outStr, errStr, _, err := ssh.Run(fmt.Sprintf("chown %s \"%s\"", f.Owner, f.Destination))
				_, _ = config.Debug("Owner file %s:%s: %v %v\n", f.Destination, f.Owner, outStr, errStr)
				if err != nil {
					return err
				}
			}
			// Group
			if f.Group != "" {
				outStr, errStr, _, err := ssh.Run(fmt.Sprintf("chgrp %s \"%s\"", f.Group, f.Destination))
				_, _ = config.Debug("Group file %s:%s: %v %v\n", f.Destination, f.Group, outStr, errStr)
				if err != nil {
					return err
				}
			}
			return nil
		}
		for {
			err := copyFile(f)
			if err == nil {
				break
			}
			select {
			case <-time.After(retryDelay):
			// Retry
			case <-ctx.Done():
				return fmt.Errorf("%s: %w", ctx.Err(), err)
			}
		}
	}
	return nil
}

func collectLifecycle(d *schema.ResourceData, field string, stage string) ([]string, diag.Diagnostics) {
	life := d.Get(field).(map[string]interface{})
	if stage != "pre_commands" && stage != "commands" {
		return nil, diag.Errorf("Invalid stage: %s", stage)
	}
	return collectLifecycleCommands(life, stage)
}

func collectLifecycleCommands(d map[string]interface{}, field string) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	list := d[field].([]interface{})
	commands := make([]string, 0)
	for i := 0; i < len(list); i++ {
		commands = append(commands, list[i].(string))
	}
	return commands, diags
}

func collectCommands(d *schema.ResourceData, field string) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	list := d.Get(field).([]interface{})
	commands := make([]string, 0)
	for i := 0; i < len(list); i++ {
		commands = append(commands, list[i].(string))
	}
	return commands, diags

}

type provisionFile struct {
	Source      string
	Content     string
	Destination string
	Permissions string
	Owner       string
	Group       string
}

func collectFilesToCreate(d *schema.ResourceData) ([]provisionFile, diag.Diagnostics) {
	var diags diag.Diagnostics
	files := make([]provisionFile, 0)
	if v, ok := d.GetOk("file"); ok {
		vL := v.(*schema.Set).List()
		for _, vi := range vL {
			mVi := vi.(map[string]interface{})
			file := provisionFile{
				Source:      mVi["source"].(string),
				Content:     mVi["content"].(string),
				Destination: mVi["destination"].(string),
				Permissions: mVi["permissions"].(string),
				Owner:       mVi["owner"].(string),
				Group:       mVi["group"].(string),
			}
			if file.Source == "" && file.Content == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "conflict in file block",
					Detail:   fmt.Sprintf("file %s has neither 'source' or 'content', set one", file.Destination),
				})
				continue
			}
			if file.Source != "" && file.Content != "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "conflict in file block",
					Detail:   fmt.Sprintf("file %s has conflicting 'source' and 'content', choose only one", file.Destination),
				})
				continue
			}
			if file.Source != "" {
				src, srcErr := os.Open(file.Source)
				if srcErr != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Error,
						Summary:  "issue with source",
						Detail:   fmt.Sprintf("file %s: %v", file.Source, srcErr),
					})
					continue
				}
				_, statErr := src.Stat()
				if statErr != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Error,
						Summary:  "issue with source stat",
						Detail:   fmt.Sprintf("file %s: %v", file.Source, statErr),
					})
					_ = src.Close()
					continue
				}
				_ = src.Close()
			}
			files = append(files, file)
		}
	}
	return files, diags
}
