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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/loafoe/easyssh-proxy/v2"
)

type SshResourceManager struct {
	config       *Config
	connSettings *SshConfig
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
		"when": {
			Description:  "Determines when the commands is to be executed. Options are 'create' or 'destroy'",
			Type:         schema.TypeString,
			Optional:     true,
			Default:      "create",
			ValidateFunc: validation.StringInSlice([]string{"create", "destroy"}, false),
		},
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

	when := d.Get("when").(string)

	if when == "destroy" {
		diags, _ = mainRun(ctx, d, m, false)
	}
	if !hasErrors(diags) {
		d.SetId("")
	}
	return diags
}

func getDeleteCommands(d *schema.ResourceData) []string {
	var commands []string
	destroy := d.Get("destroy").(map[string]interface{})
	preCommands := destroy["pre_commands"].([]interface{})
	commands = append(commands, toStringSlice(preCommands)...)
	commands = append(commands, toStringSlice(destroy["commands"].([]interface{}))...)
	return commands
}

func toStringSlice(preCommands []interface{}) []string {
	var commands []string
	for _, v := range preCommands {
		commands = append(commands, v.(string))
	}
	return commands
}

func hasErrors(diags diag.Diagnostics) bool {
	for _, d := range diags {
		if d.Severity == diag.Error {
			return true
		}
	}
	return false
}

func (mgr *SshResourceManager) validateResource(d *schema.ResourceData) diag.Diagnostics {
	var diags diag.Diagnostics
	var commands []string

	timeout := d.Get("timeout").(string)
	user := d.Get("user").(string)
	agent := d.Get("agent").(bool)
	retryDelay := d.Get("retry_delay").(string)
	connect := CreateSshConfig(d.Get("connect").(map[string]interface{}))

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
	commands, diags = collectCommands(d, "commands")
	if len(diags) > 0 {
		return diags
	}
	if len(commands) > 0 {
		if user == "" {
			return diag.FromErr(fmt.Errorf("user must be set when 'commands' is specified"))
		}
		if !agent && connect.Key == "" && connect.Password == "" {
			return diag.FromErr(fmt.Errorf("'mgr.connSettings.Key' must be set when 'commands' is specified and 'agent' is false and no 'mgr.connSettings.Password' is given"))
		}
	}
	if agent && (connect.Key != "" || connect.Password != "") {
		return diag.FromErr(fmt.Errorf("agent mode is enabled, not expecting a mgr.connSettings.Password or private key"))
	}
	return diags
}

func mainRun(_ context.Context, d *schema.ResourceData, m interface{}, onUpdate bool) (diag.Diagnostics, *SshResourceManager) {
	mgr := &SshResourceManager{
		config: m.(*Config),
	}

	if md, ok := d.GetOk("connect"); ok {
		if mdd, ok := md.(map[string]interface{}); ok {
			mgr.connSettings = mgr.config.CreateSsh(mdd)
		}
	} else {
		mgr.connSettings = mgr.config.sshConfig
	}

	if diags := mgr.validateResource(d); len(diags) > 0 {
		return diags, mgr
	}

	privateKeyPassphrase, _ := schema.EnvDefaultFunc("SSH_PRIVATE_KEY_PASSPHRASE", "")()
	bastionPrivateKeyPassphrase, _ := schema.EnvDefaultFunc("SSH_BASTION_PRIVATE_KEY_PASSPHRASE", "")()

	timeout := d.Get("timeout").(string)
	retryDelay := d.Get("retry_delay").(string)

	commandsAfterFileChanges := d.Get("commands_after_file_changes").(bool)

	timeoutValue, _ := time.ParseDuration(timeout)
	retryDelayValue, _ := time.ParseDuration(retryDelay)

	// Pre commands
	preCommands, diags := collectCommands(d, "pre_commands")
	if len(diags) > 0 {
		return diags, mgr
	}
	// Fetch files first before starting provisioning
	createFiles, diags := collectFilesToCreate(d)
	if len(diags) > 0 {
		return diags, mgr
	}
	// And commands
	commands, diags := collectCommands(d, "commands")
	if len(diags) > 0 {
		return diags, mgr
	}

	// Collect SSH details
	ssh := &easyssh.MakeConfig{
		User:       mgr.connSettings.User,
		Server:     mgr.connSettings.Host,
		Port:       mgr.connSettings.Port,
		Key:        mgr.connSettings.Key,
		Passphrase: privateKeyPassphrase.(string),
		Proxy:      http.ProxyFromEnvironment,
		Bastion: easyssh.DefaultConfig{
			User:       mgr.connSettings.Bastion.User,
			Server:     mgr.connSettings.Bastion.Host,
			Passphrase: bastionPrivateKeyPassphrase.(string),
			Port:       mgr.connSettings.Bastion.Port,
		},
	}
	if mgr.connSettings.Password != "" {
		ssh.Password = mgr.connSettings.Password
	}
	if mgr.connSettings.Bastion.Password != "" {
		ssh.Bastion.Password = mgr.connSettings.Bastion.Password
	}
	if mgr.connSettings.Bastion.User != "" {
		ssh.Bastion.User = mgr.connSettings.Bastion.User
	}
	if mgr.connSettings.Key != "" {
		ssh.Bastion.Key = mgr.connSettings.Key
	}
	if mgr.connSettings.Bastion.Key != "" {
		ssh.Bastion.Key = mgr.connSettings.Bastion.Key
	}

	if onUpdate && !(d.HasChange("file") || d.HasChange("commands")) {
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

	if onUpdate && !commandsAfterFileChanges {
		return diags, mgr
	}

	// Run commands
	stdout, errDiags, err := runCommands(ctx, retryDelayValue, commands, timeoutValue, ssh, m)
	if err != nil {
		return errDiags, mgr
	}

	_ = d.Set("result", stdout)

	return diags, mgr
}

func resourceResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	when := d.Get("when").(string)

	if when == "create" {
		diags, _ = mainRun(ctx, d, m, true)
	}
	return diags
}

func resourceResourceRead(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// when := d.Get("when").(string)

	diags, _ = mainRun(ctx, d, m, false)

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

func getSshCredentials(d *schema.ResourceData) (cfg *SshConfig) {
	if v, ok := d.GetOk("ssh"); ok {
		if vL, ok := v.(map[string]interface{}); ok {
			cfg = CreateSshConfig(vL)
		}
	}
	return
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
