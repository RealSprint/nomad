// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/posener/complete"
)

type VolumeRegisterCommand struct {
	Meta
}

func (c *VolumeRegisterCommand) Help() string {
	helpText := `
Usage: nomad volume register [options] <input>

  Creates or updates a volume in Nomad. The volume must exist on the remote
  storage provider before it can be used by a task.

  If the supplied path is "-" the volume file is read from stdin. Otherwise, it
  is read from the file at the supplied path.

  When ACLs are enabled, this command requires a token with the appropriate
  capability in the volume's namespace: the 'csi-write-volume' capability for
  CSI volumes or 'host-volume-register' for dynamic host volumes.

General Options:

  ` + generalOptionsUsage(usageOptsDefault) + `

Register Options:

  -id
    Update a volume previously created with this ID prefix. Used for dynamic
    host volumes only.

  -policy-override
    Sets the flag to force override any soft mandatory Sentinel policies. Used
    for dynamic host volumes only.
`

	return strings.TrimSpace(helpText)
}

func (c *VolumeRegisterCommand) AutocompleteFlags() complete.Flags {
	return mergeAutocompleteFlags(c.Meta.AutocompleteFlags(FlagSetClient),
		complete.Flags{
			"-policy-override": complete.PredictNothing,
			"-id":              complete.PredictNothing,
		})
}

func (c *VolumeRegisterCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictFiles("*")
}

func (c *VolumeRegisterCommand) Synopsis() string {
	return "Create or update a volume"
}

func (c *VolumeRegisterCommand) Name() string { return "volume register" }

func (c *VolumeRegisterCommand) Run(args []string) int {
	var override bool
	var volID string
	flags := c.Meta.FlagSet(c.Name(), FlagSetClient)
	flags.BoolVar(&override, "policy-override", false, "override soft mandatory Sentinel policies")
	flags.StringVar(&volID, "id", "", "update an existing dynamic host volume")
	flags.Usage = func() { c.Ui.Output(c.Help()) }

	if err := flags.Parse(args); err != nil {
		c.Ui.Error(fmt.Sprintf("Error parsing arguments %s", err))
		return 1
	}

	// Check that we get exactly one argument
	args = flags.Args()
	if l := len(args); l != 1 {
		c.Ui.Error("This command takes one argument: <input>")
		c.Ui.Error(commandErrorText(c))
		return 1
	}

	// Read the file contents
	file := args[0]
	var rawVolume []byte
	var err error
	if file == "-" {
		rawVolume, err = io.ReadAll(os.Stdin)
		if err != nil {
			c.Ui.Error(fmt.Sprintf("Failed to read stdin: %v", err))
			return 1
		}
	} else {
		rawVolume, err = os.ReadFile(file)
		if err != nil {
			c.Ui.Error(fmt.Sprintf("Failed to read file: %v", err))
			return 1
		}
	}

	ast, volType, err := parseVolumeType(string(rawVolume))
	if err != nil {
		c.Ui.Error(fmt.Sprintf("Error parsing the volume type: %s", err))
		return 1
	}
	volType = strings.ToLower(volType)

	// Get the HTTP client
	client, err := c.Meta.Client()
	if err != nil {
		c.Ui.Error(fmt.Sprintf("Error initializing client: %s", err))
		return 1
	}

	switch volType {
	case "csi":
		return c.csiRegister(client, ast)
	case "host":
		return c.hostVolumeRegister(client, ast, override, volID)
	default:
		c.Ui.Error(fmt.Sprintf("Error unknown volume type: %s", volType))
		return 1
	}
}

// parseVolume is used to parse the quota specification from HCL
func parseVolumeType(input string) (*ast.File, string, error) {
	// Parse the AST first
	ast, err := hcl.Parse(input)
	if err != nil {
		return nil, "", fmt.Errorf("parse error: %v", err)
	}

	// Decode the type, so we can dispatch on it
	dispatch := &struct {
		T string `hcl:"type"`
	}{}
	err = hcl.DecodeObject(dispatch, ast)
	if err != nil {
		return nil, "", fmt.Errorf("dispatch error: %v", err)
	}

	return ast, dispatch.T, nil
}
