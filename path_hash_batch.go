package saltyhash

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathHashBatch() *framework.Path {
	return &framework.Path{
		Pattern: "hash_batch/" +
			framework.GenericNameRegex("role_name") +
			"/" +
			framework.GenericNameRegex("algorithm"),
		Fields: map[string]*framework.FieldSchema{
			"input": {
				Type:        framework.TypeStringSlice,
				Description: "Array of the base64-encoded inputs",
			},

			"role_name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"algorithm": {
				Type: framework.TypeString,
				Description: `Algorithm to use (POST URL parameter). Valid values are:
				* sha1
				* sha2-256
				* sha2-512
				* sha3-256
				* sha3-512`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathHashBatchWrite,
		},

		HelpSynopsis:    pathHashHelpSyn,
		HelpDescription: pathHashHelpDesc,
	}
}

func (b *backend) pathHashBatchWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	err = validateFieldSet(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	roleName := data.Get("role_name").(string)
	inputB64 := data.Get("input").([]string)
	algorithm := data.Get("algorithm").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to find role %s: %s", roleName, err)), logical.ErrInvalidRequest
	}

	hf, err := hashFunction(algorithm)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	salt, _ := base64.StdEncoding.DecodeString(role.Salt)

	retVals := make([]string, 0, len(inputB64))
	for _, s := range inputB64 {
		input, err := base64.StdEncoding.DecodeString(s)
		if len(input) == 0 || err != nil {
			return logical.ErrorResponse(fmt.Sprintf("input either empty or contains invalid base64: %s", err)), logical.ErrInvalidRequest
		}

		input = saltSecret(input, salt, role.Mode)

		_, err = hf.Write(input)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("couldn't hash data: %s", err)), logical.ErrInvalidRequest
		}

		retBytes := hf.Sum(nil)
		retStr := hex.EncodeToString(retBytes)
		retVals = append(retVals, retStr)
		hf.Reset()
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"sums": retVals,
		},
	}

	return resp, nil
}
