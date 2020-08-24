package saltyhash

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"
	"hash"
)

const (
	pathHashHelpSyn = `Generate a hash sum in hex format for input data`
	pathHashHelpDesc = `Generates a hash sum of the given algorithm in hex format against the given input data.`
)

func (b *backend) pathHash() *framework.Path {
	return &framework.Path{
		Pattern: "hash/" +
			framework.GenericNameRegex("role_name") +
			"/" +
			framework.GenericNameRegex("algorithm"),
		Fields: map[string]*framework.FieldSchema{
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},

			"role_name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"algorithm": {
				Type:    framework.TypeString,
				Description: `Algorithm to use (POST URL parameter). Valid values are:
				* sha1
				* sha2-256
				* sha2-512
				* sha3-256
				* sha3-512`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathHashWrite,
		},

		HelpSynopsis:    pathHashHelpSyn,
		HelpDescription: pathHashHelpDesc,
	}
}

func (b *backend) pathHashWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	err = validateFieldSet(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	roleName := data.Get("role_name").(string)
	inputB64 := data.Get("input").(string)
	algorithm := data.Get("algorithm").(string)

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if len(input) == 0 || err != nil {
		return logical.ErrorResponse(fmt.Sprintf("input either empty or contains invalid base64: %s", err)), logical.ErrInvalidRequest
	}

	lock := b.roleLock(roleName)
	lock.RLock()
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to find role %s: %s", roleName, err)), logical.ErrInvalidRequest
	}
	lock.RUnlock()

	mode := role.Mode
	salt, err := base64.StdEncoding.DecodeString(role.Salt)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode salt as base64: %s", err)), logical.ErrInvalidRequest
	}

	switch mode {
	case "append":
		input = append(input, salt...)
	case "prepend":
		input = append(salt, input...)
	}

	var hf hash.Hash
	switch algorithm {
	case "sha1":
		hf = sha1.New()
	case "sha2-256":
		hf = sha256.New()
	case "sha2-512":
		hf = sha512.New()
	case "sha3-256":
		hf = sha3.New256()
	case "sha3-512":
		hf = sha3.New512()
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported algorithm %s", algorithm)), nil
	}

	hf.Write(input)
	retBytes := hf.Sum(nil)

	retStr := hex.EncodeToString(retBytes)

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"sum": retStr,
		},
	}

	return resp, nil
}
