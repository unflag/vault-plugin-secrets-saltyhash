package saltyhash

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathListRolesHelpSyn = `List the existing roles in this backend`
    pathListRolesHelpDesc = `Roles will be listed by the role name.`
    pathRoleHelpSyn = `Manage the roles that can be created with this backend.`
    pathRoleHelpDesc = `This path lets you manage the roles that can be created with this backend.`
)

type roleEntry struct {
	Salt string `json:"salt" mapstructure:"salt"`
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"salt": r.Salt,
	}
}

func (b *backend) pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("role_name"),
		Fields: map[string]*framework.FieldSchema{
			"role_name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"salt": {
				Type:         framework.TypeString,
				Description:  "Random base64-encoded string which will be used as an additional input to hash function",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	roleName := data.Get("role_name").(string)

	entry := &roleEntry{
		Salt: data.Get("salt").(string),
	}

	lock := b.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("roles/"+roleName, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role not found"), nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "roles/"+data.Get("role_name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "roles/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) roleLock(roleName string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.roleLocks, roleName)
}