package saltyhash

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend

	// Locks to make changes to role entries. These will be initialized to a
	// predefined number of locks when the backend is created, and will be
	// indexed based on salted role names.
	roleLocks []*locksutil.LockEntry
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(ctx, conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(_ context.Context, _ *logical.BackendConfig) *backend {
	b := &backend{
		roleLocks: locksutil.CreateLocks(),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
				b.pathHash(),
				b.pathHashBatch(),
				b.pathListRoles(),
				b.pathRoles(),
		},
	}

	return b
}