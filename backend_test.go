package saltyhash

import (
	"context"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"testing"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testRoleName = "test"
	testSalt = "dGVzdFNhbHQ="
	testUpdatedSalt = "dGVzdFVwZGF0ZWRTYWx0"
	testSecret = "dGVzdFNlY3JldA=="
)

func createBackendWithStorage(t testing.TB) (*backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := Backend(context.Background(), config)
	if b == nil {
		t.Fatalf("failed to create backend")
	}
	err := b.Backend.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b, config.StorageView
}

func TestBackend(t *testing.T) {
	logicaltest.Test(t, logicaltest.TestCase{
		LogicalFactory: Factory,
		Steps: []logicaltest.TestStep{
			testAccStepListRoles(t, testRoleName, true),
			testAccStepWriteRole(t, testRoleName, testSalt),
			testAccStepListRoles(t, testRoleName, false),
			testAccStepReadRole(t, testRoleName, testSalt),
		},
	})
}

func testAccStepListRoles(t *testing.T, roleName string, expectNone bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ListOperation,
		Path:      "roles",
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("missing response")
			}
			if expectNone {
				keysRaw, ok := resp.Data["keys"]
				if ok || keysRaw != nil {
					return fmt.Errorf("response data when expecting none")
				}
				return nil
			}
			if len(resp.Data) == 0 {
				return fmt.Errorf("no data returned")
			}

			var d struct {
				Keys []string `mapstructure:"keys"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			if len(d.Keys) > 0 && d.Keys[0] != roleName {
				return fmt.Errorf("bad name: %#v", d)
			}
			if len(d.Keys) != 1 {
				return fmt.Errorf("only 1 role expected, %d returned", len(d.Keys))
			}
			return nil
		},
	}
}

func testAccStepWriteRole(t *testing.T, roleName string, salt string) logicaltest.TestStep {
	ts := logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data: map[string]interface{}{
			"salt": salt,
			"mode": "append",
		},
	}

	return ts
}

func testAccStepReadRole(t *testing.T, roleName string, salt string) logicaltest.TestStep {
	ts := logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "roles/" + roleName,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("missing response")
			}
			if len(resp.Data) == 0 {
				return fmt.Errorf("no data returned")
			}

			var d struct {
				Role []string `mapstructure:"test"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			if len(d.Role) > 0 && d.Role[0] != roleName {
				return fmt.Errorf("bad name: %#v", d)
			}
			return nil
		},
	}

	return ts
}