package saltyhash

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSalty_Role(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Data: map[string]interface{}{
			"salt": testSalt,
			"mode": "append",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "roles/" + testRoleName,
	}

	doRequest := func(req *logical.Request, nilExpected bool, errExpected bool, expected string) {
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil && !errExpected {
			t.Fatal(err)
		}

		if errExpected {
			if err == nil && !resp.IsError() {
				t.Fatalf("bad: got no error response when error expected")
			}
			return
		}

		if nilExpected {
			if resp != nil {
				t.Fatal("expected nil response")
			}
			return
		}

		if !nilExpected && resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp != nil {
			if resp.IsError() {
				t.Fatalf("bad: got error response: %#v", *resp)
			}
			salt, ok := resp.Data["salt"]
			if !ok {
				t.Fatal("no salt key found in returned data")
			}
			if salt.(string) != expected {
				t.Fatalf("mismatched salts: %s != %s", salt.(string), expected)
			}
		}
	}

	// Test read role
	doRequest(req, false, false, testSalt)

	// Test update role
	req.Operation = logical.UpdateOperation
	req.Data = map[string]interface{}{
		"salt": testUpdatedSalt,
	}
	doRequest(req, true, false, "")

	// Test update role with invalid mode
	req.Data = map[string]interface{}{
		"mode": "foobar",
	}
	doRequest(req, false, true, "")

	// Test update role with valid role
	req.Data = map[string]interface{}{
		"mode": "prepend",
	}
	doRequest(req, true, false, "")

	// Test read updated role
	req.Operation = logical.ReadOperation
	doRequest(req, false, false, testUpdatedSalt)

	// Test delete role
	req.Operation = logical.DeleteOperation
	doRequest(req, true, false, "")

	// Test read non-existent role
	req.Operation = logical.ReadOperation
	doRequest(req, false, true, "")
}

