package saltyhash

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const hashPath = "hash/" + testRoleName

func TestSalty_Hash(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	roleReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Data: map[string]interface{}{
			"salt": testSalt,
			"mode": "append",
		},
	}

	hashReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      hashPath,
		Data: map[string]interface{}{
			"input": testSecret,
		},
	}

	_, err := b.HandleRequest(context.Background(), roleReq)
	if err != nil {
		t.Fatal(err)
	}

	doRequest := func(req *logical.Request, errExpected bool, expected string) {
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

		if resp.IsError() {
			t.Fatalf("bad: got error response: %#v", *resp)
		}

		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		sum, ok := resp.Data["sum"]
		if !ok {
			t.Fatal("no sum key found in returned data")
		}
		if sum.(string) != expected {
			t.Fatalf("mismatched hashes: %s != %s", sum.(string), expected)
		}
	}

	// Test without algorithm
	doRequest(hashReq, true, "")

	// Test algorithm selection in the path
	hashReq.Path = hashPath + "/sha1"
	doRequest(hashReq, false, "07b9eed3480a44938e17c805c9f78accab56f40b")

	hashReq.Path = hashPath + "/sha2-256"
	doRequest(hashReq, false, "2ff3a303dfa3da97966fb2df3ee499508c365fc1f4c3aef213828e614ab7aa71")

	hashReq.Path = hashPath + "/sha2-512"
	doRequest(hashReq, false, "a98de586c4eb6f92f0eb9022332891ac253ba6bda291b2353a5df07a7241fe88e50c296bc8645edbc68422d68644aab3171c4ab2641432812522c7446918511c")

	hashReq.Path = hashPath + "/sha3-256"
	doRequest(hashReq, false, "b2389b1c4d4371ebc212e62a58ab6a3fcbe145c91f7f2e0757e255de042e6fc8")

	hashReq.Path = hashPath + "/sha3-512"
	doRequest(hashReq, false, "1a6f73fdacf3e583d370ac281aaf0b9f2ee3a06672b9ce47caf42236c9e3a2c82eff289b7a4db0eb3012c6f81dd300a7394c774b097a0a0460ad4bc7ee40a592")

	// Test bad algorithm/input
	hashReq.Path = hashPath + "/shabracadabra"
	doRequest(hashReq, true, "")

	hashReq.Path = hashPath + "/sha3-512"
	hashReq.Data["input"] = "foobar"
	doRequest(hashReq, true, "")

	hashReq.Path = hashPath + "/sha3-512"
	hashReq.Data["input"] = ""
	doRequest(hashReq, true, "")

	// Test prepend mode
	roleReq.Data["mode"] = "prepend"
	if _, err = b.HandleRequest(context.Background(), roleReq); err != nil {
		t.Fatal(err)
	}
	hashReq.Path = hashPath + "/sha2-512"
	hashReq.Data["input"] = testSecret
	doRequest(hashReq, false, "10f3d4b214fac7de2d3519e945cddfd61c8505ff3d8151b56690f372e8957ee62c22d9b8725f8baa99f62abf759e4b6be77b443fb6f93041cb8df15fd48c239b")

	// Test input parameter typo
	hashReq.Path = hashPath + "/sha3-512"
	hashReq.Data["imput"] = testSecret
	doRequest(hashReq, true, "")
}
