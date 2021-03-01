package saltyhash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/hashicorp/vault/sdk/framework"
	"golang.org/x/crypto/sha3"
)

func validateFieldSet(data *framework.FieldData) error {
	for f1 := range data.Raw {
		if _, ok := data.Schema[f1]; !ok {
			return fmt.Errorf("request contains invalid field: %s", f1)
		}
	}

	return nil
}

func hashFunction(algorithm string) (hash.Hash, error) {
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
		return nil, fmt.Errorf("unsupported algorithm %s", algorithm)
	}

	return hf, nil
}

func saltSecret(secret []byte, salt []byte, mode string) []byte {
	switch mode {
	case "append":
		secret = append(secret, salt...)
	case "prepend":
		secret = append(salt, secret...)
	}

	return secret
}
