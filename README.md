# Vault Plugin: Salty Hash Secret Backend

This is standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows on-demand hashing data with configured salt.
Basically, it's [Transit Plugin](https://www.vaultproject.io/docs/secrets/transit)
or [sys/tools/hash endpoint](https://www.vaultproject.io/api-docs/system/tools#hash-data) derivative with role-based salt.

## Quick Links
    - Vault Website: https://www.vaultproject.io
    - Main Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Usage

* Configure vault to use plugins:
```sh
$ tee /path/to/vault/conf/vault.hcl <<EOF
 plugin_directory = "/path/to/vault/plugins"
 EOF
```

* Build plugin:
```sh
$ cd cmd/saltyhash/ && go build -o /path/to/vault/plugins/vault-secrets-saltyhash
```

* Register plugin in vault catalog:
```sh
$ SHASUM=$(shasum -a 256 "/path/to/vault/plugins/vault-secrets-saltyhash" | cut -d " " -f1)
$ vault write sys/plugins/catalog/vault-secrets-saltyhash \
   sha_256="$SHASUM" \
   command="vault-secrets-saltyhash"
Success! Data written to: sys/plugins/catalog/vault-secrets-saltyhash
```

* Enable plugin:
```sh
$ vault secrets enable -path=saltyhash vault-secrets-saltyhash
Success! Enabled the vault-secrets-saltyhash secrets engine at: saltyhash/
```

* Configure role with associated salt:
```sh
$ vault write saltyhash/roles/test salt="$(echo -n "secretsalt" | base64)" mode="append"
Success! Data written to: saltyhash/roles/test
```

* Hash your data via cli:
```sh
$ vault write saltyhash/hash/test/sha2-256 input=$(echo -n "secretdata" | base64)
Key    Value
---    -----
sum    675cb9ca1ed0c2d4c417c263f0fcc5a9aae12b295c311add34d003f1ac5f2e98
```
or via http request:
```sh
$ curl -k -X POST -H "X-Vault-Token: sometoken" https://vault.host:8200/v1/saltyhash/hash/test/sha2-256 -d "{ \"input\": \"$(echo -n "secretdata" | base64)\" }"
{"request_id":"48886884-8244-3783-60af-bd7660cbab30","lease_id":"","renewable":false,"lease_duration":0,"data":{"sum":"675cb9ca1ed0c2d4c417c263f0fcc5a9aae12b295c311add34d003f1ac5f2e98"},"wrap_info":null,"warnings":null,"auth":null}
```

* Same with command-line utilities to test value:
```
$ echo -n "secretdata""secretsalt" | shasum -a 256
675cb9ca1ed0c2d4c417c263f0fcc5a9aae12b295c311add34d003f1ac5f2e98  -
```

* Hash your data in batch mode:
```sh
$ curl -k -X POST -H "X-Vault-Token: sometoken" https://vault.host:8200/v1/saltyhash/hash_batch/test/sha2-256 -d "{ \"input\": [\"$(echo -n "secretdata" | base64)\", \"$(echo -n "secretdata1" | base64)\", \"$(echo -n "secretdata2" | base64)\"] }"
{"request_id":"492b5cd2-29b0-5402-bf6a-e6fe3ef5d43c","lease_id":"","renewable":false,"lease_duration":0,"data":{"sums":["675cb9ca1ed0c2d4c417c263f0fcc5a9aae12b295c311add34d003f1ac5f2e98","59a56517c595f0b78452738eb521e158cbfc05a2f3d9a09b1920d0ca000f67f2","8b84b85152113cd4bcf33b35ab534bf4ac5a5fe0dcfe5a203934abf33a5c3506"]},"wrap_info":null,"warnings":null,"auth":null}
```

* Delete role:
```sh
$ vault delete saltyhash/roles/test
Success! Data deleted (if it existed) at: saltyhash/roles/test
```

* Disable plugin:
```sh
$ vault secrets disable saltyhash
Success! Disabled the secrets engine (if it existed) at: saltyhash/
```

* Deregister plugin
```sh
$ vault plugin deregister vault-secrets-saltyhash
Success! Deregistered plugin (if it was registered): vault-secrets-saltyhash
```

## Supported algorithms
* sha1
* sha2-256
* sha2-512
* sha3-256
* sha3-512

## Supported salt modes
* append
* prepend