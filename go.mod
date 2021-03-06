module github.com/unflag/vault-plugin-secrets-saltyhash

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

go 1.14

require (
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/mitchellh/mapstructure v1.3.3
	github.com/morikuni/aec v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	gotest.tools/v3 v3.0.2 // indirect
)
