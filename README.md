# ~jwt-auth-registry~

[![CI](https://github.com/na4ma4/jwt-auth-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/na4ma4/jwt-auth-registry/actions/workflows/ci.yml)
[![CodeQL](https://github.com/na4ma4/jwt-auth-registry/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/na4ma4/jwt-auth-registry/actions/workflows/codeql-analysis.yml)
[![GitHub issues](https://img.shields.io/github/issues/na4ma4/jwt-auth-registry)](https://github.com/na4ma4/jwt-auth-registry/issues)
[![GitHub forks](https://img.shields.io/github/forks/na4ma4/jwt-auth-registry)](https://github.com/na4ma4/jwt-auth-registry/network)
[![GitHub stars](https://img.shields.io/github/stars/na4ma4/jwt-auth-registry)](https://github.com/na4ma4/jwt-auth-registry/stargazers)
[![GitHub license](https://img.shields.io/github/license/na4ma4/jwt-auth-registry)](https://github.com/na4ma4/jwt-auth-registry/blob/main/LICENSE)

**NOTE: No longer maintained.**

Authentication token provider for docker distribution registry that uses JWT tokens.

## Testing

```shell
docker run -ti --rm -p 5000:5000 --name registry \
-v "$(pwd)/artifacts/data/registry:/localconfig" \
-e 'REGISTRY_AUTH_TOKEN_REALM=http://192.168.1.157:8011/token' \
-e 'REGISTRY_AUTH_TOKEN_SERVICE=localhost:5000' \
-e 'REGISTRY_AUTH_TOKEN_ISSUER=docker-registry-auth-token' \
-e 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/localconfig/ca.pem' \
-e 'REGISTRY_AUTH_TOKEN_AUTOREDIRECT=false' \
registry:2.7.1
```

```shell
AUTH_CA_FILE="artifacts/data/test/token-users.pem" LEGACY_USERS='test1:test2' make run RUN_ARGS="-d -p 8011"
```
