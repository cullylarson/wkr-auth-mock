# wkr-auth-mock

> Kinda mocks the wkr auth service, but mostly just allows for generating JWTs and verifying them against a JWKS endpoint.

NOTICE: This should not be used in production, or anywhere that is publicly accessible. It uses a hard-coded keys, committed in the repo. Counterfeit JWTs can easily be created by simply looking at the source code of this application. The intended purpose of this application is testing.

## Development

Run the linter:

```
npm run watch
```

### Integration Tests

NOTE: These tests probably only work on macos, since using `gtimeout` and `greadlink` in the `wait-for-it.sh` script.

NOTE: If running on macos, you will need `coreutils` installed.

```
brew install coreutils
```

Run integration tests:

```
npm run test:integration
```

## Usage

This command starts up a service running on a specified port. The command is added to npm's bin as `wkr-auth-mock`.

```
Usage: wkr-auth-mock -p <num> -c <string>

Options:
  --version  Show version number                                       [boolean]
  -h         Show help                                                 [boolean]
  -p         The port to listen on.                                   [required]
  -c         The claims namespace store custom parameters (e.g. permissions) in
             the JWT.                                                 [required]
```

The service exposes several endpoints.

### `/jwt`

Get a JWT. All provided parameters will be set in the JWT under the claims namespace provided when running the command.

Method: `POST`

Content Type: `application/json`

Parameters:

- **lasts** *(int, default: `3600`)* How long the JWT should last, in seconds.
- **account** *(object, optional, default: `{}`)* The account info to set in the JWT.
- **permissions** *(array, optional, default: `[]`)* The permissions to set in the JWT.
- **roles** *(array, optional, default: `[]`)* The roles to set in the JWT.
- **groups** *(array, optional, default: `[]`)* The groups to set in the JWT.

Result:

Status: 200, 500 (on error)

- **token** *(object, optional)* The JWT. May not be set if there was an error.

### `/jwks.json`

The JWKS endpoint.

Method: `GET`
