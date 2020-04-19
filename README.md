godra-cli-client
================
* Godra-cli-client provides a library to start a PKCE enabled hydra login flow or a logout flow from the cli.
* At least the client id and the hydra base url needs to be defined when creating a handler.
* While performing the login flow, a http server serving a callback route is started (by default on port 8123).
* There is a working example in ./cmd/client/client.go which performs a login and a logout.


# create hydra client
To use this library, you need to create a hydra client.
The client needs to define the callback url based on the defined PORT (http://localhost:8123 for example).
As we are using PKCE, the token-endpoint-auth-method needs to be set to none.

```
# create hydra client
hydra clients create --endpoint http://localhost:4445 --fake-tls-termination -n "my-cli" -c "http://localhost:8123" --token-endpoint-auth-method none
```