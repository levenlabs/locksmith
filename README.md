# locksmith

The locksmith is responsible for generating OpenVPN certificates for clients. It exposes an HTTP API. It talks to
a remote [cfssl](https://github.com/cloudflare/cfssl) instance to generate the certificates.

You need to have a ovpn template file that it will use to create the ovpn file. An example one is below:
```
client
dev tun
proto tcp
remote yourremote.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
remote-cert-tls server
<ca>
{{.CA}}
</ca>
<cert>
{{.Cert}}
</cert>
<key>
{{.Key}}
</key>
```

`{{.CA}}`, `{{.Cert}}`, and `{{.Key}}` fill be filled in with the certificate information automatically.

Pass the path to the template file as `--ovpn-template` and it defaults as `./ovpn.template`.

You'll also need a CA certificate that matches the cert/key that cfssl has. If cfssl is generating using a intermediate
CA certificate you'll need to provide locksmith the bundle certificate that contains the intermediate and the root CA.
This is assuming that you provided the OpenVPN server with the root CA. Pass the CA file/bundle as `--ca-file`.

Optionally the HTTP API accepts an HMAC sha256 signature in the url as the query param `sig`. When starting the server
specify the key using `--key` and then send `?sig=yoursighere` to have locksmith verify the request. The message is
the POST body of the request. An example openssl hmac bash command is:
```
$ echo -n '{"Hostname": "test@yourremote.com"}' | openssl dgst -sha256 -hmac "yourkey" | awk '{print $2}'
10ded103a220f14f02f9ee106a32348b1d0105cc8c40aa1c99ef1f115542a2ff
```

For `/list` and `/revoke` an optional `--admin-key` can be sent which should differ from `--key`. For those methods
you should instead use that key. By default `--admin-key` defaults to `--key`.

## OCSP

In addition to generating certs, locksmith can also be a OCSP responder. In your cfssl config, add
```
"ocsp_url": "https://locksmithIP:port/ocsp-verify",
```
to each profile you want to use ocsp verification. You'll also need to have a responses file and pass it to locksmith
via `--ocsp-responses-file`. The responses file should be base64-encoded responses separated by a space (or newline)
character. By default, generated certificates are NOT automatically added to the ocsp responses file. To add them
automatically, pass `--auto-ocsp-sign` to locksmith. The `/ocsp-verify` endpoint does not accept an HMAC signature.

In order to sign OCSP responses in cfssl you will need to generate a OCSP certificate/key and pass it to cfssl as
`-responder` and `-responder-key`.

Todo: add instructions for how to incorporate this into OpenSSL server

## Endpoints

### /generate

Generates a new certificate

#### Params
* `hostname` [string] the hostname to set as the CN for the certificate
* `timestamp` [int] the current unix timestamp in seconds
* `profile` [string|optional] the profile to send to cfssl
* `request` [hash|optional] the csr request to send to cfssl (optional if `--default-name-file` was specified)
    * `CN` [string|optional] common name for the certificate (defaults to `hostname`)
    * `key` [hash|optional] key options to send to cfssl (defaults to `{algo: "rsa", size: 2048}`)
    * `names` [array|optional] names to send to cfssl (defaults to `--default-name-file` if specified)
        * Keys for each name hash are: `C`, `L`, `O`, `OU`, `ST` [cfssl README](https://github.com/cloudflare/cfssl/blob/master/README.md#signing)

#### Result

Returns the contents of a new ovpn file to save as `client.conf` (on Linux) and use with OpenVPN client.
*This does not return json*


### /list

Returns a list of previously generated certificates (assuming you passed `--certs-file`)

#### Params
* `timestamp` [int] the current unix timestamp in seconds

#### Result

Returns an array of certificates. Each certificate looks like:
```
{"hostname":"laptop","remoteAddr":"10.0.0.1","generated_at":1440113442,"certificate":"MIIEWD..."}


### /revoke

Generates a new certificate

#### Params
* `certificate` [string] base64 of certificate der, or pem-encoded certificate
* `reason` [int] the reason code for the revocation
* `timestamp` [int] the current unix timestamp in seconds

#### Result

Returns `{"success": true}` or non-200 status code.
