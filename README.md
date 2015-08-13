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

## Endpoints

### /generate

Generates a new certificate

#### Params
* `hostname` [string] the hostname to set as the CN for the certificate
* `rimestamp` [int] the current unix timestamp in seconds
* `profile` [string|optional] the profile to send to cfssl
* `request` [hash|optional] the csr request to send to cfssl (optional if `--default-name-file` was specified)
    * `CN` [string|optional] common name for the certificate (defaults to `hostname`)
    * `key` [hash|optional] key options to send to cfssl (defaults to `{algo: "rsa", size: 2048}`)
    * `names` [array|optional] names to send to cfssl (defaults to `--default-name-file` if specified)
        * Keys for each name hash are: `C`, `L`, `O`, `OU`, `ST` [cfssl README](https://github.com/cloudflare/cfssl/blob/master/README.md#signing)

#### Result

Returns a ovpn file to save as `client.conf` (on Linux) and use with OpenVPN client
