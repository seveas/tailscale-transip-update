# Update DNS records at TransIP based on tailscale data

If, like me, you happen to register your domains at [TransIP](https://transip.nl), use
[tailscale](https://tailscale.com) for your VPN needs and want to have DNS records for your
tailscale hostnames in one of your domains, then this tool can help you!

To use it, you need to:
- Enable TransIP API access
- Generate an API key in the TransIP control panel
- `go install github.com/seveas/tailscale-transip-update@latest`
- `tailscale-transip-update -h`

And then run the tool every time you add/remove/reinstall a node. It also can read a config file in
`~/.config/tailscale-transip-update/config.yaml`. Contents should look like:

```
user: your-transip-username
key: ~/.config/tailscale-transip-update/private-key
domain: your.domain.here
subdomain: ts
```

A subdomain is not required, just leave it empty to use the root of your domain.
