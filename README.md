# gpbox

GlobalProtect VPN in a Docker container.

> [!IMPORTANT]
> Using a third-party client may be against your organization's VPN policy. Check before you use it.
> This project is not affiliated with Palo Alto Networks. GlobalProtect is a trademark of Palo Alto Networks.

gpbox is a small program that runs [openconnect](https://www.infradead.org/openconnect/)
and
[ocproxy](https://github.com/cernekee/ocproxy), and controls Chromium through the
DevTools protocol for the login.
Only Docker is needed to run it. Images are published for both x86-64 and ARM64.

## Usage

This example uses the `:latest` tag of the image. Change it to a specific version if you want a more stable configuration.

```bash
docker run -d --name gpbox --restart unless-stopped \
  -e GP_PORTAL=vpn.example.com \
  -e GP_FORWARDS=10000:10.0.0.10:3389,10001:10.0.0.20:22 \
  -e GP_LOGIN_PASSWORD=changeme \
  -p 127.0.0.1:6080:6080 \
  -p 127.0.0.1:1080:1080 \
  -p 127.0.0.1:10000-10001:10000-10001 \
  -v gpbox-data:/data \
  ghcr.io/jjezewski/gpbox:latest
```

1. Run `docker logs -f gpbox`.
2. Open <http://localhost:6080> and enter `GP_LOGIN_PASSWORD`.
3. When the log prints `VPN connected`, connect your clients to `localhost`:
   - Remote Desktop to `localhost:10000`
   - `ssh -p 10001 user@localhost`
   - anything with proxy support through SOCKS5 `localhost:1080`

Every port in `GP_FORWARDS` must also be published with `-p`.

You can also use Docker Compose. See [docker-compose.yaml](docker-compose.yaml).

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GP_PORTAL` | none (required) | portal or gateway address, e.g. `vpn.example.com` |
| `GP_FORWARDS` | none | list of TCP forwards, `local_port:host:port`, separated by commas |
| `GP_LOGIN_PASSWORD` | none | password for the status and login page. Empty means no password |
| `SESSION_KEY` | `1` | change it to force a new login |
| `GP_MODE` | `gateway` | `gateway`: log in directly to the gateway. `portal`: go through the portal first |
| `GP_OS` | `win` | which system gpbox claims to be: `win`, `mac-intel`, `linux-64` |
| `GP_HIP` | `1` | send a basic HIP report (`0` to disable) |
| `SOCKS_PORT` | `1080` | SOCKS5 proxy port inside the container |
| `NOVNC_PORT` | `6080` | status and login page port inside the container |

`/data` stores the saved login cookie. Without a configured volume, you log in again every time the
container is recreated.

Host names in `GP_FORWARDS` and in SOCKS5 requests are resolved through the VPN's DNS.

## Security considerations

- **The SOCKS5 proxy and the port forwards have no password.** Anyone who can reach these
  ports can use your configured VPN connection.
- **The login page has no password unless you set `GP_LOGIN_PASSWORD`.** Without one, anyone
  who can reach port 6080 sees the login window during a login and can log in.
- **`/data/session.json` gives access to your VPN session** until the VPN server ends it.

## Limitations

- **Only SAML login is supported.** Servers that ask for a username and password directly are not supported.
- **Only TCP is forwarded.** UDP services do not work through the forwards or the SOCKS5 proxy.
- **HIP checks:** openconnect sends only a basic HIP report. Servers that require specific security software may not accept it.

## Development

```bash
go vet ./...
docker build -t gpbox .
```

## License

This project is licensed under the zlib license. See the [LICENSE](LICENSE) file for more details.
