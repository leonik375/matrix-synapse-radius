# matrix-synapse-radius

RADIUS authentication provider for [Matrix Synapse](https://github.com/element-hq/synapse).

Authenticates users against a RADIUS server and optionally creates Matrix accounts automatically on first login. Built-in Synapse users (e.g. admin accounts created via `register_new_matrix_user`) continue to work alongside RADIUS authentication.

## Requirements

- Matrix Synapse 1.x (tested on 1.149.1)
- Python 3.8+
- [pyrad](https://github.com/wichert/pyrad) >= 2.4

## Installation

```bash
# Install into Synapse's virtualenv
/opt/venvs/matrix-synapse/bin/pip install git+https://github.com/yourusername/matrix-synapse-radius.git
```

## Configuration

Add to your Synapse config (e.g. `/etc/matrix-synapse/conf.d/radius.yaml`):

```yaml
modules:
  - module: radius_auth_provider.RadiusAuthProvider
    config:
      # RADIUS server address
      server: "127.0.0.1"
      # RADIUS shared secret
      secret: "your_radius_secret"
      # RADIUS authentication port
      port: 1812
      # Automatically create Matrix accounts for authenticated users
      create_users: true
      # NAS IP address sent to RADIUS server
      nas_ip: "127.0.0.1"
```

Restart Synapse after configuration:

```bash
systemctl restart matrix-synapse
```

## How it works

1. User attempts to log in via a Matrix client
2. Synapse calls `RadiusAuthProvider.check_password()`
3. The provider sends an `AccessRequest` to the RADIUS server
4. If RADIUS returns `AccessAccept`, the user is authenticated
5. If `create_users: true` and the Matrix account does not exist, it is created automatically
6. If RADIUS returns anything other than `AccessAccept`, Synapse falls through to its built-in authentication

## License

Apache 2.0
