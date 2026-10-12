# Test on non-gateway hardware (e.g. on your Linux machine)

Create certificate and key for HTTPS in the root of the repository:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -sha256 -days 36524 -nodes -subj '/CN=example.com'
```

```bash
cargo run --features nongwhw
```

The feature `nongwhw` changes multiple things in the code:

## Faking Gateway Version and Gateway ID

The feature returns a hardcoded Gateway ID and a hardcoded OS version.

## Wi-Fi API header file

When building the project, a wrapper code for the  Wi-Fi API is generated.
This file resides in the `sg-homekit-accessory-server` repo and might not be available
during development. Therefore, a header for development is added. But keep in mind
that this header could be out of sync with the one in `sg-homekit-accessory-server`.

## Custom Password File

By default, the feature stores the hash of the custom password in
`/etc/gateway-config-interface/password`, the same path the service uses on the
gateway. To use another file, set the environment variable `TEST_PASSWORD_FILE`
to the path of that file before you start the service.

## Development Ports

This enables the use of non-privileged ports, that don't need superuser permissions
to bind to.
