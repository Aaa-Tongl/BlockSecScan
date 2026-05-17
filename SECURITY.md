# Security Policy

## Supported Use Cases

BlockSecScan is designed for:

- **Authorized security testing** of systems you own or have explicit permission to test
- **Educational purposes** in classroom or lab environments
- **Self-owned asset security inspection**
- **CI/CD pipeline integration** for continuous security monitoring

## Unauthorized Use

Do **NOT** use BlockSecScan to:

- Scan public networks or hosts without explicit written authorization
- Perform denial-of-service attacks
- Attempt to exploit discovered vulnerabilities on systems you do not own
- Bypass authentication or access controls

## Safe Defaults

- RPC scanning defaults to low-risk read-only probes
- Remote target scanning displays an authorization warning
- No destructive or state-changing operations are performed by default
- CouchDB accessibility checks only verify reachability, not authentication bypass

## Reporting Vulnerabilities

If you discover a vulnerability in BlockSecScan itself, please open an issue on GitHub:
https://github.com/Aaa-Tongl/BlockSecScan/issues

## Security Boundaries

| Boundary | Policy |
|----------|--------|
| `blocksec scan rpc --target <non-local>` | Browser/user must confirm authorization |
| `blocksec scan fabric-runtime --host <remote>` | Only authorized hosts |
| Docker socket access | Read-only container inspection only |
