# JWT None Algorithm Attack Payload Generator

This Python script demonstrates a JWT (JSON Web Token) vulnerability known as the "none" algorithm attack. In this attack, an attacker can forge a JWT token by setting the algorithm to "none", which bypasses signature verification on vulnerable servers.

## How it works

1. **Header Creation**: The script creates a JWT header specifying `"alg": "none"`, indicating that no signature is required for validation.

2. **Payload Creation**: The payload contains the claims that the attacker wants to inject, such as elevated privileges (e.g., admin role) or unlimited resources (e.g., infinite credits).

3. **Token Assembly**: The header and payload are base64url-encoded and combined with a dot separator. Since the algorithm is "none", no signature is appended.

## Usage

Run the script to generate a forged JWT token:

```bash
python payload.py
```

The output will be a JWT token that looks like: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoicm9vdCIsInJvbGUiOiJhZG1pbiJ9.`

## Security Note

This script is for educational purposes only to demonstrate JWT vulnerabilities. In a real-world scenario, servers should never accept JWTs with the "none" algorithm unless explicitly configured to do so in a secure manner. Always validate JWT signatures properly.

## Requirements

- Python 3.x
- Standard library modules: `base64`, `json`

## Fix

To prevent this attack, servers should:
- Reject JWTs with `"alg": "none"`
- Always verify signatures for supported algorithms
- Use secure key management