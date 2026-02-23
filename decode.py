#!/usr/bin/env python3
"""
JWT Cookie Decoder for Penetration Testing
Decodes and inspects JWT tokens from cookies. Does NOT verify signatures.
Use responsibly in authorized testing environments.
"""

import json
import base64
import sys
import argparse
from typing import Dict, Any

def base64url_decode(data: str) -> bytes:
    """Decode base64url encoded string with padding."""
    # Add padding if missing
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    # Replace URL-safe chars
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode JWT token parts without verification."""
    try:
        header, payload, signature = token.split('.')
        
        # Decode header
        header_decoded = base64url_decode(header)
        header_json = json.loads(header_decoded)
        
        # Decode payload
        payload_decoded = base64url_decode(payload)
        payload_json = json.loads(payload_decoded)
        
        return {
            'header': header_json,
            'payload': payload_json,
            'signature': signature
        }
    except Exception as e:
        raise ValueError(f"Invalid JWT format: {str(e)}")

def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse cookie string into dict."""
    cookies = {}
    if cookie_string:
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
    return cookies

def main():
    parser = argparse.ArgumentParser(description='Decode JWT cookies for pentesting')
    parser.add_argument('cookies', nargs='?', help='Cookie string (e.g., "auth=eyJ...")')
    parser.add_argument('-f', '--file', help='File containing cookie strings (one per line)')
    parser.add_argument('-k', '--key', help='Specific cookie key to decode')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    if not args.cookies and not args.file:
        print("Usage: Provide cookies string or file with -f/--file")
        print("Example: python jwt_decode.py 'auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'")
        sys.exit(1)
    
    tokens_decoded = []
    
    if args.file:
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    cookies = parse_cookies(line)
                    for key, value in cookies.items():
                        if '.' in value and len(value) > 50:  # Rough JWT check
                            try:
                                decoded = decode_jwt(value)
                                tokens_decoded.append({
                                    'cookie_name': key,
                                    'token': value,
                                    'decoded': decoded
                                })
                            except ValueError:
                                pass
    else:
        cookies = parse_cookies(args.cookies)
        for key, value in cookies.items():
            if args.key and key != args.key:
                continue
            if '.' in value and len(value) > 50:
                try:
                    decoded = decode_jwt(value)
                    tokens_decoded.append({
                        'cookie_name': key,
                        'token': value,
                        'decoded': decoded
                    })
                except ValueError:
                    print(f"Skipping invalid JWT in cookie '{key}': {value[:50]}...")
    
    if not tokens_decoded:
        print("No valid JWT tokens found in provided cookies.")
        sys.exit(1)
    
    if args.json:
        print(json.dumps(tokens_decoded, indent=2))
    else:
        for token_info in tokens_decoded:
            print(f"\n{'='*60}")
            print(f"Cookie: {token_info['cookie_name']}")
            print(f"Token:  {token_info['token'][:100]}...")
            print(f"{'='*60}")
            
            print("\nHeader:")
            for k, v in token_info['decoded']['header'].items():
                print(f"  {k}: {v}")
            
            print("\nPayload:")
            for k, v in token_info['decoded']['payload'].items():
                print(f"  {k}: {v}")
            
            print("\n⚠️  Signature NOT verified!")
            print("   This is for inspection only during authorized pentesting.")

if __name__ == "__main__":
    main()
