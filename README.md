# NoMoreLeaks Master EdgeWorker

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A defensive security EdgeWorker that validates username/password combinations against a HarperDB database to detect and prevent the use of known compromised credentials.

## Overview

The NoMoreLeaks EdgeWorker acts as middleware that intercepts login requests, generates SHA-256 hashes of username/password combinations, and validates them against a database of known compromised credentials. This helps organizations prevent account takeover attacks by blocking authentication attempts using leaked credentials.

## Features

- **Real-time Credential Validation**: Validates login attempts against known compromised credentials
- **Multiple Content-Type Support**: Handles both JSON and form-urlencoded request bodies
- **Secure Hash Generation**: Creates SHA-256 hashes of normalized username/password combinations
- **HarperDB Integration**: Queries HarperDB via subWorkers for efficient credential lookups
- **Positive Match Reporting**: Reports successful logins with known compromised credentials
- **Header Security**: Automatically removes unsafe headers from requests/responses

## Architecture

```
Client Request → EdgeWorker → Hash Generation → HarperDB Lookup → Origin Server
                    ↓
              Positive Match Reporting (if compromised credentials found)
```

## Quick Start

### Prerequisites

- Akamai EdgeWorkers environment
- HarperDB instance configured with compromised credentials
- Basic authentication credentials for HarperDB access

### Installation

1. Clone the repository:
```bash
git clone https://github.com/jjgrinwis/ew-nomoreleaks-master-harperdb.git
cd ew-nomoreleaks-master-harperdb
```

2. Install dependencies:
```bash
npm install
```

3. Configure the EdgeWorker by editing `constants.ts`:
```typescript
export const UNAME = "username";        // JSON path to username field
export const PASSWD = "password";       // JSON path to password field
export const KNOWN_KEY_URL = "https://your-harperdb-endpoint/ew-knownkey";
export const POSITIVE_MATCH_URL = "https://your-harperdb-endpoint/positiveMatch";
```

4. Set the environment variable in your delivery configuration:
```
PMUSER_AUTH_HEADER = "Basic <base64-encoded-credentials>"
```

### Build and Deploy

```bash
# Build the EdgeWorker
npm run build

# Deploy to staging
npm run activate-edgeworker

# Deploy to production
npm run activate-edgeworker-prod
```

## Configuration

### Field Mapping

The EdgeWorker supports flexible JSON path mapping for username and password fields:

```typescript
// Simple fields
export const UNAME = "username";
export const PASSWD = "password";

// Nested fields
export const UNAME = "user.email";
export const PASSWD = "credentials.password";

// Array elements
export const UNAME = "users[0].email";
```

### HarperDB Integration

Configure your HarperDB endpoints in `constants.ts`:

- **KNOWN_KEY_URL**: Endpoint for hash lookup queries
- **POSITIVE_MATCH_URL**: Endpoint for reporting positive matches

### Request Processing

The EdgeWorker processes requests in the following order:

1. **Content-Type Detection**: Supports `application/json` and `application/x-www-form-urlencoded`
2. **Credential Extraction**: Uses configured field paths to extract username/password
3. **Normalization**: Converts username to lowercase and applies NFC normalization
4. **Hash Generation**: Creates SHA-256 hash of normalized credentials
5. **Database Lookup**: Queries HarperDB for hash existence
6. **Request Forwarding**: Forwards request to origin with security headers
7. **Match Reporting**: Reports positive matches asynchronously

## API Reference

### Request Headers

- `Content-Type`: `application/json` or `application/x-www-form-urlencoded`
- `Pragma`: `akamai-x-ew-debug-rp,akamai-x-ew-subworkers,akamai-x-ew-debug-subs` (for debugging)

### Response Headers

- `x-nomoreleaks`: `true` if compromised credentials detected, `false` otherwise

### HarperDB Response Format

Expected response from HarperDB lookup:

```json
{
  "id": {
    "timestamp": 1747393156429,
    "positiveMatch": false,
    "id": "2415aa96-ef6d-4ee6-bf1f-d69072d52b02"
  }
}
```

## Development

### Available Scripts

- `npm run build`: Build TypeScript and create deployment package
- `npm run build-ts`: Compile TypeScript only
- `npm run activate-edgeworker`: Deploy to staging
- `npm run activate-edgeworker-prod`: Deploy to production
- `npm run generate-token`: Generate authentication token
- `npm run list-groups`: List EdgeWorker groups

### Testing

Test the EdgeWorker with httpie:

```bash
http POST https://your-endpoint.com/login \
  Content-Type:application/json \
  username=test@example.com \
  password=testpassword
```

Or with form data:

```bash
http --form POST https://your-endpoint.com/login \
  username=test@example.com \
  password=testpassword
```

### Debugging

Enable debug logging by adding the Pragma header:

```
Pragma: akamai-x-ew-debug-rp,akamai-x-ew-subworkers,akamai-x-ew-debug-subs
```

## Security Considerations

- **Credential Normalization**: Usernames are normalized to lowercase and NFC to prevent encoding bypasses
- **Hash Security**: Only first 5 characters of hashes are logged for security
- **Header Sanitization**: Unsafe headers are automatically removed from requests/responses
- **Non-blocking Operation**: Positive match reporting is fire-and-forget to avoid impacting user experience

## Performance

- **Efficient Hashing**: Uses Web Crypto API for optimal performance
- **Asynchronous Processing**: Database lookups and reporting are non-blocking
- **Minimal Overhead**: Lightweight implementation with minimal impact on request latency

## Troubleshooting

### Common Issues

1. **Content-Type not detected**: Ensure requests include proper Content-Type headers
2. **Hash lookup failures**: Verify HarperDB endpoint configuration and authentication
3. **Build failures**: Check TypeScript compilation and dependencies

### Logging

The EdgeWorker logs the following information:

- Generated hash prefixes (first 5 characters)
- HarperDB lookup results
- Error conditions and debugging information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

Copyright 2024 Akamai Technologies, Inc. Licensed under the Apache License, Version 2.0.

## Support

For issues and questions:
- Check the [troubleshooting guide](#troubleshooting)
- Review EdgeWorker logs for error details
- Consult [Akamai EdgeWorkers documentation](https://techdocs.akamai.com/edgeworkers/docs)