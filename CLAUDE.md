# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Akamai EdgeWorker that implements a security system called "NoMoreLeaks" which validates username/password combinations against a HarperDB database. The EdgeWorker acts as middleware to detect known compromised credentials and prevent unauthorized access.

### Core Architecture

The system follows a defensive security pattern:

1. **Request Interception**: The EdgeWorker intercepts login requests (both JSON and form-urlencoded)
2. **Hash Generation**: Creates SHA-256 hash of normalized username+password combination
3. **Database Lookup**: Queries HarperDB via subWorker to check if the hash exists in known compromised credentials
4. **Response Modification**: Adds security headers and forwards request to origin
5. **Positive Match Reporting**: Reports successful logins with known compromised credentials

### Key Files

- **`main.ts`**: Primary EdgeWorker code containing the `responseProvider` function
- **`constants.ts`**: Configuration file - **this is the only file that should be modified for deployment**
- **`utils.ts`**: Helper functions for JSON path navigation and validation
- **`generateDigest.ts`**: SHA-256 hash generation utility

## Common Commands

### Build and Deploy
```bash
# Build TypeScript and create deployment package
npm run build

# Build only TypeScript
npm run build-ts

# Upload to staging environment
npm run activate-edgeworker

# Deploy to production
npm run activate-edgeworker-prod
```

### Development
```bash
# Install dependencies
npm install

# Generate authentication token
npm run generate-token

# List EdgeWorker groups
npm run list-groups
```

## Configuration

All configuration changes should be made in `constants.ts`:

- **`UNAME`**: JSON path to username field (e.g., "username", "user.email")
- **`PASSWD`**: JSON path to password field (e.g., "password", "credentials.password")
- **`KNOWN_KEY_URL`**: HarperDB subWorker endpoint for hash lookup
- **`POSITIVE_MATCH_URL`**: Endpoint for reporting successful logins with compromised credentials
- **`NO_MORE_LEAKS_HEADER`**: Header name added to origin requests

## EdgeWorker Environment Variables

Set `PMUSER_AUTH_HEADER` in your delivery configuration:
- Contains basic auth info for HarperDB
- Format: `'Basic bm1sX......s='`

## Request Flow

1. Client sends login request (JSON or form-urlencoded)
2. EdgeWorker extracts username/password using paths from `constants.ts`
3. Credentials are normalized (lowercase, NFC) and hashed with SHA-256
4. Hash is sent to HarperDB via `KNOWN_KEY_URL` subWorker
5. If hash exists, user ID is returned for positive match reporting
6. Request is forwarded to origin with security header
7. If login succeeds and hash was found, positive match is reported to `POSITIVE_MATCH_URL`

## HarperDB Response Format

The system expects this response format from HarperDB:
```json
{
  "id": {
    "timestamp": 1747393156429,
    "positiveMatch": false,
    "id": "2415aa96-ef6d-4ee6-bf1f-d69072d52b02"
  }
}
```

## Security Features

- Unsafe headers are automatically removed from requests/responses
- Credentials are normalized to prevent encoding bypasses
- Only first 5 characters of hashes are logged for security
- Positive match reporting is fire-and-forget (non-blocking)
- EW-bypass header is added for subWorker authentication

## Testing

Test with httpie:
```bash
http POST https://api.grinwis.com/login user:='{"name":"test@test.nl","password":"test"}'
```

## TypeScript Configuration

- Target: ES2022
- Module: ES2022
- Output: `built/` directory
- Source maps: disabled