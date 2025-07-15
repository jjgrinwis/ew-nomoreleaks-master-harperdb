/*
Configuration constants for the NoMoreLeaks EdgeWorker.
This is the only file that should be modified for deployment.

JSON path examples:
- Simple field: "username"
- Nested field: "user.email"
- Array element: "credentials[0].username"

Test with httpie: http POST https://api.grinwis.com/login user:='{"name":"test@test.nl","password":"test"}'
*/

export const UNAME = "username";
export const PASSWD = "password";

export const KNOWN_KEY_URL = "https://nomoreleaks.grinwis.com/ew-knownkey";
export const POSITIVE_MATCH_URL = "https://nomoreleaks.grinwis.com/positiveMatch";

export const NO_MORE_LEAKS_HEADER = "x-nomoreleaks";
