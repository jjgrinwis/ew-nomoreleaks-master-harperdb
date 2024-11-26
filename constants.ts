/*
This is the only file that should be updated.
It defines some constants including the JSON path to lookup the UNAME and PASSWD so can look like user.email for example.
If you want to test with httpie: http POST https://api.grinwis.com/login user:='{"name":"test@test.nl","password":"test"}'
*/

// define the json fields where username and password can be found.
export const UNAME = "username";
export const PASSWD = "password";

// some subworker endpoints
export const KNOWN_KEY_URL = "https://nomoreleaks.grinwis.com/ew-knownkey";
export const POSITIVE_MATCH_URL =
  "https://nomoreleaks.grinwis.com/positiveMatch"; // case sensitive endpoint

// header that's going to be forwarded to the origin
export const NO_MORE_LEAKS_HEADER = "x-nomoreleaks";
