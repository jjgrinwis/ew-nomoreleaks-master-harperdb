/*
This is the only file that should be updated.
It defines some constants including the JSON path to lookup the UNAME and PASSWD so can look like data.user.email for example.

There is a separate utils.ts that has two functions to lookup the value, again using dynamic JSON field via this var.
*/
export const UNAME = "username";
export const PASSWD = "password";
// our key generating and know password lookup
export const KEY_GENERATOR_URL = "https://api.grinwis.com/NoMoreLeaksKey";
export const KNOWNKEY_URL = "https://api.grinwis.com/KnownKey";
// header that's going to be forwarded to the origin
export const NO_MORE_LEAKS_HEADER = "x-nomoreleaks";
