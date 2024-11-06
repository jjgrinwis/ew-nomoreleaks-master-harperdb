/*
Some functions created to do better lookup of values in a JSON body.
Thanks ChatGTP for generating these two functions.
*/
import { UNAME, PASSWD } from "./constants.js";
export function hasNestedProperty(obj, path) {
  return (
    path.split(".").reduce((acc, key) => {
      // Check if the current accumulator is an object or array and contains the key/index
      if (
        acc &&
        (typeof acc === "object" || Array.isArray(acc)) &&
        key in acc
      ) {
        return acc[key]; // Move to the next level
      }
      return undefined; // If key doesn't exist, stop
    }, obj) !== undefined
  );
}
export function getNestedValue(obj, path) {
  return path.split(".").reduce((acc, key) => {
    // Check if acc is an object or array and if key exists in acc
    if (acc && (typeof acc === "object" || Array.isArray(acc))) {
      return acc[key]; // Move to the next level
    }
    return undefined; // If key doesn't exist, stop
  }, obj);
}
export function isValidBody(body) {
  //let's check if we have the required fields in our body. This version is based on a JSON payload!
  // Using intermediate variables to clean up our if statement. Thanks ChatGPT.
  // Check if the body is a valid object
  const hasBody = body !== null && typeof body === "object";
  // Check if the required credentials exist in the body
  const hasCredentials =
    hasBody &&
    hasNestedProperty(body, UNAME) &&
    hasNestedProperty(body, PASSWD);
  // Check if credentials meet the length requirements
  const bodyIsValid =
    hasCredentials &&
    getNestedValue(body, UNAME).length > 1 &&
    getNestedValue(body, PASSWD).length > 2;
  return bodyIsValid;
}
