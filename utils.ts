/*
Utility functions for JSON path navigation and credential validation.
*/
import { UNAME, PASSWD } from "./constants.js";

export function hasNestedProperty(obj: object, path: string): boolean {
  return (
    path.split(".").reduce((acc, key) => {
      if (
        acc &&
        (typeof acc === "object" || Array.isArray(acc)) &&
        key in acc
      ) {
        return acc[key];
      }
      return undefined;
    }, obj) !== undefined
  );
}
export function getNestedValue(obj: object, path: string): any {
  return path.split(".").reduce((acc, key) => {
    if (acc && (typeof acc === "object" || Array.isArray(acc))) {
      return acc[key];
    }
    return undefined;
  }, obj);
}
export function isValidBody(body: object): boolean {
  const hasBody = body !== null && typeof body === "object";
  const hasCredentials =
    hasBody &&
    hasNestedProperty(body, UNAME) &&
    hasNestedProperty(body, PASSWD);
  const bodyIsValid =
    hasCredentials &&
    getNestedValue(body, UNAME).length > 1 &&
    getNestedValue(body, PASSWD).length > 2;
  return bodyIsValid;
}
