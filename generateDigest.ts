import { TextEncoder } from "encoding";
import { crypto } from "crypto";

/**
 * Generates the digest from a string using the provided algorithm
 * @param {('SHA-1'|'SHA-256'|'SHA-384'|'SHA-512')} algorithm - The algorithm to use, must be one of the following options ["SHA-1", "SHA-256", "SHA-384","SHA-512"]
 * @param {string} stringToDigest - a string to digest
 * @returns {string} returns the string value of the digest
 */
export async function generateDigest(
  algorithm: string,
  stringToDigest: string
): Promise<string> {
  // first convert the input string into a stream of UTF-8 bytes (Uint8Array)
  // Uint8Array is a TypedArray so an array-like object that stores 8-bit unsigned integers (bytes).
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
  // length of the array should be the exact same size as the length of the string.
  // https://techdocs.akamai.com/edgeworkers/docs/encoding
  const msgUint8 = new TextEncoder().encode(stringToDigest);

  // A digest is a short fixed-length value derived from some variable-length input.
  // Generate a digest of the given data using SHA256, response will be an Arraybuffer promise.
  // Arraybuffer serves as a raw binary data storage.
  const hashBuffer = await crypto.subtle.digest(algorithm, msgUint8);

  // convert the digest generate arraybuffer to a Uint8Array TypedArray
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
  const walkable = Array.from(new Uint8Array(hashBuffer));

  // walk through the array, convert to string and put into single var
  return walkable.map((b) => b.toString(16).padStart(2, "0")).join("");
}
