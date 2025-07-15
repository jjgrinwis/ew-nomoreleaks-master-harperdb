import { TextEncoder } from "encoding";
import { crypto } from "crypto";

/**
 * Generates a cryptographic digest from a string using the specified algorithm.
 * @param algorithm - The hash algorithm to use (SHA-1, SHA-256, SHA-384, or SHA-512)
 * @param stringToDigest - The string to hash
 * @returns A promise that resolves to the hex-encoded digest string
 */
export async function generateDigest(
  algorithm: string,
  stringToDigest: string
): Promise<string> {
  const msgUint8 = new TextEncoder().encode(stringToDigest);
  const hashBuffer = await crypto.subtle.digest(algorithm, msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
