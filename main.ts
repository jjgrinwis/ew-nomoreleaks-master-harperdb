/*
(c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.
Purpose: Our Master Edgworker calling different subWorkers to validate hash of username/password against a database
More info regarding subworkers: https://techdocs.akamai.com/edgeworkers/docs/create-a-subworker
*/
import { httpRequest } from "http-request";
import { createResponse } from "create-response";
import { generateDigest } from "./generateDigest.js";
import { logger } from "log";

// some custom created library and CONSTs we need to import
// you only need to make changes to the constants file!
import { isValidBody, getNestedValue } from "./utils.js";
import {
  UNAME,
  PASSWD,
  KNOWN_KEY_URL,
  NO_MORE_LEAKS_HEADER,
  POSITIVE_MATCH_URL,
} from "./constants.js";

// the field in JSON response that has the generated hash
const X_HASH_KEY = "X-Hash-Value";

// as we need  some info from the request body, we have to use the responseProvider
export async function responseProvider(request: EW.ResponseProviderRequest) {
  // lets first check our content-type and data is a POST.
  // we support application/x-www-form-urlencoded and application/json
  let body: object = null;

  // only get content-type if it exists and just convert to lowercase just to sure.
  const contentType = request.getHeader("content-type")?.[0]?.toLowerCase();

  // get body based on content-type. This is the buffered version so be aware of the limits
  if (contentType === "application/json") {
    body = await request.json().catch(() => null);
  }

  // key is the digest of our username+password combination
  let key: string = undefined;
  // if key is found a unique id is created used to register on /positiveMatch endpoint
  let id: string = null;

  // for some calls to HarperDB we need basic auth header, get it from delivery config.
  const authHeader = request.getVariable("PMUSER_AUTH_HEADER") ?? null;

  // only start process if we have a body and the required fields.
  if (body && isValidBody(body)) {
    // Looks like we have all the required fields, lookup body fields and normalize
    try {
      const normalizedUnamePasswd =
        getNestedValue(body, UNAME).toLowerCase().normalize("NFC") +
        getNestedValue(body, PASSWD).normalize("NFC");

      // now generated digest
      key = await generateDigest("SHA-256", normalizedUnamePasswd);

      //logger.info("SHA-256 hash created from username+password combination");
    } catch (error) {
      // in case anything goes wrong, just log it but forward request to origin.
      logger.error(`Something went wrong creating the SHA-256: ${error}`);
    }

    // if we have received some response and auth defined, let's validate the key against our db.
    if (key && authHeader) {
      // to get subWorker logs, use Pragma:akamai-x-ew-debug-rp,akamai-x-ew-subworkers,akamai-x-ew-debug-subs in request header
      id = await keyExists(key, authHeader);
    } else {
      logger.error(`key or autheader not defined ${key}`);
    }
  } else {
    logger.error(`${UNAME} and/or ${PASSWD} not provided in json body`);
  }
  // for now just forwarding request to the origin.
  // not using a try, if call fails, it fails, just forwarding the response to the user.
  const originResponse = await originRequest(request, body, id);

  // a successful login using a known username/password now just defined as a 200.
  if (id && originResponse.ok) {
    // no need to wait for it, just fire it off to our delivery config that's in front of harperDB
    // using a post body like {"id": "86cdca52-a34e-4899-8c12-fd370b9b5c56"m "group": "something"}
    const reqBody = { id: id, group: request.host };
    registerPositiveMatch(reqBody, authHeader);
  }

  // time respond d ot the client.
  if (originResponse) {
    return Promise.resolve(
      createResponse(
        originResponse.status,
        originResponse.getHeaders(),
        originResponse.body
      )
    );
  } else {
    // just return a rejected promise if to origin has failed, not reporting it to external system
    return Promise.reject(
      `failed origin sub-request: ${originResponse.status}`
    );
  }
}

// this endpoint is using HarperDB to lookup the key.
async function keyExists(key: string, auth?: string): Promise<string> {
  /*
    This is our HarperDB version where we need to feed the X-Hash-Key and Authorization values via request header.
    authorization header is optional, that can be set in the delivery configuration for the KNOWN_KEY_URL endpoint via a PMUSER var.

    response from this subWorker is one of these two where id is key in db to register a successful login.
    If it's null, user combination not active in the db or anything went wrong.
   
      {"id": "86cdca52-a34e-4899-8c12-fd370b9b5c56"}
      {"id": null}

    This function will also use a null if anything goes wrong.
 */

  // create our reqHeaders object, key should be stored in X_HASH_KEY defined as a const
  const reqHeaders = {
    [X_HASH_KEY]: key,
    Authorization: auth,
  };

  try {
    const result = await httpRequest(KNOWN_KEY_URL, { headers: reqHeaders });

    if (result.ok) {
      const response = await result.json();
      // make sure field exists and it's value is a UUID v4 with 36 chars.
      // if not, just return a null
      if (
        response.hasOwnProperty("id") &&
        response["id"] !== null &&
        response["id"].length === 36
      ) {
        logger.info(
          `Call to ${KNOWN_KEY_URL} found id ${response["id"].substring(
            0,
            5
          )}.....`
        );
        return response["id"];
      } else {
        logger.error(
          "id field not in json response so key not found or wrong format"
        );
      }
    }
  } catch (error) {
    logger.error(`There was a problem calling ${KNOWN_KEY_URL}: ${error}`);
  }

  // if anything goes wrong, just respond with false, a null, to keep things going.
  return null;
}

// this function will forward request to origin.
async function originRequest(
  request: EW.ResponseProviderRequest,
  body: object,
  id: string,
  informHeader: string = NO_MORE_LEAKS_HEADER
) {
  /*
  some 'unsafe' headers we need to remove. httpRequest to the origin will fail if they are not removed
  https://techdocs.akamai.com/edgeworkers/docs/http-request#http-sub-requests
  https://techdocs.akamai.com/edgeworkers/docs/edgeworkers-javascript-code#can-i-re-use-request-and-response-headers
  */
  const HEADERS_TO_REMOVE = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "vary",
    "accept-encoding",
    "content-encoding",
    "keep-alive",
    "Proxy-Authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
  ];

  // first cleanup our request headers
  let requestHeaders = request.getHeaders();
  HEADERS_TO_REMOVE.forEach((element) => delete requestHeaders[element]);

  // add fraudster state header. If null convert to string null otherwise string true
  requestHeaders[informHeader] = [String(id ? true : false)];

  // fire off the request to our statically defined origin for now
  // this should be changed to request.url
  const url = "https://api.grinwis.com/headers";
  let originResponse = await httpRequest(url, {
    method: request.method,
    headers: requestHeaders,
    body: JSON.stringify(body),
  });

  // return our promise, good or bad.
  return originResponse;
}

function registerPositiveMatch(reqBody: object, auth?: string) {
  /*
  This function will report a successful login with a known username/password
  We're just going to call our delivery config which is forwarding this request to HarperDB backend.

  Request body should look like this where group will be hostname for now.
  '{"id": "86cdca52-a34e-4899-8c12-fd370b9b5c56", "group": "hostname"}'
  */

  const reqHeaders = {
    Authorization: auth,
    "content-type": "application/json",
  };

  try {
    // just fire off the request, no need to wait for the result
    httpRequest(POSITIVE_MATCH_URL, {
      method: "POST",
      headers: reqHeaders,
      body: JSON.stringify(reqBody),
    });
    logger.info(`Registering a hit on ${POSITIVE_MATCH_URL}`);
  } catch (error) {
    logger.error(`There was a problem calling ${POSITIVE_MATCH_URL}: ${error}`);
  }
}
