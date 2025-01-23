/*
(c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.
Purpose: Our Master EdgeWorker calling different subWorkers to validate hash of username/password against a database
More info regarding subWorkers: https://techdocs.akamai.com/edgeworkers/docs/create-a-subworker

Make sure to set the PMUSER_AUTH_HEADER variable in your delivery configuration calling this EdgeWorker
That var is the basic auth info for HarperDB and should look like this: 'Basic bm1sX......s=' 

You only need to change parameters in the constants.js
*/
import { httpRequest } from "http-request";
import { createResponse } from "create-response";
import { generateDigest } from "./generateDigest.js";
import URLSearchParams from "url-search-params";
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

// the field in JSON response from HarperDB that has the generated hash
const X_HASH_KEY = "X-Hash-Value";

// as we need  some info from the request body, we have to use the responseProvider
export async function responseProvider(request: EW.ResponseProviderRequest) {
  // lets first check our content-type
  // we support application/x-www-form-urlencoded and application/json
  // only get content-type if it exists and just convert to lowercase just to be sure.
  const contentType = request.getHeader("content-type")?.[0]?.toLowerCase();

  // our body that only holds UNAME and PASSWD key and value. It will also be used for our text form data
  let body: object = null;

  // our original form body
  let formBody: string = null;

  // based on the content type, we're going to use the JSON body or convert x-www-form-urlencoded data to a JSON object
  // be aware of the json() and text() memory limits in EdgeWorkers as this is buffered, not streamed!
  // we only need to start the try block if contentType has some value and no need for toLowerCase() as we have done that before for var contentType
  if (contentType !== undefined) {
    try {
      if (contentType.startsWith("application/json")) {
        body = await request.json();
      } else if (contentType.startsWith("application/x-www-form-urlencoded")) {
        formBody = await request.text();

        // create a URLSearchParams object from our form-urlencoded body
        const params = new URLSearchParams(formBody);

        // set our body object with values fromBody with keys defined in UNAME and PASSWD
        body = mapCredentials(params);
      }
    } catch (error) {
      // if anything goes wrong, just log an error but continue process.
      logger.error(
        `Failed to parse request body with Content-Type: ${contentType}`,
        error
      );
    }
  } else {
    logger.error("Content-Type is undefined, skipped the try block.");
  }

  // key is the digest of our username+password combination
  let key: string = undefined;

  // if key is found a unique id is created used to register on /positiveMatch endpoint
  let id: string = null;

  // for some calls to HarperDB we need basic auth header, get it from delivery config.
  // const authHeader = request.getVariable("PMUSER_AUTH_HEADER") || null;
  // using || as value might be empty so check for any falsy value
  const authHeader = request.getVariable("PMUSER_AUTH_HEADER") || null;

  // only start process if we have a body and the required fields.
  if (body && isValidBody(body)) {
    // Looks like we have all the required fields, lookup body fields and normalize using NFC
    try {
      const normalizedUnamePasswd =
        getNestedValue(body, UNAME).toLowerCase().normalize("NFC") +
        getNestedValue(body, PASSWD).normalize("NFC");

      // generate SHA-256 digest of normalized username+password string
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
      logger.error(
        `key or autHeader not defined key: ${key}, authHeader: ${authHeader}`
      );
    }
  } else {
    logger.error(
      `${UNAME} and/or ${PASSWD} fields not provided in request body`
    );
  }
  // for now just forwarding request to the origin.
  // not using a try, if call fails, it fails, just forwarding the response to the user.
  // if it's from data, use formBody, else just use origin json body and fire off the request
  const reqBody = formBody || JSON.stringify(body);
  const originResponse = await originRequest(request, reqBody, id);

  // a successful login using a known username/password now just defined as a 200.
  // we might need to use other options like some header or different response code.
  if (id && originResponse.ok) {
    // no need to wait for it, just fire it off to our delivery config that's in front of harperDB
    // using a post body like {"id": "86cdca52-a34e-4899-8c12-fd370b9b5c56"m "group": "something"}
    const reqBody = { id: id, group: request.host };
    registerPositiveMatch(reqBody, authHeader);
  }

  // time to respond to the client.
  // we had some issues and looks like we also need to remove unsafe headers when providing the response.

  if (originResponse) {
    return Promise.resolve(
      createResponse(
        originResponse.status,
        removeUnsafeHeaders(originResponse.getHeaders()),
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
    } else {
      logger.error(`${JSON.stringify(result.body)}`);
    }
  } catch (error) {
    logger.error(`There was a problem calling ${KNOWN_KEY_URL}: ${error}`);
  }

  // if anything goes wrong, just respond with false, a null, to keep things going.
  return null;
}

// this function will forward request to origin. As a body you can use json object or text for form data
async function originRequest(
  request: EW.ResponseProviderRequest,
  body: string,
  id: string,
  informHeader: string = NO_MORE_LEAKS_HEADER
) {
  // first cleanup our request headers using our removeUnsafeHeaders option.
  let requestHeaders = removeUnsafeHeaders(request.getHeaders());

  // lets add some special EW bypass header.
  // but this only need to be verified if 'enable-subworker' has been enabled in your EdgeWorker bundle.json
  requestHeaders["ew-bypass"] = [String(true)];

  // add fraudster state header. If null convert to string null otherwise string true
  requestHeaders[informHeader] = [String(id ? true : false)];

  // fire off the request to our statically defined origin using original body data and modified request headers.
  // we can't use request.body as the request stream is already locked, so we need to feed the text into httpRequest call which has some limitations
  // In a next version we might want to tee() the stream so we can just use the request.body in the httpRequest() call.
  // request.url
  let originResponse = await httpRequest(request.url, {
    method: request.method,
    headers: requestHeaders,
    body: body,
  });

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

function mapCredentials(params: URLSearchParams): { [key: string]: string } {
  return {
    [UNAME]: params.get(UNAME) || "",
    [PASSWD]: params.get(PASSWD) || "",
  };
}

function removeUnsafeHeaders(headers: EW.Headers): EW.Headers {
  /*
  Some 'unsafe' headers we need to remove. Not only request but also response headers should be cleaned up!
  You will see some strange behavior if you don't remove them.
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
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
  ];

  // only try to delete if headers exists and is an object
  if (headers && typeof headers === "object") {
    // in case entry doesn't exist, delete will just return true and lower case our header, just in case there is typo.
    HEADERS_TO_REMOVE.forEach((header) => delete headers[header.toLowerCase()]);
  }

  // return EW.Headers without the 'unsafe' elements.
  return headers;
}
