/*
(c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.
Purpose: Master EdgeWorker that validates username/password hashes against HarperDB
More info: https://techdocs.akamai.com/edgeworkers/docs/create-a-subworker

Required configuration:
- Set PMUSER_AUTH_HEADER in delivery configuration (Basic auth for HarperDB)
- Update constants.ts for field mappings and endpoints
*/
import { httpRequest } from "http-request";
import { createResponse } from "create-response";
import { generateDigest } from "./generateDigest.js";
import URLSearchParams from "url-search-params";
import { logger } from "log";

import { isValidBody, getNestedValue } from "./utils.js";
import {
  UNAME,
  PASSWD,
  KNOWN_KEY_URL,
  NO_MORE_LEAKS_HEADER,
  POSITIVE_MATCH_URL,
} from "./constants.js";

const X_HASH_KEY = "X-Hash-Value";

export async function responseProvider(request: EW.ResponseProviderRequest) {
  const contentType = request.getHeader("content-type")?.[0]?.toLowerCase();
  
  let body: object = null;
  let formBody: string = null;

  if (contentType) {
    try {
      if (contentType.startsWith("application/json")) {
        body = await request.json();
      } else if (contentType.startsWith("application/x-www-form-urlencoded")) {
        formBody = await request.text();
        const params = new URLSearchParams(formBody);
        body = mapCredentials(params);
      }
    } catch (error) {
      logger.error(
        `Failed to parse request body with Content-Type: ${contentType}`,
        error
      );
    }
  } else {
    logger.error("Content-Type is undefined, skipped parsing.");
  }

  let key: string = undefined;
  let id: string = null;
  const authHeader = request.getVariable("PMUSER_AUTH_HEADER") || null;

  if (body && isValidBody(body)) {
    try {
      const normalizedUnamePasswd =
        getNestedValue(body, UNAME).toLowerCase().normalize("NFC") +
        getNestedValue(body, PASSWD).normalize("NFC");

      key = await generateDigest("SHA-256", normalizedUnamePasswd);
      logger.log(`generated hash: ${key.substring(0, 5)}...`);
    } catch (error) {
      logger.error(`Failed to create SHA-256 hash: ${error}`);
    }

    if (key && authHeader) {
      id = await keyExists(key, authHeader);
    } else {
      logger.error(
        `Missing key or authHeader - key: ${key}, authHeader: ${authHeader}`
      );
    }
  } else {
    logger.error(
      `${UNAME} and/or ${PASSWD} fields not provided in request body`
    );
  }
  const reqBody = formBody || JSON.stringify(body);
  const originResponse = await originRequest(request, reqBody, id);

  if (id && originResponse.ok) {
    const matchData = { id: id, group: request.host };
    registerPositiveMatch(matchData, authHeader);
  }

  if (originResponse) {
    return Promise.resolve(
      createResponse(
        originResponse.status,
        removeUnsafeHeaders(originResponse.getHeaders()),
        originResponse.body
      )
    );
  } else {
    return Promise.reject(
      `Failed origin sub-request: ${originResponse.status}`
    );
  }
}

async function keyExists(key: string, auth?: string): Promise<string> {
  const reqHeaders = {
    [X_HASH_KEY]: key,
    Authorization: auth,
  };

  try {
    const result = await httpRequest(KNOWN_KEY_URL, { headers: reqHeaders });

    if (result.ok) {
      const response = await result.json();
      
      if (
        response &&
        typeof response === "object" &&
        response.hasOwnProperty("id") &&
        response.id !== null &&
        typeof response.id.id === "string" &&
        response.id.id.length === 36
      ) {
        logger.info(
          `Call to ${KNOWN_KEY_URL} found id ${response.id.id.substring(
            0,
            5
          )}...`
        );
        return response["id"];
      } else {
        logger.error(
          "Invalid response format: id field not found or malformed"
        );
      }
    } else {
      logger.error(`HarperDB lookup failed: ${JSON.stringify(result.body)}`);
    }
  } catch (error) {
    logger.error(`Error calling ${KNOWN_KEY_URL}: ${error}`);
  }

  return null;
}

async function originRequest(
  request: EW.ResponseProviderRequest,
  body: string,
  id: string,
  informHeader: string = NO_MORE_LEAKS_HEADER
) {
  let requestHeaders = removeUnsafeHeaders(request.getHeaders());
  
  requestHeaders["ew-bypass"] = [String(true)];
  requestHeaders[informHeader] = [String(id ? true : false)];

  const originResponse = await httpRequest(request.url, {
    method: request.method,
    headers: requestHeaders,
    body: body,
  });

  return originResponse;
}

function registerPositiveMatch(reqBody: object, auth?: string) {
  const reqHeaders = {
    Authorization: auth,
    "content-type": "application/json",
  };

  try {
    httpRequest(POSITIVE_MATCH_URL, {
      method: "POST",
      headers: reqHeaders,
      body: JSON.stringify(reqBody),
    });
    logger.info(`Registering positive match on ${POSITIVE_MATCH_URL}`);
  } catch (error) {
    logger.error(`Error calling ${POSITIVE_MATCH_URL}: ${error}`);
  }
}

function mapCredentials(params: URLSearchParams): { [key: string]: string } {
  return {
    [UNAME]: params.get(UNAME) || "",
    [PASSWD]: params.get(PASSWD) || "",
  };
}

function removeUnsafeHeaders(headers: EW.Headers): EW.Headers {
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

  if (headers && typeof headers === "object") {
    HEADERS_TO_REMOVE.forEach((header) => delete headers[header.toLowerCase()]);
  }

  return headers;
}
