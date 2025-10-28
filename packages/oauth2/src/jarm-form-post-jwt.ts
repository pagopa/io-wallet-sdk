import { DecodeJwtResult, decodeJwt } from "@openid4vc/oauth2";
import z from "zod";

import { Oauth2Error } from "./errors";

export interface GetJwtFromFormPostOptions<T> {
  /**
   * Raw HTML containing the autosubmitted form with the jwt response
   */
  formData: string;

  /**
   * Schema for parsing and validating
   */
  schema: z.ZodSchema<T>;
}

/*
 * Decode a form_post.jwt and return the final JWT.
 * The formData here is in form_post.jwt format as defined in
 * JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
 <!DOCTYPE html>
    <html>
        <head>
            <meta charset="utf-8" />
        </head>
        <body onload="document.forms[0].submit()">
        <noscript>
            <p>
                <strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.
            </p>
        </noscript>
            <form action="iowalletexample//cb" method="post">       
                <div>
                    <input type="hidden" name="response" value="somevalue" />
                </div>
                <noscript>
                    <div>
                        <input type="submit" value="Continue" />
                    </div>
                </noscript>
            </form>
        </body>
    </html>
 */
export const getJwtFromFormPost = async <T>(
  options: GetJwtFromFormPostOptions<T>,
): Promise<{
  decodedJwt: Omit<DecodeJwtResult<undefined, z.ZodSchema<T>>, "signature">;
  jwt: string;
}> => {
  const formPostRegex = /<input[^>]*name="response"[^>]*value="([^"]*)"/i;
  const lineExpressionRegex = /\r\n|\n\r|\n|\r|\s+/g;

  const match = formPostRegex.exec(options.formData);
  if (match && match[1]) {
    const responseJwt = match[1];

    if (responseJwt) {
      const jwt = responseJwt.replace(lineExpressionRegex, "");
      const decodedJwt = decodeJwt({
        jwt,
        payloadSchema: options.schema,
      });
      return {
        decodedJwt: {
          header: decodedJwt.header,
          payload: decodedJwt.payload,
        },
        jwt,
      };
    }
  }

  throw new Oauth2Error(
    `Unable to obtain JWT from form_post.jwt. Form data: ${options.formData}`,
  );
};
