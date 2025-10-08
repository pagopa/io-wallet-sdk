import { UnexpectedStatusCodeError } from "./errors";

/**
 * Check if a response is in the expected status, otherwise throw an error
 * @param status - The expected status
 * @param customError - A custom error compatible with {@link UnexpectedStatusCodeError}
 * @throws UnexpectedStatusCodeError if the status is different from the one expected
 * @returns The given response object
 */
export const hasStatusOrThrow =
  (status: number, customError?: typeof UnexpectedStatusCodeError) =>
  async (res: Response): Promise<Response> => {
    if (res.status !== status) {
      const ErrorClass = customError ?? UnexpectedStatusCodeError;
      throw new ErrorClass({
        message: `Http request failed. Expected ${status}, got ${res.status}, url: ${res.url}`,
        reason: await parseRawHttpResponse(res), // Pass the response body as reason so the original error can surface
        statusCode: res.status,
      });
    }
    return res;
  };

/**
 * Utility function to parse a raw HTTP response as JSON if supported, otherwise as text.
 */
export const parseRawHttpResponse = <T extends Record<string, unknown>>(
  response: Response,
) =>
  response.headers.get("content-type")?.includes("application/json")
    ? (response.json() as Promise<T>)
    : response.text();
