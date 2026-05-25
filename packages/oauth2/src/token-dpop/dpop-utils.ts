/**
 * Normalizes a request URL into the DPoP `htu` claim value.
 *
 * @param requestUrl - Full request URL.
 * @returns URL string without query string or fragment.
 */
export const htuFromRequestUrl = (requestUrl: string) => {
  const htu = new URL(requestUrl);
  htu.search = "";
  htu.hash = "";

  return htu.toString();
};
