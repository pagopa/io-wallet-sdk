export const htuFromRequestUrl = (requestUrl: string) => {
  const htu = new URL(requestUrl);
  htu.search = "";
  htu.hash = "";

  return htu.toString();
};
