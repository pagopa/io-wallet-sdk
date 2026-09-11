export function objectToQueryParams(
  object: Record<string, unknown>,
): URLSearchParams {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(object)) {
    if (value != null) {
      params.append(
        key,
        typeof value === "object" ? JSON.stringify(value) : String(value),
      );
    }
  }

  return params;
}
