import type z from "zod";

/**
 * Some code comes from `zod-validation-error` package (MIT License) and
 * was slightly simplified to fit our needs.
 */
const constants = {
  identifierRegex: /[$_\p{ID_Start}][$\u200c\u200d\p{ID_Continue}]*/u,
  issueSeparator: "\n\t- ",
  unionSeparator: ", or ",
};

function escapeQuotes(str: string): string {
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

type ZodIssue = z.ZodError["issues"][number];

function joinPath(path: PropertyKey[]): string {
  if (path.length === 1 && path[0] !== undefined) {
    return String(path[0]);
  }

  return path.reduce<string>((acc, item) => {
    // handle numeric indices
    if (typeof item === "number") {
      return `${acc}[${item.toString()}]`;
    }

    if (typeof item === "symbol") {
      return `${acc}[${JSON.stringify(String(item))}]`;
    }

    // handle quoted values
    if (item.includes('"')) {
      return `${acc}["${escapeQuotes(item)}"]`;
    }

    // handle special characters
    if (!constants.identifierRegex.test(item)) {
      return `${acc}["${item}"]`;
    }

    // handle normal values
    const separator = acc.length === 0 ? "" : ".";
    return acc + separator + item;
  }, "");
}
function getMessageFromZodIssue(issue: ZodIssue): string {
  if (issue.code === "invalid_union") {
    return getMessageFromUnionErrors(issue.errors);
  }

  if (issue.path.length !== 0) {
    // handle array indices
    if (issue.path.length === 1) {
      const identifier = issue.path[0];

      if (typeof identifier === "number") {
        return `${issue.message} at index ${identifier}`;
      }
    }

    return `${issue.message} at "${joinPath(issue.path)}"`;
  }

  return issue.message;
}

function getMessageFromUnionErrors(unionErrors: ZodIssue[][]): string {
  return unionErrors
    .reduce<string[]>((acc, issues) => {
      const newIssues = issues
        .map((issue) => getMessageFromZodIssue(issue))
        .join(constants.issueSeparator);

      if (!acc.includes(newIssues)) acc.push(newIssues);

      return acc;
    }, [])
    .join(constants.unionSeparator);
}

export function formatZodError(error?: z.ZodError): string {
  if (!error) return "";

  return `\t- ${error?.issues.map((issue) => getMessageFromZodIssue(issue)).join(constants.issueSeparator)}`;
}
