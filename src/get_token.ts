export const fromHeader = function (name: string = "X-Paseto-Token") {
  return (req) => req?.header?.[name];
};

export const fromAuthBearer = function () {
  return fromAuthScheme("Bearer");
};

export const fromAuthScheme = function (scheme: string) {
  return (req) => {
    const auth = req.headers?.["authorization"];

    if (!auth) return null;

    const [prefix, token]: string[] = auth.split(/\s+/g);

    return prefix?.trim().toLowerCase() === scheme.toLowerCase() ? token : null;
  };
};

export const fromBody = function (field: string) {
  return (req) => req?.body[field];
};

export const fromQuery = function (field: string) {
  return (req) => req?.query[field];
};
