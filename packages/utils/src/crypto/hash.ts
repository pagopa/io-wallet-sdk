type OrPromise<T> = Promise<T> | T;

export enum HashAlgorithm {
  Sha256 = "sha-256",
  Sha384 = "sha-384",
  Sha512 = "sha-512",
}

export type HashCallback = (
  data: Uint8Array,
  alg: HashAlgorithm,
) => OrPromise<Uint8Array>;
