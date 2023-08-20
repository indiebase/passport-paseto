import { Strategy } from "passport-strategy";
import * as paseto from "paseto";
import type { KeyObject } from "crypto";
import * as assert from "assert";

type CustomPasetoTokenFromProvider = (
  req: any,
  options?: LocalPasetoStrategyOptions
) => string;

type Verified = (err: Error, user: Record<string, any>, info: any) => void;

export interface LocalPasetoStrategyOptions {
  getToken?: CustomPasetoTokenFromProvider;
  key?: KeyObject | Buffer | string;
  consumeOptions?: paseto.ConsumeOptions<any>;
  passReqToCallback?: boolean;
  version?: "V1" | "V3";
}

export class LocalPasetoStrategy extends Strategy {
  public readonly name = "local-paseto";

  private options!: LocalPasetoStrategyOptions;
  private verify!: any;

  constructor(
    options: LocalPasetoStrategyOptions,
    verify: (payload: any, verified: any) => void
  );
  constructor(
    options: LocalPasetoStrategyOptions = {},
    verify: (
      req: any,
      payload: Record<string, unknown>,
      verified: Verified
    ) => void
  ) {
    super();
    options = Object.assign({}, { version: "V3" }, options);

    assert.ok(
      options.version && ["V1", "V3"].includes(options.version),
      `LocalPasetoStrategy doesn't support ${options.version}`
    );

    if (typeof verify !== "function") {
      throw new TypeError("LocalPasetoStrategy requires a verify callback");
    }

    this.options = options;
    this.verify = verify;
  }

  private verified(err, user, info) {
    if (err) {
      return this.error(err);
    } else if (!user) {
      return this.fail(info);
    } else {
      return this.success(user, info);
    }
  }

  override async authenticate(
    req: any,
    _options: LocalPasetoStrategyOptions = {}
  ): Promise<void> {
    const token = await this.options.getToken(req);
    const payload = await paseto[this.options.version]
      .decrypt(token, this.options.key, this.options.consumeOptions)
      .catch(this.fail);

    this.verified = this.verified.bind(this);

    try {
      if (this.options.passReqToCallback) {
        this.verify(req, payload, this.verified);
      } else {
        this.verify(payload, this.verified);
      }
    } catch (err) {
      this.error(err);
    }
  }
}
