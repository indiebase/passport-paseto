import { Strategy } from "passport-strategy";
import * as paseto from "paseto";
import type { JsonWebKeyInput, KeyObject, PublicKeyInput } from "crypto";
import * as assert from "assert";

type CustomPasetoTokenFromProvider = (
  req: any,
  options?: PublicPasetoStrategyOptions
) => string;

type Verified = (err: Error, user: Record<string, any>, info: any) => void;

export interface PublicPasetoStrategyOptions {
  getToken?: CustomPasetoTokenFromProvider;
  publicKey?: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string;
  consumeOptions?: paseto.ConsumeOptions<any>;
  passReqToCallback?: boolean;
  version?: "V1" | "V2" | "V3" | "V4";
}

export class PublicPasetoStrategy extends Strategy {
  public readonly name = "public-paseto";

  private options!: PublicPasetoStrategyOptions;
  private verify!: any;

  constructor(
    options: PublicPasetoStrategyOptions,
    verify: (payload: any, verified: any) => void
  );
  constructor(
    options: PublicPasetoStrategyOptions = {},
    verify: (
      req: any,
      payload: Record<string, unknown>,
      verified: Verified
    ) => void
  ) {
    super();
    options = Object.assign({}, { version: "V4" }, options);

    assert.ok(
      options.version && ["V1", "V2", "V3", "V4"].includes(options.version),
      `PublicPasetoStrategy doesn't support ${options.version}`
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
    _options: PublicPasetoStrategyOptions = {}
  ): Promise<void> {
    const token = await this.options.getToken(req);
    const payload = await paseto[this.options.version]
      .verify(token, this.options.publicKey, this.options.consumeOptions)
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
