const { LocalPasetoStrategy } = require("../src");
const { passport, expect } = require("chai");
const { V3 } = require("paseto");

describe("Local Strategy", function () {
  let payload, user;

  before((done) => {
    V3.generateKey("local").then((key) => {
      return V3.encrypt(
        {
          username: "test",
        },
        key,
        {
          expiresIn: "99999999s",
        }
      ).then((token) => {
        passport
          .use(
            new LocalPasetoStrategy(
              {
                getToken() {
                  return token;
                },
                key: key,
                version: "V3",
              },
              (p, next) => {
                payload = p;
                next(
                  null,
                  { username: "username_" + payload.username },
                  { info: "test" }
                );
              }
            )
          )
          .success((u, i) => {
            user = u;
            done();
          })
          .authenticate();
      });
    });
  });

  it("assert correct payload", () => {
    expect(payload.username).equal("test");
  });

  it("assert correct user", () => {
    expect(user.username).equal("username_test");
  });
});
