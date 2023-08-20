const { createApp } = require("./app");
const fastifyPassport = require("@fastify/passport");
const { PublicPasetoStrategy, fromAuthBearer } = require("../src");
const paseto = require("paseto");
const { expect } = require("chai");

describe("Public Strategy:e2e", function () {
  async function testServer(ver) {
    const app = await createApp(4000);
    const { secretKey, publicKey } = await paseto[ver].generateKey("public", {
      format: "paserk",
    });
    const token = await paseto[ver].sign(
      {
        username: "test",
      },
      secretKey,
      {
        expiresIn: "99999999s",
      }
    );

    fastifyPassport.use(
      "public-paseto",
      new PublicPasetoStrategy(
        {
          getToken: fromAuthBearer(),
          publicKey,
          version: ver,
        },
        (payload, done) => {
          expect(payload.username).equal("test");
          done(null, { username: "username_test" });
        }
      )
    );

    app.get(
      "/test/bearer",
      {
        preValidation: fastifyPassport.authenticate("public-paseto", {
          authInfo: false,
          session: false,
        }),
      },
      async function (req, reply) {
        expect(req.user.username).equal("username_test");
        reply.send();
      }
    );

    await app.start();

    let res = await app.inject({
      method: "GET",
      url: "/test/bearer",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.statusCode).equal(
      200,
      `${ver} get statusCode ${res.statusCode}`
    );

    await app.close();
  }

  it("Paseto public strategy V1: header", async () => {
    await testServer("V1");
  });

  it("Paseto public strategy V2: header", async () => {
    await testServer("V2");
  });

  it("Paseto public strategy V3: header", async () => {
    await testServer("V3");
  });

  it("Paseto public strategy V4: header", async () => {
    await testServer("V3");
  });
});
