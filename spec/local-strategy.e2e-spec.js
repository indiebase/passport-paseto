const { createApp } = require("./app");
const fastifyPassport = require("@fastify/passport");
const { LocalPasetoStrategy, fromAuthBearer } = require("../src");
const paseto = require("paseto");
const { expect } = require("chai");

describe("Local Strategy:e2e", function () {
  async function testServer(ver) {
    const app = await createApp(5000);

    const key = await paseto[ver].generateKey("local");
    const token = await paseto[ver].encrypt(
      {
        username: "test",
      },
      key,
      {
        expiresIn: "99999999s",
      }
    );

    fastifyPassport.use(
      "local-paseto",
      new LocalPasetoStrategy(
        {
          getToken: fromAuthBearer(),
          key,
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
        preValidation: fastifyPassport.authenticate("local-paseto", {
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

  it("Paseto local strategy V1: header", async () => {
    await testServer("V1");
  });

  it("Paseto local strategy V3: header", async () => {
    await testServer("V3");
  });
});
