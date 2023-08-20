const fastify = require("fastify");
const cookie = require("@fastify/cookie");
const fastifySession = require("@fastify/session");
const fastifyPassport = require("@fastify/passport");

export const createApp = async function (port = 3000) {
  const app = fastify({
    logger: {
      level: "error",
    },
  });

  app.register(cookie, {
    secret: "paseto",
    hook: "onRequest",
  });

  app.register(fastifySession, {
    secret: "secret with minimum length of 32 characters",
  });

  app.register(fastifyPassport.initialize());

  app.start = () =>
    new Promise((resolve) => {
      app.listen({ port }, (err) => {
        if (err) {
          console.log(err);
          process.exit(1);
        }

        resolve();
      });
    });

  return app;
};
