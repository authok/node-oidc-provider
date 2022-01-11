const { InvalidRequest } = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const getTokenAuth = require('../shared/token_auth');
const { urlencoded: parseBody } = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const paramsMiddleware = require('../shared/assemble_params');
const revoke = require('../helpers/revoke');

const revokeable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);

module.exports = function revocationAction(provider) {
  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'revocation');
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const { grantTypeHandlers } = instance(provider);

  function getAccessToken(ctx, token) {
    return provider.AccessToken.find(ctx, token);
  }

  function getClientCredentials(ctx, token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return provider.ClientCredentials.find(ctx, token);
  }

  function getRefreshToken(ctx, token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return provider.RefreshToken.find(ctx, token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return [
    parseBody,
    paramsMiddleware.bind(undefined, PARAM_LIST),
    ...tokenAuth,
    rejectDupes.bind(undefined, {}),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function renderTokenResponse(ctx, next) {
      ctx.status = 200;
      ctx.body = '';
      await next();
    },

    async function revokeToken(ctx, next) {
      let token;
      const { params } = ctx.oidc;

      switch (params.token_type_hint) {
        case 'access_token':
        case 'urn:ietf:params:oauth:token-type:access_token':
          token = await getAccessToken(ctx, params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(ctx, params.token),
                getRefreshToken(ctx, params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          token = await getClientCredentials(ctx, params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(ctx, params.token),
                getRefreshToken(ctx, params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
        case 'urn:ietf:params:oauth:token-type:refresh_token':
          token = await getRefreshToken(ctx, params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(ctx, params.token),
                getClientCredentials(ctx, params.token),
              ]).then(findResult);
            });
          break;
        default:
          token = await Promise.all([
            getAccessToken(ctx, params.token),
            getClientCredentials(ctx, params.token),
            getRefreshToken(ctx, params.token),
          ]).then(findResult);
      }

      if (!token) return;

      if (revokeable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        throw new InvalidRequest('this token does not belong to you');
      }

      await token.destroy(ctx);

      if (token.kind === 'RefreshToken') {
        await revoke(ctx, token.grantId);
      }

      await next();
    },
  ];
};
