const presence = require('../helpers/validate_presence');
const getTokenAuth = require('../shared/token_auth');
const noCache = require('../shared/no_cache');
const instance = require('../helpers/weak_cache');
const { urlencoded: parseBody } = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const paramsMiddleware = require('../shared/assemble_params');
const { InvalidRequest } = require('../helpers/errors');

const introspectable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);
const JWT = 'application/token-introspection+jwt';

module.exports = function introspectionAction(provider) {
  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'introspection');
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const configuration = instance(provider).configuration();
  const {
    pairwiseIdentifier, features: {
      introspection: { allowedPolicy },
      jwtIntrospection,
    },
  } = configuration;
  const { grantTypeHandlers } = instance(provider);
  const {
    IdToken, AccessToken, ClientCredentials, RefreshToken, Client,
  } = provider;

  function getAccessToken(ctx, token) {
    return AccessToken.find(ctx, token);
  }

  function getClientCredentials(ctx, token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return ClientCredentials.find(ctx, token);
  }

  function getRefreshToken(ctx, token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return RefreshToken.find(ctx, token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return [
    noCache,
    parseBody,
    paramsMiddleware.bind(undefined, PARAM_LIST),
    ...tokenAuth,
    rejectDupes.bind(undefined, {}),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function jwtIntrospectionResponse(ctx, next) {
      if (jwtIntrospection.enabled) {
        const { client } = ctx.oidc;

        const {
          introspectionEncryptedResponseAlg: encrypt,
          introspectionSignedResponseAlg: sign,
        } = client;

        const accepts = ctx.accepts('json', JWT);
        if (encrypt && accepts !== JWT) {
          throw new InvalidRequest(`introspection must be requested with Accept: ${JWT} for this client`);
        }

        await next();

        if ((encrypt || sign) && accepts === JWT) {
          const token = new IdToken({}, { ctx });
          token.extra = {
            token_introspection: ctx.body,
            aud: ctx.body.aud,
          };

          ctx.body = await token.issue({ use: 'introspection' });
          ctx.type = 'application/token-introspection+jwt; charset=utf-8';
        }
      } else {
        await next();
      }
    },

    async function renderTokenResponse(ctx, next) {
      const { params } = ctx.oidc;

      ctx.body = { active: false };

      let token;

      switch (params.token_type_hint) {
        case 'access_token':
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

      if (!token || !token.isValid) {
        return;
      }

      if (token.grantId) {
        const grant = await ctx.oidc.provider.Grant.find(ctx, token.grantId, {
          ignoreExpiration: true,
        });

        if (!grant) return;
        if (grant.isExpired) return;
        if (grant.clientId !== token.clientId) return;
        if (grant.accountId !== token.accountId) return;

        ctx.oidc.entity('Grant', grant);
      }

      if (introspectable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (!(await allowedPolicy(ctx, ctx.oidc.client, token))) {
        return;
      }

      if (token.accountId) {
        ctx.body.sub = token.accountId;
        if (token.clientId !== ctx.oidc.client.clientId) {
          const client = await Client.find(ctx, token.clientId);
          if (client.subjectType === 'pairwise') {
            ctx.body.sub = await pairwiseIdentifier(ctx, ctx.body.sub, client);
          }
        } else if (ctx.oidc.client.subjectType === 'pairwise') {
          ctx.body.sub = await pairwiseIdentifier(ctx, ctx.body.sub, ctx.oidc.client);
        }
      }

      Object.assign(ctx.body, {
        ...token.extra,
        active: true,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        sid: token.sid,
        iss: provider.issuer,
        jti: token.jti !== params.token ? token.jti : undefined,
        aud: token.aud,
        scope: token.scope,
        cnf: token.isSenderConstrained() ? {} : undefined,
        token_type: token.kind !== 'RefreshToken' ? token.tokenType : undefined,
      });

      if (token['x5t#S256']) {
        ctx.body.cnf['x5t#S256'] = token['x5t#S256'];
      }

      if (token.jkt) {
        ctx.body.cnf.jkt = token.jkt;
      }

      await next();
    },
  ];
};
