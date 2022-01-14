const instance = require('../../helpers/weak_cache');
const { InvalidGrant, InvalidTarget, InvalidScope } = require('../../helpers/errors');
const dpopValidate = require('../../helpers/validate_dpop');
const checkResource = require('../../shared/check_resource');

module.exports.handler = async function clientCredentialsHandler(ctx, next) {
  const { client } = ctx.oidc;
  const { ClientCredentials, ReplayDetection } = ctx.oidc.provider;
  const {
    features: {
      dPoP: { iatTolerance },
      mTLS: { getCertificate },
    },
    scopes: statics,
    loadClientGrantScopes,
  } = instance(ctx.oidc.provider).configuration();

  await checkResource(ctx, () => {});

  const scopes = ctx.oidc.params.scope ? [...new Set(ctx.oidc.params.scope.split(' '))] : [];

  const token = new ClientCredentials({
    client,
  });

  // eslint-disable-next-line no-restricted-syntax
  const resourceServers = Object.values(ctx.oidc.resourceServers);
  if (resourceServers) {
    if (resourceServers.length > 1) {
      throw new InvalidTarget('only a single resource indicator value is supported for this grant type');
    }

    const resourceServer = resourceServers[0];

    token.resourceServer = resourceServer;
    let clientGrantScopes = (await loadClientGrantScopes(ctx, client, resourceServer.audience)) || [];
    
    // 如果传入了 scope, 就用传入的scope, 否则用 client_grant配置的
    if (scopes.length > 0) {
      const allowList = new Set(clientGrantScopes);
      // eslint-disable-next-line no-restricted-syntax
      for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
        if (!allowList.has(scope)) {
          throw new InvalidScope('requested scope is not allowed', scope);
        }
      }

      token.scope = scopes.join(' ') || undefined;
    } else {
      token.scope = clientGrantScopes.join(' ') || undefined;
    }
  }

  if (client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);

    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    token.setThumbprint('x5t', cert);
  }

  const dPoP = await dpopValidate(ctx);

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      ctx, client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));

    token.setThumbprint('jkt', dPoP.thumbprint);
  }

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save(ctx);

  ctx.body = {
    access_token: value,
    expires_in: token.expiration,
    token_type: token.tokenType,
    scope: token.scope,
  };

  await next();
};

module.exports.parameters = new Set(['scope']);
