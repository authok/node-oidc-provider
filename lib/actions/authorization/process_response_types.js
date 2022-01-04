const { InvalidTarget } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const filterClaims = require('../../helpers/filter_claims');
const combinedScope = require('../../helpers/combined_scope');

async function tokenHandler(ctx) {
  const { accountId } = ctx.oidc.session;

  const token = new ctx.oidc.provider.AccessToken({
    accountId,
    client: ctx.oidc.client,
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    gty: 'implicit',
    sessionUid: ctx.oidc.session.uid,
    sid: ctx.oidc.session.sidFor(ctx.oidc.client.clientId),
  });

  const {
    expiresWithSession,
    features: { resourceIndicators },
  } = instance(ctx.oidc.provider).configuration();

  let { audience } = ctx.oidc.params;

  if (Array.isArray(audience)) {
    audience = await resourceIndicators.defaultResource(ctx, ctx.oidc.client, audience);
  }

  if (Array.isArray(audience)) {
    throw new InvalidTarget('only a single resource indicator value must be requested/resolved during Access Token Request');
  }

  const { grant } = ctx.oidc;

  if (audience) {
    const resourceServer = ctx.oidc.resourceServers[audience];
    if (!resourceServer) throw new InvalidTarget();
    token.resourceServer = resourceServer;
    token.scope = grant.getResourceScopeFiltered(audience, ctx.oidc.requestParamScopes);
  } else {
    token.claims = ctx.oidc.claims;
    token.scope = grant.getOIDCScopeFiltered(ctx.oidc.requestParamOIDCScopes);
  }

  if (await expiresWithSession(ctx, token)) {
    token.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  ctx.oidc.entity('AccessToken', token);

  const result = {
    access_token: await token.save(),
    expires_in: token.expiration,
    token_type: token.tokenType,
    scope: token.scope,
  };

  return result;
}

async function codeHandler(ctx) {
  const {
    expiresWithSession,
  } = instance(ctx.oidc.provider).configuration();

  const { grant } = ctx.oidc;

  const scopeSet = combinedScope(
    grant, ctx.oidc.requestParamScopes, ctx.oidc.resourceServers,
  );

  console.log('007 clientId', ctx.oidc.client.clientId);
  console.log('007 grantId', ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId));

  const code = new ctx.oidc.provider.AuthorizationCode({
    accountId: ctx.oidc.session.accountId,
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.claims,
    client: ctx.oidc.client,
    codeChallenge: ctx.oidc.params.code_challenge,
    codeChallengeMethod: ctx.oidc.params.code_challenge_method,
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    nonce: ctx.oidc.params.nonce,
    redirectUri: ctx.oidc.params.redirect_uri,
    audience: Object.keys(ctx.oidc.resourceServers),
    scope: [...scopeSet].join(' '),
    sessionUid: ctx.oidc.session.uid,
  });

  console.error('Object.keys(ctx.oidc.resourceServers)', Object.keys(ctx.oidc.resourceServers));
  console.error('ctx.oidc.resourceServers', ctx.oidc.resourceServers);
  console.error('code.audience', code.audience);

  if (Object.keys(code.claims).length === 0) {
    delete code.claims;
  }

  // eslint-disable-next-line default-case
  switch (code.audience.length) {
    case 0:
      delete code.audience;
      break;
    case 1:
      [code.audience] = code.audience;
      break;
  }

  if (await expiresWithSession(ctx, code)) {
    code.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  if (ctx.oidc.client.includeSid() || (ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }

  ctx.oidc.entity('AuthorizationCode', code);

  return { code: await code.save() };
}

async function idTokenHandler(ctx) {
  const claims = filterClaims(ctx.oidc.claims, 'id_token', ctx.oidc.grant);
  const rejected = ctx.oidc.grant.getRejectedOIDCClaims();
  const scope = ctx.oidc.grant.getOIDCScopeFiltered(ctx.oidc.requestParamScopes);
  const idToken = new ctx.oidc.provider.IdToken({
    ...await ctx.oidc.account.claims('id_token', scope, claims, rejected),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    auth_time: ctx.oidc.session.authTime(),
  }, { ctx });

  const {
    conformIdTokenClaims, features: { userinfo },
  } = instance(ctx.oidc.provider).configuration();

  if (conformIdTokenClaims && userinfo.enabled && ctx.oidc.params.response_type !== 'id_token' && !ctx.oidc.params.audience) {
    idToken.scope = 'openid';
  } else {
    idToken.scope = scope;
  }

  idToken.mask = claims;
  idToken.rejected = rejected;

  idToken.set('nonce', ctx.oidc.params.nonce);

  if (ctx.oidc.client.includeSid() || (ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)) {
    idToken.set('sid', ctx.oidc.session.sidFor(ctx.oidc.client.clientId));
  }

  return { id_token: idToken };
}

/*
 * Resolves each requested response type to a single response object. If one of the hybrid
 * response types is used an appropriate _hash is also pushed on to the id_token.
 */
module.exports = async function processResponseTypes(ctx) {
  const responses = ctx.oidc.params.response_type.split(' ');
  const response = Object.assign({}, ...await Promise.all(responses.map((responseType) => {
    switch (responseType) {
      case 'code':
        return codeHandler(ctx);
      case 'token':
        return tokenHandler(ctx);
      case 'id_token':
        return idTokenHandler(ctx);
      default:
        return {};
    }
  })));

  if ('id_token' in response) {
    if ('access_token' in response) {
      response.id_token.set('at_hash', response.access_token);
    }

    if ('code' in response) {
      response.id_token.set('c_hash', response.code);
    }

    if (ctx.oidc.params.state) {
      response.id_token.set('s_hash', ctx.oidc.params.state);
    }

    response.id_token = await response.id_token.issue({ use: 'idtoken' });
  }

  return response;
};
