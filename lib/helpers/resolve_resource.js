const { InvalidTarget } = require('./errors');

module.exports = async (ctx, model, config, scopes = model.scopes) => {
  let resource;
  if (config.resourceIndicators.enabled) {
    // eslint-disable-next-line default-case
    switch (true) {
      case !!ctx.oidc.params.audience:
        resource = ctx.oidc.params.audience;
        break;
      case !model.resource:
      case Array.isArray(model.resource) && model.resource.length === 0:
        break;
      case model.resource && !!config.resourceIndicators.useGrantedResource(ctx, model):
      case !ctx.oidc.params.audience && (!config.userinfo.enabled || !scopes.has('openid')):
        resource = model.resource;
        break;
    }

    if (Array.isArray(resource)) {
      resource = await config.resourceIndicators.defaultResource(ctx, ctx.oidc.client, resource);
    }

    if (Array.isArray(resource)) {
      throw new InvalidTarget('only a single resource indicator value must be requested/resolved during Access Token Request');
    }

    if (resource && !model.resourceIndicators.has(resource)) {
      throw new InvalidTarget();
    }
  }
  return resource;
};
