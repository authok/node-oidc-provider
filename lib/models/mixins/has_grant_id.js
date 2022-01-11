module.exports = (superclass) => class extends superclass {
  static async revokeByGrantId(ctx, grantId) {
    await this.adapter.revokeByGrantId(ctx, grantId);
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'grantId',
    ];
  }
};
