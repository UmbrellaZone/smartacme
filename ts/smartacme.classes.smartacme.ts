const acme = require('acme-v2').ACME.create({
  RSA: require('rsa-compat').RSA,

  // other overrides
  promisify: require('util').promisify,

  // used for constructing user-agent
  os: require('os'),
  process: require('process'),

  // used for overriding the default user-agent
  userAgent: 'My custom UA String',
  getUserAgentString: function(deps) {
    return 'My custom UA String';
  },

  // don't try to validate challenges locally
  skipChallengeTest: false
});

import { KeyPair } from './smartacme.classes.keypair';

export class SmartAcme {
  keyPair: KeyPair;
  directoryUrls: any;

  async init() {
    // get directory url
    this.directoryUrls = await acme.init('https://acme-staging-v02.api.letsencrypt.org/directory');

    // create keyPair
    this.keyPair = await KeyPair.generateFresh();

    // get account
    const registrationData = await acme.accounts.create({
      email: 'domains@lossless.org', // valid email (server checks MX records)
      accountKeypair: this.keyPair.rsaKeyPair,
      agreeToTerms: async tosUrl => {
        return tosUrl;
      }
    }).catch(e => {
      console.log(e);
    });

    console.log(registrationData);
  }
}
