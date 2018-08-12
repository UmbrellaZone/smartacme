const acme = require('acme-v2').ACME.create({
  RSA: require('rsa-compat').RSA,

  // used for constructing user-agent
  os: require('os'),
  process: require('process'),

  // used for overriding the default user-agent
  userAgent: 'My custom UA String',
  getUserAgentString: function(deps) {
    return 'My custom UA String';
  },

  // don't try to validate challenges locally
  skipChallengeTest: true
});

import { KeyPair } from './smartacme.classes.keypair';
import * as plugins from './smartacme.plugins';
const rsa = require('rsa-compat').RSA;

export class SmartAcme {
  domainKeyPair: KeyPair;
  accountKeyPair: KeyPair;
  accountData: any;
  directoryUrls: any;

  async init() {
    // get directory url
    this.directoryUrls = await acme.init('https://acme-staging-v02.api.letsencrypt.org/directory');

    // create keyPairs
    this.domainKeyPair = await KeyPair.generateFresh();
    this.accountKeyPair = await KeyPair.generateFresh();

    // get account
    const registrationData = await acme.accounts
      .create({
        email: 'domains@lossless.org', // valid email (server checks MX records)
        accountKeypair: this.accountKeyPair.rsaKeyPair,
        agreeToTerms: async tosUrl => {
          return tosUrl;
        }
      })
      .catch(e => {
        console.log(e);
      });
    this.accountData = registrationData;
  }

  async getCertificateForDomain(domain) {
    const result = await acme.certificates
      .create({
        domainKeypair: this.domainKeyPair.rsaKeyPair,
        accountKeypair: this.accountKeyPair.rsaKeyPair,
        domains: ['bleu.de'],
        challengeType: 'dns-01',

        setChallenge: async (hostname, key, val, cb) => {
          console.log('set challenge');
          console.log(hostname);
          //console.log(key);
          //console.log(val);
          const dnsKey = rsa.utils.toWebsafeBase64(
            require('crypto')
              .createHash('sha256')
              .update(val)
              .digest('base64')
          );

          console.log(dnsKey);
          await plugins.smartdelay.delayFor(20000);
          console.log('ready!');
          cb();
        }, // return Promise
        removeChallenge: async (hostname, key) => {
          console.log('removing challenge');
          return;
        } // return Promise
      })
      .catch(e => {
        console.log(e);
      }); // returns Promise<pems={ privkey (key), cert, chain (ca) }>
    console.log(result);
  }
}
