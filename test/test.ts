import { tap, expect } from '@pushrocks/tapbundle';

import * as smartacme from '../ts/index';

let smartAcmeInstance: smartacme.SmartAcme;

tap.test('should create a valid instance of SmartAcme', async () => {
  smartAcmeInstance = new smartacme.SmartAcme();
  await smartAcmeInstance.init({
    accountEmail: 'domains@lossless.org',
    accountPrivateKey: null,
    removeChallenge: async (...args) => {
      console.log(args);
    },
    setChallenge: async (...args) => {
      console.log(args);
    } 
  });
  await smartAcmeInstance.getCertificateForDomain('bleu.de');
});

tap.start();
