import { tap, expect } from '@pushrocks/tapbundle';
import { Qenv } from '@pushrocks/qenv';

const testQenv = new Qenv('./', './.nogit/');

import * as smartacme from '../ts/index';

let smartAcmeInstance: smartacme.SmartAcme;

tap.test('should create a valid instance of SmartAcme', async () => {
  smartAcmeInstance = new smartacme.SmartAcme({
    accountEmail: 'domains@lossless.org',
    accountPrivateKey: null,
    removeChallenge: async (...args) => {
      console.log(args);
    },
    setChallenge: async (...args) => {
      console.log(args);
    },
    mongoDescriptor: {
      mongoDbName: testQenv.getEnvVarOnDemand('MONGODB_DATABASE'),
      mongoDbPass: testQenv.getEnvVarOnDemand('MONGODB_PASSWORD'),
      mongoDbUrl: testQenv.getEnvVarOnDemand('MONGODB_URL')
    }
  });
  await smartAcmeInstance.init();
  await smartAcmeInstance.getCertificateForDomain('bleu.de');
});

tap.start();
