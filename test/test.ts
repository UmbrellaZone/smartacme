import { tap, expect } from '@pushrocks/tapbundle';
import { Qenv } from '@pushrocks/qenv';

const testQenv = new Qenv('./', './.nogit/');

import * as smartacme from '../ts/index';

let smartAcmeInstance: smartacme.SmartAcme;

tap.test('should create a valid instance of SmartAcme', async () => {
  smartAcmeInstance = new smartacme.SmartAcme({
    accountEmail: 'domains@lossless.org',
    accountPrivateKey: null,
    mongoDescriptor: {
      mongoDbName: testQenv.getEnvVarRequired('MONGODB_DATABASE'),
      mongoDbPass: testQenv.getEnvVarRequired('MONGODB_PASSWORD'),
      mongoDbUrl: testQenv.getEnvVarRequired('MONGODB_URL')
    },
    removeChallenge: async (...args) => {
      console.log(args);
    },
    setChallenge: async (...args) => {
      console.log(args);
    },
    environment: "integration"
  });
  await smartAcmeInstance.init();
  // await smartAcmeInstance.getCertificateForDomain('bleu.de');
});

tap.test('certmatcher should correctly match domains', async () => {
  const certMatcherMod = await import('../ts/smartacme.classes.certmatcher'); 
  const certMatcher = new certMatcherMod.CertMatcher();
  const matchedCert = certMatcher.getCertificateDomainNameByDomainName('level3.level2.level1');
  expect(matchedCert).to.equal('level2.level1');
});

tap.test('should stop correctly', async () => {
  await smartAcmeInstance.stop();
});

tap.start();
