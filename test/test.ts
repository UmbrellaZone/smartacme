import { tap, expect } from '@pushrocks/tapbundle';
import { Qenv } from '@pushrocks/qenv';
import * as cloudflare from '@mojoio/cloudflare';

const testQenv = new Qenv('./', './.nogit/');
const testCloudflare = new cloudflare.CloudflareAccount(testQenv.getEnvVarOnDemand('CF_TOKEN'));

import * as smartacme from '../ts/index';

let smartAcmeInstance: smartacme.SmartAcme;

tap.test('should create a valid instance of SmartAcme', async () => {
  smartAcmeInstance = new smartacme.SmartAcme({
    accountEmail: 'domains@lossless.org',
    accountPrivateKey: null,
    mongoDescriptor: {
      mongoDbName: testQenv.getEnvVarRequired('MONGODB_DATABASE'),
      mongoDbPass: testQenv.getEnvVarRequired('MONGODB_PASSWORD'),
      mongoDbUrl: testQenv.getEnvVarRequired('MONGODB_URL'),
    },
    removeChallenge: async (dnsChallenge) => {
      testCloudflare.convenience.acmeRemoveDnsChallenge(dnsChallenge);
    },
    setChallenge: async (dnsChallenge) => {
      testCloudflare.convenience.acmeSetDnsChallenge(dnsChallenge);
    },
    environment: 'integration',
  });
  await smartAcmeInstance.init();
});

tap.test('should get a domain certificate', async () => {
  const certificate = await smartAcmeInstance.getCertificateForDomain('bleu.de');
  console.log(certificate);
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
