# @pushrocks/smartuniverse
acme with an easy yet powerful interface in TypeScript

## Availabililty and Links
* [npmjs.org (npm package)](https://www.npmjs.com/package/@pushrocks/smartuniverse)
* [gitlab.com (source)](https://gitlab.com/pushrocks/smartuniverse)
* [github.com (source mirror)](https://github.com/pushrocks/smartuniverse)
* [docs (typedoc)](https://pushrocks.gitlab.io/smartuniverse/)

## Status for master
[![pipeline status](https://gitlab.com/pushrocks/smartuniverse/badges/master/pipeline.svg)](https://gitlab.com/pushrocks/smartuniverse/commits/master)
[![coverage report](https://gitlab.com/pushrocks/smartuniverse/badges/master/coverage.svg)](https://gitlab.com/pushrocks/smartuniverse/commits/master)
[![npm downloads per month](https://img.shields.io/npm/dm/@pushrocks/smartuniverse.svg)](https://www.npmjs.com/package/@pushrocks/smartuniverse)
[![Known Vulnerabilities](https://snyk.io/test/npm/@pushrocks/smartuniverse/badge.svg)](https://snyk.io/test/npm/@pushrocks/smartuniverse)
[![TypeScript](https://img.shields.io/badge/TypeScript->=%203.x-blue.svg)](https://nodejs.org/dist/latest-v10.x/docs/api/)
[![node](https://img.shields.io/badge/node->=%2010.x.x-blue.svg)](https://nodejs.org/dist/latest-v10.x/docs/api/)
[![JavaScript Style Guide](https://img.shields.io/badge/code%20style-prettier-ff69b4.svg)](https://prettier.io/)

## Usage

Use TypeScript for best in class instellisense.

```javascript
import { SmartAcme } from 'smartacme';

const run = async () => {
  smartAcmeInstance = new smartacme.SmartAcme({
    accountEmail: 'domains@lossless.org',
    accountPrivateKey: null,
    mongoDescriptor: {
      mongoDbName: testQenv.getEnvVarRequired('MONGODB_DATABASE'),
      mongoDbPass: testQenv.getEnvVarRequired('MONGODB_PASSWORD'),
      mongoDbUrl: testQenv.getEnvVarRequired('MONGODB_URL')
    },
    removeChallenge: async dnsChallenge => {
      // somehow provide a function that is able to remove the dns challenge
    },
    setChallenge: async dnsChallenge => {
      // somehow provide a function that is able to the dns challenge
    },
    environment: 'integration'
  });
  await smartAcmeInstance.init();

  // myCert has properties for public/private keys and csr ;)
  const myCert = await smartAcmeInstance.getCertificateForDomain('bleu.de');
};
```

## Contribution

We are always happy for code contributions. If you are not the code contributing type that is ok. Still, maintaining Open Source repositories takes considerable time and thought. If you like the quality of what we do and our modules are useful to you we would appreciate a little monthly contribution: You can [contribute one time](https://lossless.link/contribute-onetime) or [contribute monthly](https://lossless.link/contribute). :)

For further information read the linked docs at the top of this readme.

> MIT licensed | **&copy;** [Lossless GmbH](https://lossless.gmbh)
| By using this npm module you agree to our [privacy policy](https://lossless.gmbH/privacy)

[![repo-footer](https://lossless.gitlab.io/publicrelations/repofooter.svg)](https://maintainedby.lossless.com)
