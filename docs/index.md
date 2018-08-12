# smartacme

acme implementation in TypeScript

## Availabililty

[![npm](https://umbrellazone.gitlab.io/assets/repo-button-npm.svg)](https://www.npmjs.com/package/smartacme)
[![git](https://umbrellazone.gitlab.io/assets/repo-button-git.svg)](https://GitLab.com/umbrellazone/smartacme)
[![git](https://umbrellazone.gitlab.io/assets/repo-button-mirror.svg)](https://github.com/umbrellazone/smartacme)
[![docs](https://umbrellazone.gitlab.io/assets/repo-button-docs.svg)](https://umbrellazone.gitlab.io/smartacme/)

## Status for master

[![build status](https://GitLab.com/umbrellazone/smartacme/badges/master/build.svg)](https://GitLab.com/umbrellazone/smartacme/commits/master)
[![coverage report](https://GitLab.com/umbrellazone/smartacme/badges/master/coverage.svg)](https://GitLab.com/umbrellazone/smartacme/commits/master)
[![npm downloads per month](https://img.shields.io/npm/dm/smartacme.svg)](https://www.npmjs.com/package/smartacme)
[![Dependency Status](https://david-dm.org/umbrellazone/smartacme.svg)](https://david-dm.org/umbrellazone/smartacme)
[![bitHound Dependencies](https://www.bithound.io/github/umbrellazone/smartacme/badges/dependencies.svg)](https://www.bithound.io/github/umbrellazone/smartacme/master/dependencies/npm)
[![bitHound Code](https://www.bithound.io/github/umbrellazone/smartacme/badges/code.svg)](https://www.bithound.io/github/umbrellazone/smartacme)
[![TypeScript](https://img.shields.io/badge/TypeScript-2.x-blue.svg)](https://nodejs.org/dist/latest-v6.x/docs/api/)
[![node](https://img.shields.io/badge/node->=%206.x.x-blue.svg)](https://nodejs.org/dist/latest-v6.x/docs/api/)
[![JavaScript Style Guide](https://img.shields.io/badge/code%20style-standard-brightgreen.svg)](http://standardjs.com/)

## Usage

Use TypeScript for best in class instellisense.

```javascript
import { SmartAcme } from 'smartacme';

let smac = new SmartAcme()(async () => {
  // learn async/await, it'll make your life easier

  // optionally accepts a filePath Arg with a stored acmeaccount.json
  // will create an account and
  let myAccount = await smac.createAcmeAccount();

  // will return a dnsHash to set in your DNS record
  let myCert = await myAccount.createAcmeCert('example.com');

  // gets and accepts the specified challenge
  // first argument optional, defaults to dns-01 (which is the cleanest method for production use)
  let myChallenge = await myCert.getChallenge('dns-01');

  /* ----------
    Now you need to set the challenge in your DNS
    myChallenge.domainNamePrefixed is the address for the record
    myChallenge.dnsKeyHash is the ready to use txt record value expected by letsencrypt
    -------------*/
})();
```

## Other relevant npm modules

| module name | description                                                         |
| ----------- | ------------------------------------------------------------------- |
| cert        | a higlevel production module that uses smartacme to manage certs    |
| smartnginx  | a highlevel production tool for docker environments to manage nginx |

> MIT licensed | **&copy;** [Lossless GmbH](https://lossless.gmbh)
> | By using this npm module you agree to our [privacy policy](https://lossless.gmbH/privacy.html)

[![repo-footer](https://umbrellazone.gitlab.io/assets/repo-footer.svg)](https://umbrella.zone
