# smartacme
acme implementation in TypeScript

## Availabililty
[![npm](https://push.rocks/assets/repo-button-npm.svg)](https://www.npmjs.com/package/smartacme)
[![git](https://push.rocks/assets/repo-button-git.svg)](https://GitLab.com/pushrocks/smartacme)
[![git](https://push.rocks/assets/repo-button-mirror.svg)](https://github.com/pushrocks/smartacme)
[![docs](https://push.rocks/assets/repo-button-docs.svg)](https://pushrocks.gitlab.io/smartacme/)

## Status for master
[![build status](https://GitLab.com/pushrocks/smartacme/badges/master/build.svg)](https://GitLab.com/pushrocks/smartacme/commits/master)
[![coverage report](https://GitLab.com/pushrocks/smartacme/badges/master/coverage.svg)](https://GitLab.com/pushrocks/smartacme/commits/master)
[![npm downloads per month](https://img.shields.io/npm/dm/smartacme.svg)](https://www.npmjs.com/package/smartacme)
[![Dependency Status](https://david-dm.org/pushrocks/smartacme.svg)](https://david-dm.org/pushrocks/smartacme)
[![bitHound Dependencies](https://www.bithound.io/github/pushrocks/smartacme/badges/dependencies.svg)](https://www.bithound.io/github/pushrocks/smartacme/master/dependencies/npm)
[![bitHound Code](https://www.bithound.io/github/pushrocks/smartacme/badges/code.svg)](https://www.bithound.io/github/pushrocks/smartacme)
[![TypeScript](https://img.shields.io/badge/TypeScript-2.x-blue.svg)](https://nodejs.org/dist/latest-v6.x/docs/api/)
[![node](https://img.shields.io/badge/node->=%206.x.x-blue.svg)](https://nodejs.org/dist/latest-v6.x/docs/api/)
[![JavaScript Style Guide](https://img.shields.io/badge/code%20style-standard-brightgreen.svg)](http://standardjs.com/)

## Usage
Use TypeScript for best in class instellisense.

```javascript
import { SmartAcme } from 'smartacme'

let smac = new SmartAcme()

let myAccount = smac.getAccount() // optionally accepts a filePath Arg with a stored acmeaccount.json
let myCert = myAccount.getChallenge('example.com','dns-01') // will return a dnsHash to set in your DNS record
myCert.get().then(() => {
    console.log(myCert.certificate) // your certificate, ready to use in whatever way you prefer
})
```

[![npm](https://push.rocks/assets/repo-header.svg)](https://push.rocks)
