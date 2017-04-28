## Usage
Use TypeScript for best in class instellisense.

```javascript
import { SmartAcme } from 'smartacme'

let smac = new SmartAcme()

(async () => { // learn async/await, it'll make your life easier

    // optionally accepts a filePath Arg with a stored acmeaccount.json
    // will create an account and 
    let myAccount = await smac.createAcmeAccount()
    
    // will return a dnsHash to set in your DNS record
    let myCert = await myAccount.createAcmeCert('example.com')

    // gets and accepts the specified challenge
    // first argument optional, defaults to dns-01 (which is the cleanest method for production use)
    let myChallenge = await myCert.getChallenge('dns-01')

    /* ----------
    Now you need to set the challenge in your DNS
    myChallenge.domainNamePrefixed is the address for the record
    myChallenge.dnsKeyHash is the ready to use txt record value expected by letsencrypt
    -------------*/
})()
```

## Other relevant npm modules
module name | description
--- | ---
cert | a higlevel production module that uses smartacme to manage certs
smartnginx | a highlevel production tool for docker environments to manage nginx 