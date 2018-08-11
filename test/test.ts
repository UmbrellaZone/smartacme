import { tap, expect } from 'tapbundle';

import * as smartacme from '../ts/index';

let smartAcmeInstance: smartacme.SmartAcme;

tap.test('should create a valid instance of SmartAcme' , async () => {
  smartAcmeInstance = new smartacme.SmartAcme();
  await smartAcmeInstance.init()
  console.log(smartAcmeInstance.directoryUrls);
  await smartAcmeInstance.getCertificateForDomain('bleu.de');
})

tap.start();