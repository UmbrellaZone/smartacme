import * as plugins from './smartacme.plugins';
import { CertManager } from './smartacme.classes.certmanager';

import { Collection, svDb, unI } from '@pushrocks/smartdata';

@plugins.smartdata.Collection(() => {
  return CertManager.activeDB;
})
export class Cert extends plugins.smartdata.SmartDataDbDoc<Cert> {
  @unI()
  public index: string;

  @svDb()
  domainName: string;

  @svDb()
  created: number;

  @svDb()
  privateKey: string;
  
  @svDb()
  publicKey: string;
  
  @svDb()
  csr: string;

  constructor(privateKeyArg: string, publicKeyArg: string, csrArg: string) {
    super();
    this.privateKey = privateKeyArg;
    this.publicKey = publicKeyArg;
    this.csr = csrArg;
  }
}
