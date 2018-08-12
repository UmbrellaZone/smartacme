import * as plugins from './smartacme.plugins';
const rsa = require('rsa-compat').RSA;

export class KeyPair {
  rsaKeyPair: any;

  /**
   * generates a fresh rsa keyPair
   */
  static async generateFresh(): Promise<KeyPair> {
    const done = plugins.smartpromise.defer();
    var options = { bitlen: 2048, exp: 65537, public: true, pem: true, internal: true };
    rsa.generateKeypair(options, function(err, keypair) {
      if (err) {
        console.log(err);
      }
      done.resolve(keypair);
    });
    const result: any = await done.promise;
    const keyPair = new KeyPair(result);
    return keyPair;
  }

  constructor(rsaKeyPairArg) {
    this.rsaKeyPair = rsaKeyPairArg;
  }
}
