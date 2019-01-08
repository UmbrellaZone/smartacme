import * as plugins from './smartacme.plugins';
import * as interfaces from './interfaces';
import { ICertRemoteResponse } from './interfaces';

// tslint:disable-next-line: max-classes-per-file
export class CertRemoteClient {
  private remoteUrl: string;
  private secret: string;

  constructor(optionsArg: {
    remoteUrl: string;
    secret: string;
  }) {
    this.remoteUrl = optionsArg.remoteUrl;
    this.secret = optionsArg.secret;
  }

  /**
   * 
   * @param domainNameArg 
   */
  async getCertificateForDomain(domainNameArg: string): Promise<interfaces.ICert> {
    let certificate: interfaces.ICert;
    const doRequestCycle = async (): Promise<interfaces.ICert> => {
      const response: ICertRemoteResponse = (await plugins.smartrequest.postJson(this.remoteUrl, {
        requestBody: <interfaces.ICertRemoteRequest>{
          domainName: domainNameArg,
          secret: this.secret
        }
      })).body;
      switch(response.status) {
        case 'pending':
          await plugins.smartdelay.delayFor(5000);
          const finalResponse = await doRequestCycle();
          return finalResponse;
        case 'existing':
          return response.certificate;
        case 'failed':
        default:
          console.log(`could not retrieve certificate for ${domainNameArg}`);
          return null;
      }
    };
    certificate = await doRequestCycle();
    return certificate;
  }
}
