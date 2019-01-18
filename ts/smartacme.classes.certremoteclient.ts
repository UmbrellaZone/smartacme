import * as plugins from './smartacme.plugins';
import * as interfaces from './interfaces';

// tslint:disable-next-line: max-classes-per-file
export class CertRemoteClient {
  private remoteUrl: string;
  private secret: string;
  private logger: plugins.smartlog.Smartlog;

  constructor(optionsArg: {
    remoteUrl: string;
    secret: string;
    logger?: plugins.smartlog.Smartlog;
  }) {
    this.remoteUrl = optionsArg.remoteUrl;
    this.secret = optionsArg.secret;
    optionsArg.logger
      ? (this.logger = optionsArg.logger)
      : (this.logger = plugins.smartlog.defaultLogger);
  }

  /**
   *
   * @param domainNameArg
   */
  public async getCertificateForDomain(domainNameArg: string): Promise<interfaces.ICert> {
    let certificate: interfaces.ICert;
    const doRequestCycle = async (): Promise<interfaces.ICert> => {
      const responseBody: interfaces.ICertRemoteResponse = (await plugins.smartrequest.postJson(
        this.remoteUrl,
        {
          requestBody: <interfaces.ICertRemoteRequest>{
            domainName: domainNameArg,
            secret: this.secret
          }
        }
      )).body;
      switch (responseBody.status as interfaces.TCertStatus) {
        case 'pending':
          this.logger.log('info', `request for ${domainNameArg} still pending!`);
          await plugins.smartdelay.delayFor(5000);
          const finalResponse = await doRequestCycle();
          return finalResponse;
        case 'existing':
          this.logger.log('ok', `got certificate for ${domainNameArg}`);
          return responseBody.certificate;
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
