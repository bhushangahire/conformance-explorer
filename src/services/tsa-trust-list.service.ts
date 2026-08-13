import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { map, shareReplay } from 'rxjs/operators';
import { Certificate } from '../models/certificate.model';
import { X509Certificate } from '@peculiar/x509';

// Interfaces for Trust List JSON Structure
interface JsonLangValue { lang: string; value: string; }
interface JsonLangUriValue { lang: string; uriValue: string; }
interface JsonPostalAddress { lang: string; StreetAddress: string; Locality: string; Country: string; StateOrProvince: string; PostalCode: string; }
interface JsonElectronicAddress { lang: string; uriValue: string; }
interface JsonTEAddress { TEPostalAddress?: JsonPostalAddress[]; TEElectronicAddress?: JsonElectronicAddress[]; }
interface JsonTrustedEntityInformation { TEName?: JsonLangValue[]; TEAddress?: JsonTEAddress; TEInformationURI?: JsonLangUriValue[]; }
interface JsonX509Certificate { val: string; }
interface JsonServiceDigitalIdentity { X509Certificates?: JsonX509Certificate[]; }
interface JsonServiceInformation { ServiceName?: JsonLangValue[]; ServiceDigitalIdentity?: JsonServiceDigitalIdentity; ServiceStatus: string; StatusStartingTime: string; }
interface JsonTrustedEntityService { ServiceInformation: JsonServiceInformation; }
interface JsonTrustedEntity { TrustedEntityInformation: JsonTrustedEntityInformation; TrustedEntityServices?: JsonTrustedEntityService[]; }
interface JsonLoTE { TrustedEntitiesList?: JsonTrustedEntity[]; }
interface JsonTrustList { LoTE: JsonLoTE; }

@Injectable({
  providedIn: 'root',
})
export class TsaTrustListService {
  private http = inject(HttpClient);
  private readonly JSON_URL = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.json';

  private certificates$ = this.http.get<JsonTrustList>(this.JSON_URL).pipe(
    map(json => this.parseJsonFile(json)),
    shareReplay(1)
  );

  certificates = toSignal(this.certificates$, { initialValue: [] as Certificate[] });

  private parseJsonFile(json: JsonTrustList): Certificate[] {
    const certificates: Certificate[] = [];
    let id = 0;

    const entities = json.LoTE?.TrustedEntitiesList || [];
    for (const entity of entities) {
      const info = entity.TrustedEntityInformation;
      if (!info) continue;

      const teName = info.TEName?.[0]?.value || 'Unknown Entity';
      const teUri = info.TEInformationURI?.[0]?.uriValue;
      
      // Extract email from TEElectronicAddress
      const teEmail = info.TEAddress?.TEElectronicAddress?.find(addr => addr.uriValue.startsWith('mailto:'))?.uriValue.replace('mailto:', '');
      
      // Format address
      const postal = info.TEAddress?.TEPostalAddress?.[0];
      const teAddress = postal ? `${postal.StreetAddress}, ${postal.Locality}, ${postal.StateOrProvince} ${postal.PostalCode}, ${postal.Country}` : undefined;

      const services = entity.TrustedEntityServices || [];
      for (const service of services) {
        const svcInfo = service.ServiceInformation;
        if (!svcInfo) continue;

        const serviceName = svcInfo.ServiceName?.[0]?.value || 'Unknown Service';
        const serviceStatus = svcInfo.ServiceStatus;
        const statusStartingTime = svcInfo.StatusStartingTime;

        const certs = svcInfo.ServiceDigitalIdentity?.X509Certificates || [];
        for (const cert of certs) {
          const val = cert.val;
          if (!val) continue;

          // Convert to PEM format
          const pem = `-----BEGIN CERTIFICATE-----\n${val.trim()}\n-----END CERTIFICATE-----`;

          // Try to decode X.509 to get subject/issuer etc. for compatibility
          let subject = 'N/A';
          let organization = 'N/A';
          let commonName = 'N/A';

          try {
            const x509 = new X509Certificate(pem);
            subject = x509.subject;
            const orgField = x509.subjectName.getField('O');
            const cnField = x509.subjectName.getField('CN');
            
            organization = Array.isArray(orgField) ? orgField[0] : orgField || 'N/A';
            commonName = Array.isArray(cnField) ? cnField[0] : cnField || 'N/A';
          } catch (e) {
            console.error('Failed to parse X509 certificate for', serviceName, e);
          }

          certificates.push({
            id: id++,
            subject,
            organization: organization !== 'N/A' ? organization : teName, // Fallback to TEName
            commonName: commonName !== 'N/A' ? commonName : serviceName, // Fallback to ServiceName
            pem,
            trustedEntityName: teName,
            serviceName,
            serviceStatus,
            statusStartingTime,
            trustedEntityAddress: teAddress,
            trustedEntityUri: teUri,
            trustedEntityEmail: teEmail
          });
        }
      }
    }

    return certificates;
  }
}