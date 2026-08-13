export interface Certificate {
  id: number;
  subject: string;
  organization: string;
  commonName: string;
  pem: string;

  // Rich info from JSON
  trustedEntityName: string;
  serviceName: string;
  serviceStatus: string;
  statusStartingTime: string;

  // Additional details from JSON
  trustedEntityAddress?: string;
  trustedEntityUri?: string;
  trustedEntityEmail?: string;
}
