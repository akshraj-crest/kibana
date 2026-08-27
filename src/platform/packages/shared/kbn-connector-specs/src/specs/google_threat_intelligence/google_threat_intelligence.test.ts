/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import type { ActionContext } from '../../connector_spec';
import { GoogleThreatIntelligenceConnector } from './google_threat_intelligence';
import {
  GetFileBehavioursInputSchema,
  GetFileMitreAttackTechniquesInputSchema,
  GetIpReportInputSchema,
  GetIpRelationshipInputSchema,
  GetDomainReportInputSchema,
  GetDomainRelationshipInputSchema,
  GetUrlReportInputSchema,
  GetUrlRelationshipInputSchema,
  GetFileReportInputSchema,
  GetFileRelationshipInputSchema,
  ScanUrlInputSchema,
  GetAnalysisInputSchema,
  GetUrlScanReportInputSchema,
  ScanPrivateUrlInputSchema,
  GetPrivateAnalysisInputSchema,
  GetPrivateUrlReportInputSchema,
} from './types';

const SHA256_HASH = '25d8ae4678c37251e7ffbaeddc252ae2530ef23f66e4c856d98ef60f399fa3dc';

describe('GoogleThreatIntelligenceConnector', () => {
  const mockClient = {
    get: jest.fn(),
    post: jest.fn(),
  };

  const mockContext = {
    client: mockClient,
    config: {},
    log: {},
    secrets: { authType: 'api_key_header', apiKey: 'gti-test-key' },
  } as unknown as ActionContext;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(GoogleThreatIntelligenceConnector).toBeDefined();
  });

  describe('test handler', () => {
    it('calls the IP report endpoint with the x-tool header and resolves when gti_assessment is present', async () => {
      mockClient.get.mockResolvedValue({
        data: { data: { attributes: { gti_assessment: { contributing_factors: {} } } } },
      });

      const result = await GoogleThreatIntelligenceConnector.test.handler(mockContext);

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8');
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual({});
    });

    it('throws a subscription-tier error when the key is valid but gti_assessment is absent', async () => {
      mockClient.get.mockResolvedValue({ data: { data: { attributes: {} } } });

      await expect(GoogleThreatIntelligenceConnector.test.handler(mockContext)).rejects.toThrow(
        'does not have an Enterprise subscription'
      );
    });

    it('throws on API/network failure, same as every action (see "GTI API error handling" below)', async () => {
      mockClient.get.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(GoogleThreatIntelligenceConnector.test.handler(mockContext)).rejects.toThrow(
        'ECONNREFUSED'
      );
    });
  });

  describe('getFileBehaviours', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getFileBehaviours.handler;

    it('rejects a malformed hash at the schema level, before the handler runs', () => {
      const result = GetFileBehavioursInputSchema.safeParse({ fileHash: 'test' });
      expect(result.success).toBe(false);
    });

    it('rejects a hash longer than 64 characters at the schema level', () => {
      const result = GetFileBehavioursInputSchema.safeParse({ fileHash: `${SHA256_HASH}a` });
      expect(result.success).toBe(false);
    });

    it('rejects a limit above 40 at the schema level', () => {
      const result = GetFileBehavioursInputSchema.safeParse({ fileHash: SHA256_HASH, limit: 41 });
      expect(result.success).toBe(false);
    });

    it('rejects a negative limit at the schema level', () => {
      const result = GetFileBehavioursInputSchema.safeParse({ fileHash: SHA256_HASH, limit: -1 });
      expect(result.success).toBe(false);
    });

    it('accepts limit at its boundary values (0 and 40)', () => {
      expect(
        GetFileBehavioursInputSchema.safeParse({ fileHash: SHA256_HASH, limit: 0 }).success
      ).toBe(true);
      expect(
        GetFileBehavioursInputSchema.safeParse({ fileHash: SHA256_HASH, limit: 40 }).success
      ).toBe(true);
    });

    it('calls the behaviours endpoint with the hash and x-tool header, and returns populated data as-is', async () => {
      const apiResponse = {
        data: [
          {
            id: `${SHA256_HASH}_C2AE`,
            type: 'file_behaviour',
            attributes: { sandbox_name: 'C2AE' },
          },
        ],
        meta: { count: 1 },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { fileHash: SHA256_HASH });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(`https://www.virustotal.com/api/v3/files/${SHA256_HASH}/behaviours`);
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('resolves with an empty collection for a hash known to GTI but never sandboxed', async () => {
      mockClient.get.mockResolvedValue({
        data: { data: [], meta: { count: 0 } },
      });

      const result = await handler(mockContext, { fileHash: SHA256_HASH });

      expect(result).toEqual({ data: [], meta: { count: 0 } });
    });

    it('throws on a 404 (hash unknown to GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: `File "${SHA256_HASH}" not found` } },
        },
      });

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow(
        `GTI API error (404): File "${SHA256_HASH}" not found`
      );
    });
  });

  describe('getFileMitreAttackTechniques', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getFileMitreAttackTechniques.handler;

    it('rejects a malformed hash at the schema level, before the handler runs', () => {
      const result = GetFileMitreAttackTechniquesInputSchema.safeParse({ fileHash: 'test' });
      expect(result.success).toBe(false);
    });

    it('calls the behaviour_mitre_trees endpoint with the hash and x-tool header, and returns the sandbox-keyed data as-is', async () => {
      const apiResponse = {
        data: {
          Zenbox: {
            tactics: [
              {
                id: 'TA0005',
                name: 'Stealth',
                techniques: [
                  {
                    id: 'T1027',
                    name: 'Obfuscated Files or Information',
                    signatures: [{ severity: 'INFO', description: 'encode data using XOR' }],
                  },
                ],
              },
            ],
          },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { fileHash: SHA256_HASH });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/files/${SHA256_HASH}/behaviour_mitre_trees`
      );
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('resolves with an empty object for a hash known to GTI but never sandboxed', async () => {
      mockClient.get.mockResolvedValue({ data: { data: {} } });

      const result = await handler(mockContext, { fileHash: SHA256_HASH });

      expect(result).toEqual({ data: {} });
    });

    it('throws on a 404 (hash unknown to GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: `File "${SHA256_HASH}" not found` } },
        },
      });

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow(
        `GTI API error (404): File "${SHA256_HASH}" not found`
      );
    });
  });

  describe('getIpReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getIpReport.handler;

    it('rejects a malformed IP address at the schema level, before the handler runs', () => {
      const result = GetIpReportInputSchema.safeParse({ ipAddress: 'not-an-ip' });
      expect(result.success).toBe(false);
    });

    it('accepts a valid IPv4 address', () => {
      expect(GetIpReportInputSchema.safeParse({ ipAddress: '8.8.8.8' }).success).toBe(true);
    });

    it('accepts a valid IPv6 address', () => {
      expect(GetIpReportInputSchema.safeParse({ ipAddress: '2001:4860:4860::8888' }).success).toBe(
        true
      );
    });

    it('calls the ip_addresses endpoint with the address and x-tool header, URL-encodes an IPv6 address, and returns the report as-is', async () => {
      const apiResponse = {
        data: {
          id: '2001:4860:4860::8888',
          type: 'ip_address',
          attributes: {
            as_owner: 'Google LLC',
            asn: 15169,
            network: '2001:4860:4860::/48',
            gti_assessment: { verdict: { value: 'VERDICT_BENIGN' } },
          },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { ipAddress: '2001:4860:4860::8888' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(
          '2001:4860:4860::8888'
        )}`
      );
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });
  });

  describe('getIpRelationship', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getIpRelationship.handler;

    it('rejects a malformed IP address at the schema level, before the handler runs', () => {
      const result = GetIpRelationshipInputSchema.safeParse({
        ipAddress: 'not-an-ip',
        relationship: 'resolutions',
      });
      expect(result.success).toBe(false);
    });

    it('rejects an empty relationship string at the schema level, before the handler runs', () => {
      const result = GetIpRelationshipInputSchema.safeParse({
        ipAddress: '8.8.8.8',
        relationship: '',
      });
      expect(result.success).toBe(false);
    });

    it('accepts a couple of representative relationship values', () => {
      expect(
        GetIpRelationshipInputSchema.safeParse({
          ipAddress: '8.8.8.8',
          relationship: 'communicating_files',
        }).success
      ).toBe(true);
      expect(
        GetIpRelationshipInputSchema.safeParse({
          ipAddress: '8.8.8.8',
          relationship: 'resolutions',
        }).success
      ).toBe(true);
    });

    it('rejects a limit above 40 at the schema level', () => {
      const result = GetIpRelationshipInputSchema.safeParse({
        ipAddress: '8.8.8.8',
        relationship: 'urls',
        limit: 41,
      });
      expect(result.success).toBe(false);
    });

    it('rejects a negative limit at the schema level', () => {
      const result = GetIpRelationshipInputSchema.safeParse({
        ipAddress: '8.8.8.8',
        relationship: 'urls',
        limit: -1,
      });
      expect(result.success).toBe(false);
    });

    it('accepts limit at its boundary values (0 and 40)', () => {
      expect(
        GetIpRelationshipInputSchema.safeParse({
          ipAddress: '8.8.8.8',
          relationship: 'urls',
          limit: 0,
        }).success
      ).toBe(true);
      expect(
        GetIpRelationshipInputSchema.safeParse({
          ipAddress: '8.8.8.8',
          relationship: 'urls',
          limit: 40,
        }).success
      ).toBe(true);
    });

    it('calls the relationship endpoint with both segments encoded, passes limit/cursor through, and returns the response as-is', async () => {
      const apiResponse = {
        data: [
          { id: 'resolution-id', type: 'resolution', attributes: { host_name: 'example.com' } },
        ],
        meta: { count: 200, cursor: 'opaque-cursor' },
        links: {
          self: 'https://www.virustotal.com/api/v3/ip_addresses/2606:4700:4700::1111/resolutions?limit=2',
          next: 'https://www.virustotal.com/api/v3/ip_addresses/2606:4700:4700::1111/resolutions?limit=2&cursor=opaque-cursor',
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, {
        ipAddress: '2606:4700:4700::1111',
        relationship: 'resolutions',
        limit: 2,
      });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(
          '2606:4700:4700::1111'
        )}/resolutions`
      );
      expect(call[1]).toMatchObject({
        headers: { 'x-tool': 'Elastic' },
        params: { limit: 2, cursor: undefined },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (relationship not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Resource not found.' } },
        },
      });

      await expect(
        handler(mockContext, { ipAddress: '8.8.8.8', relationship: 'not_a_real_relationship' })
      ).rejects.toThrow('GTI API error (404): Resource not found.');
    });

    it('resolves with an empty collection when limit is 0', async () => {
      mockClient.get.mockResolvedValue({
        data: { data: [], meta: { count: 200 }, links: { self: 'https://example.com' } },
      });

      const result = await handler(mockContext, {
        ipAddress: '8.8.8.8',
        relationship: 'resolutions',
        limit: 0,
      });

      expect(result).toEqual({
        data: [],
        meta: { count: 200 },
        links: { self: 'https://example.com' },
      });
    });
  });

  describe('getDomainReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getDomainReport.handler;

    it('rejects a malformed domain at the schema level, before the handler runs', () => {
      const result = GetDomainReportInputSchema.safeParse({ domain: 'not a domain!!' });
      expect(result.success).toBe(false);
    });

    it('accepts a valid domain name', () => {
      expect(GetDomainReportInputSchema.safeParse({ domain: 'example.com' }).success).toBe(true);
    });

    it('rejects a domain longer than 253 characters at the schema level', () => {
      const overlong = `${Array(130).fill('a').join('.')}.com`;
      const result = GetDomainReportInputSchema.safeParse({ domain: overlong });
      expect(result.success).toBe(false);
    });

    it('calls the domains endpoint with the domain and x-tool header, and returns the report as-is', async () => {
      const apiResponse = {
        data: {
          id: 'example.com',
          type: 'domain',
          attributes: {
            registrar: 'GoDaddy.com, LLC',
            tld: 'com',
            gti_assessment: { verdict: { value: 'VERDICT_BENIGN' } },
          },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { domain: 'example.com' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/domains/example.com');
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (domain unknown to GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Domain "example.com" not found' } },
        },
      });

      await expect(handler(mockContext, { domain: 'example.com' })).rejects.toThrow(
        'GTI API error (404): Domain "example.com" not found'
      );
    });
  });

  describe('getDomainRelationship', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getDomainRelationship.handler;

    it('rejects a malformed domain at the schema level, before the handler runs', () => {
      const result = GetDomainRelationshipInputSchema.safeParse({
        domain: 'not a domain!!',
        relationship: 'resolutions',
      });
      expect(result.success).toBe(false);
    });

    it('rejects an empty relationship string at the schema level, before the handler runs', () => {
      const result = GetDomainRelationshipInputSchema.safeParse({
        domain: 'example.com',
        relationship: '',
      });
      expect(result.success).toBe(false);
    });

    it('accepts a couple of representative relationship values', () => {
      expect(
        GetDomainRelationshipInputSchema.safeParse({
          domain: 'example.com',
          relationship: 'subdomains',
        }).success
      ).toBe(true);
      expect(
        GetDomainRelationshipInputSchema.safeParse({
          domain: 'example.com',
          relationship: 'resolutions',
        }).success
      ).toBe(true);
    });

    it('rejects a limit above 40 at the schema level', () => {
      const result = GetDomainRelationshipInputSchema.safeParse({
        domain: 'example.com',
        relationship: 'resolutions',
        limit: 41,
      });
      expect(result.success).toBe(false);
    });

    it('accepts limit at its boundary values (0 and 40)', () => {
      expect(
        GetDomainRelationshipInputSchema.safeParse({
          domain: 'example.com',
          relationship: 'resolutions',
          limit: 0,
        }).success
      ).toBe(true);
      expect(
        GetDomainRelationshipInputSchema.safeParse({
          domain: 'example.com',
          relationship: 'resolutions',
          limit: 40,
        }).success
      ).toBe(true);
    });

    it('calls the relationship endpoint with both segments encoded, passes limit/cursor through, and returns the response as-is', async () => {
      const apiResponse = {
        data: [
          {
            id: '172.67.155.74example.com',
            type: 'resolution',
            attributes: { host_name: 'example.com', ip_address: '172.67.155.74' },
          },
        ],
        meta: { count: 2 },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, {
        domain: 'example.com',
        relationship: 'resolutions',
        limit: 2,
      });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/domains/example.com/resolutions');
      expect(call[1]).toMatchObject({
        headers: { 'x-tool': 'Elastic' },
        params: { limit: 2, cursor: undefined },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (relationship not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Resource not found.' } },
        },
      });

      await expect(
        handler(mockContext, { domain: 'example.com', relationship: 'not_a_real_relationship' })
      ).rejects.toThrow('GTI API error (404): Resource not found.');
    });
  });

  describe('getUrlReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getUrlReport.handler;
    const SAMPLE_URL = 'http://www.example.com/path?q=1';
    const SAMPLE_URL_ID = 'aHR0cDovL3d3dy5leGFtcGxlLmNvbS9wYXRoP3E9MQ';

    it('rejects a malformed URL at the schema level, before the handler runs', () => {
      const result = GetUrlReportInputSchema.safeParse({ url: 'not-a-url' });
      expect(result.success).toBe(false);
    });

    it('accepts a valid https URL', () => {
      expect(GetUrlReportInputSchema.safeParse({ url: 'https://example.com/path' }).success).toBe(
        true
      );
    });

    it('rejects a URL longer than 2048 characters at the schema level', () => {
      const overlong = `https://example.com/${'a'.repeat(2048)}`;
      const result = GetUrlReportInputSchema.safeParse({ url: overlong });
      expect(result.success).toBe(false);
    });

    it('accepts a non-http(s) URL scheme, e.g. ftp', () => {
      expect(GetUrlReportInputSchema.safeParse({ url: 'ftp://example.com/file' }).success).toBe(
        true
      );
    });

    it('derives the GTI URL identifier (base64url of the URL, no padding) and calls the urls endpoint', async () => {
      const apiResponse = {
        data: {
          id: SAMPLE_URL_ID,
          type: 'url',
          attributes: {
            url: SAMPLE_URL,
            gti_assessment: { verdict: { value: 'VERDICT_UNDETECTED' } },
          },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { url: SAMPLE_URL });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(`https://www.virustotal.com/api/v3/urls/${SAMPLE_URL_ID}`);
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (URL unknown to GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'URL not found' } },
        },
      });

      await expect(handler(mockContext, { url: SAMPLE_URL })).rejects.toThrow(
        'GTI API error (404): URL not found'
      );
    });
  });

  describe('getUrlRelationship', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getUrlRelationship.handler;
    const SAMPLE_URL = 'http://www.example.com/path?q=1';
    const SAMPLE_URL_ID = 'aHR0cDovL3d3dy5leGFtcGxlLmNvbS9wYXRoP3E9MQ';

    it('rejects a malformed URL at the schema level, before the handler runs', () => {
      const result = GetUrlRelationshipInputSchema.safeParse({
        url: 'not-a-url',
        relationship: 'downloaded_files',
      });
      expect(result.success).toBe(false);
    });

    it('rejects an empty relationship string at the schema level, before the handler runs', () => {
      const result = GetUrlRelationshipInputSchema.safeParse({
        url: 'https://example.com/path',
        relationship: '',
      });
      expect(result.success).toBe(false);
    });

    it('accepts a couple of representative relationship values', () => {
      expect(
        GetUrlRelationshipInputSchema.safeParse({
          url: 'https://example.com/path',
          relationship: 'downloaded_files',
        }).success
      ).toBe(true);
      expect(
        GetUrlRelationshipInputSchema.safeParse({
          url: 'https://example.com/path',
          relationship: 'redirects_to',
        }).success
      ).toBe(true);
    });

    it('rejects a limit above 40 at the schema level', () => {
      const result = GetUrlRelationshipInputSchema.safeParse({
        url: 'https://example.com/path',
        relationship: 'downloaded_files',
        limit: 41,
      });
      expect(result.success).toBe(false);
    });

    it('accepts limit at its boundary values (0 and 40)', () => {
      expect(
        GetUrlRelationshipInputSchema.safeParse({
          url: 'https://example.com/path',
          relationship: 'downloaded_files',
          limit: 0,
        }).success
      ).toBe(true);
      expect(
        GetUrlRelationshipInputSchema.safeParse({
          url: 'https://example.com/path',
          relationship: 'downloaded_files',
          limit: 40,
        }).success
      ).toBe(true);
    });

    it('calls the relationship endpoint with the derived URL identifier, passes limit/cursor through, and returns the response as-is', async () => {
      const apiResponse = {
        data: [
          {
            id: '064ab5414e3e6d48d40937ecf2d3178f67817ccfc221c801ff7602af96635c18',
            type: 'file',
            attributes: { meaningful_name: 'sample.exe' },
          },
        ],
        meta: { count: 57, cursor: 'opaque-cursor' },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, {
        url: SAMPLE_URL,
        relationship: 'downloaded_files',
        limit: 2,
      });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/urls/${SAMPLE_URL_ID}/downloaded_files`
      );
      expect(call[1]).toMatchObject({
        headers: { 'x-tool': 'Elastic' },
        params: { limit: 2, cursor: undefined },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (relationship not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Resource not found.' } },
        },
      });

      await expect(
        handler(mockContext, {
          url: SAMPLE_URL,
          relationship: 'not_a_real_relationship',
        })
      ).rejects.toThrow('GTI API error (404): Resource not found.');
    });
  });

  describe('getFileReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getFileReport.handler;

    it('rejects a malformed hash at the schema level, before the handler runs', () => {
      const result = GetFileReportInputSchema.safeParse({ fileHash: 'test' });
      expect(result.success).toBe(false);
    });

    it('calls the files endpoint with the hash and x-tool header, and returns the report as-is', async () => {
      const apiResponse = {
        data: {
          id: SHA256_HASH,
          type: 'file',
          attributes: {
            meaningful_name: 'sample.exe',
            type_description: 'Win32 EXE',
            popular_threat_classification: { suggested_threat_label: 'trojan.cert/example' },
            gti_assessment: { verdict: { value: 'VERDICT_MALICIOUS' } },
          },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { fileHash: SHA256_HASH });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(`https://www.virustotal.com/api/v3/files/${SHA256_HASH}`);
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (hash unknown to GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: `File "${SHA256_HASH}" not found` } },
        },
      });

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow(
        `GTI API error (404): File "${SHA256_HASH}" not found`
      );
    });
  });

  describe('getFileRelationship', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getFileRelationship.handler;

    it('rejects a malformed hash at the schema level, before the handler runs', () => {
      const result = GetFileRelationshipInputSchema.safeParse({
        fileHash: 'test',
        relationship: 'dropped_files',
      });
      expect(result.success).toBe(false);
    });

    it('rejects an empty relationship string at the schema level, before the handler runs', () => {
      const result = GetFileRelationshipInputSchema.safeParse({
        fileHash: SHA256_HASH,
        relationship: '',
      });
      expect(result.success).toBe(false);
    });

    it('accepts a couple of representative relationship values', () => {
      expect(
        GetFileRelationshipInputSchema.safeParse({
          fileHash: SHA256_HASH,
          relationship: 'contacted_domains',
        }).success
      ).toBe(true);
      expect(
        GetFileRelationshipInputSchema.safeParse({
          fileHash: SHA256_HASH,
          relationship: 'similar_files',
        }).success
      ).toBe(true);
    });

    it('rejects a limit above 40 at the schema level', () => {
      const result = GetFileRelationshipInputSchema.safeParse({
        fileHash: SHA256_HASH,
        relationship: 'dropped_files',
        limit: 41,
      });
      expect(result.success).toBe(false);
    });

    it('accepts limit at its boundary values (0 and 40)', () => {
      expect(
        GetFileRelationshipInputSchema.safeParse({
          fileHash: SHA256_HASH,
          relationship: 'dropped_files',
          limit: 0,
        }).success
      ).toBe(true);
      expect(
        GetFileRelationshipInputSchema.safeParse({
          fileHash: SHA256_HASH,
          relationship: 'dropped_files',
          limit: 40,
        }).success
      ).toBe(true);
    });

    it('calls the relationship endpoint with both segments encoded, passes limit/cursor through, and returns the response as-is', async () => {
      const apiResponse = {
        data: [
          {
            id: 'config.pchelper.ai',
            type: 'domain',
            attributes: { reputation: 0, tld: 'ai' },
          },
        ],
        meta: { count: 5, cursor: 'opaque-cursor' },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, {
        fileHash: SHA256_HASH,
        relationship: 'contacted_domains',
        limit: 2,
      });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/files/${SHA256_HASH}/contacted_domains`
      );
      expect(call[1]).toMatchObject({
        headers: { 'x-tool': 'Elastic' },
        params: { limit: 2, cursor: undefined },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (relationship not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Resource not found.' } },
        },
      });

      await expect(
        handler(mockContext, { fileHash: SHA256_HASH, relationship: 'not_a_real_relationship' })
      ).rejects.toThrow('GTI API error (404): Resource not found.');
    });
  });

  describe('scanUrl', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.scanUrl.handler;

    it('rejects a malformed URL at the schema level, before the handler runs', () => {
      const result = ScanUrlInputSchema.safeParse({ url: 'not-a-url' });
      expect(result.success).toBe(false);
    });

    it('submits the URL as a form-urlencoded body and returns the analysis id as-is', async () => {
      const apiResponse = { data: { type: 'analysis', id: 'u-abc123' } };
      mockClient.post.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { url: 'https://example.com/' });

      const call = mockClient.post.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/urls');
      expect(call[1]).toBeInstanceOf(URLSearchParams);
      expect((call[1] as URLSearchParams).get('url')).toBe('https://example.com/');
      expect(call[2]).toMatchObject({
        headers: { 'x-tool': 'Elastic', 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on API/network failure (see "GTI API error handling" below)', async () => {
      mockClient.post.mockRejectedValue({
        response: { status: 400, data: { error: { code: 'BadRequestError' } } },
      });

      await expect(handler(mockContext, { url: 'https://example.com/' })).rejects.toThrow(
        'GTI API error (400): BadRequestError'
      );
    });
  });

  describe('getAnalysis', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getAnalysis.handler;

    it('rejects an analysis id above the length bound at the schema level', () => {
      const result = GetAnalysisInputSchema.safeParse({ analysisId: 'a'.repeat(513) });
      expect(result.success).toBe(false);
    });

    it('calls the analyses endpoint with the id and x-tool header, and returns the response as-is', async () => {
      const apiResponse = {
        data: {
          type: 'url_analysis',
          id: 'u-abc123',
          attributes: { status: 'completed', stats: { malicious: 0 } },
        },
        meta: { url_info: { id: 'the-url-id', url: 'https://example.com/' } },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { analysisId: 'u-abc123' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/analyses/u-abc123');
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (analysis id not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Analysis "u-abc123" not found' } },
        },
      });

      await expect(handler(mockContext, { analysisId: 'u-abc123' })).rejects.toThrow(
        'GTI API error (404): Analysis "u-abc123" not found'
      );
    });
  });

  describe('getUrlScanReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getUrlScanReport.handler;

    it('rejects a URL id above the length bound at the schema level', () => {
      const result = GetUrlScanReportInputSchema.safeParse({ urlId: 'a'.repeat(513) });
      expect(result.success).toBe(false);
    });

    it('calls the URL report endpoint with the id, encoded, and returns the response as-is', async () => {
      const apiResponse = {
        data: {
          type: 'url',
          id: 'the/url+id',
          attributes: { url: 'https://example.com/', last_analysis_stats: { malicious: 0 } },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { urlId: 'the/url+id' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/urls/${encodeURIComponent('the/url+id')}`
      );
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (URL id not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'URL "the-url-id" not found' } },
        },
      });

      await expect(handler(mockContext, { urlId: 'the-url-id' })).rejects.toThrow(
        'GTI API error (404): URL "the-url-id" not found'
      );
    });
  });

  describe('scanPrivateUrl', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.scanPrivateUrl.handler;

    it('rejects a malformed URL at the schema level, before the handler runs', () => {
      const result = ScanPrivateUrlInputSchema.safeParse({ url: 'not-a-url' });
      expect(result.success).toBe(false);
    });

    it('rejects a retentionPeriodDays outside 1-28 at the schema level', () => {
      expect(
        ScanPrivateUrlInputSchema.safeParse({
          url: 'https://example.com/',
          retentionPeriodDays: 0,
        }).success
      ).toBe(false);
      expect(
        ScanPrivateUrlInputSchema.safeParse({
          url: 'https://example.com/',
          retentionPeriodDays: 29,
        }).success
      ).toBe(false);
    });

    it('rejects an interactionTimeout outside 60-1800 at the schema level', () => {
      expect(
        ScanPrivateUrlInputSchema.safeParse({
          url: 'https://example.com/',
          interactionTimeout: 59,
        }).success
      ).toBe(false);
      expect(
        ScanPrivateUrlInputSchema.safeParse({
          url: 'https://example.com/',
          interactionTimeout: 1801,
        }).success
      ).toBe(false);
    });

    it('submits only the url when no optional parameters are supplied', async () => {
      mockClient.post.mockResolvedValue({
        data: { data: { type: 'private_analysis', id: 'private-id' } },
      });

      await handler(mockContext, { url: 'https://example.com/' });

      const call = mockClient.post.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/private/urls');
      expect(Array.from((call[1] as URLSearchParams).keys())).toEqual(['url']);
    });

    it('submits every optional parameter as a form-urlencoded body, returning the analysis id as-is', async () => {
      const apiResponse = { data: { type: 'private_analysis', id: 'private-id' } };
      mockClient.post.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, {
        url: 'https://example.com/',
        userAgent: 'custom-agent/1.0',
        sandboxes: 'chrome_headless_linux,cape_win',
        retentionPeriodDays: 7,
        storageRegion: 'EU',
        interactionSandbox: 'cape_win',
        interactionTimeout: 120,
      });

      const call = mockClient.post.mock.calls[0];
      expect(call[1]).toBeInstanceOf(URLSearchParams);
      const body = call[1] as URLSearchParams;
      expect(body.get('url')).toBe('https://example.com/');
      expect(body.get('user_agent')).toBe('custom-agent/1.0');
      expect(body.get('sandboxes')).toBe('chrome_headless_linux,cape_win');
      expect(body.get('retention_period_days')).toBe('7');
      expect(body.get('storage_region')).toBe('EU');
      expect(body.get('interaction_sandbox')).toBe('cape_win');
      expect(body.get('interaction_timeout')).toBe('120');
      expect(call[2]).toMatchObject({
        headers: { 'x-tool': 'Elastic', 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      expect(result).toEqual(apiResponse);
    });

    it('throws on API/network failure (see "GTI API error handling" below)', async () => {
      mockClient.post.mockRejectedValue({
        response: { status: 400, data: { error: { code: 'BadRequestError' } } },
      });

      await expect(handler(mockContext, { url: 'https://example.com/' })).rejects.toThrow(
        'GTI API error (400): BadRequestError'
      );
    });
  });

  describe('getPrivateAnalysis', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getPrivateAnalysis.handler;

    it('rejects an analysis id above the length bound at the schema level', () => {
      const result = GetPrivateAnalysisInputSchema.safeParse({ analysisId: 'a'.repeat(513) });
      expect(result.success).toBe(false);
    });

    it('calls the private analyses endpoint with the id and x-tool header, and returns the response as-is', async () => {
      const apiResponse = {
        data: {
          type: 'private_analysis',
          id: 'private-id',
          attributes: { status: 'completed' },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { analysisId: 'private-id' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe('https://www.virustotal.com/api/v3/private/analyses/private-id');
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (analysis id not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'Analysis "private-id" not found' } },
        },
      });

      await expect(handler(mockContext, { analysisId: 'private-id' })).rejects.toThrow(
        'GTI API error (404): Analysis "private-id" not found'
      );
    });
  });

  describe('getPrivateUrlReport', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getPrivateUrlReport.handler;

    it('rejects a URL id above the length bound at the schema level', () => {
      const result = GetPrivateUrlReportInputSchema.safeParse({ urlId: 'a'.repeat(513) });
      expect(result.success).toBe(false);
    });

    it('calls the private URL report endpoint with the id, encoded, and returns the response as-is', async () => {
      const apiResponse = {
        data: {
          type: 'private_url',
          id: 'the/url+id',
          attributes: { url: 'https://example.com/', private: true },
        },
      };
      mockClient.get.mockResolvedValue({ data: apiResponse });

      const result = await handler(mockContext, { urlId: 'the/url+id' });

      const call = mockClient.get.mock.calls[0];
      expect(call[0]).toBe(
        `https://www.virustotal.com/api/v3/private/urls/${encodeURIComponent('the/url+id')}`
      );
      expect(call[1]).toMatchObject({ headers: { 'x-tool': 'Elastic' } });
      expect(result).toEqual(apiResponse);
    });

    it('throws on a 404 (URL id not recognized by GTI), matching the real API error shape', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: { code: 'NotFoundError', message: 'URL "private-url-id" not found' } },
        },
      });

      await expect(handler(mockContext, { urlId: 'private-url-id' })).rejects.toThrow(
        'GTI API error (404): URL "private-url-id" not found'
      );
    });
  });

  describe('GTI API error handling', () => {
    const handler = GoogleThreatIntelligenceConnector.actions.getFileBehaviours.handler;

    it('throws an enriched GTI error when the API returns an error envelope', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 401,
          data: { error: { code: 'WrongCredentialsError', message: 'Wrong API key' } },
        },
      });

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow(
        'GTI API error (401): Wrong API key'
      );
    });

    it('falls back to the error code when the envelope has no message', async () => {
      mockClient.get.mockRejectedValue({
        response: { status: 400, data: { error: { code: 'BadRequestError' } } },
      });

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow(
        'GTI API error (400): BadRequestError'
      );
    });

    it('rethrows the original error when the response body is not GTI-shaped, e.g. a bare network error', async () => {
      mockClient.get.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(handler(mockContext, { fileHash: SHA256_HASH })).rejects.toThrow('ECONNREFUSED');
    });
  });
});
