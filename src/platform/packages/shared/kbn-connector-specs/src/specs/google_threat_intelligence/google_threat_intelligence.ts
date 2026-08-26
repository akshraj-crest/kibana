/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { i18n } from '@kbn/i18n';
import type { ConnectorSpec } from '../../connector_spec';
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
import type {
  GetFileBehavioursInput,
  GetFileMitreAttackTechniquesInput,
  GetIpReportInput,
  GetIpRelationshipInput,
  GetDomainReportInput,
  GetDomainRelationshipInput,
  GetUrlReportInput,
  GetUrlRelationshipInput,
  GetFileReportInput,
  GetFileRelationshipInput,
  ScanUrlInput,
  GetAnalysisInput,
  GetUrlScanReportInput,
  ScanPrivateUrlInput,
  GetPrivateAnalysisInput,
  GetPrivateUrlReportInput,
} from './types';

const GTI_API_BASE_URL = 'https://www.virustotal.com';
const GTI_HEADERS = { 'x-tool': 'Elastic' };

interface GtiErrorResponse {
  response?: {
    status?: number;
    data?: {
      error?: {
        code?: string;
        message?: string;
      };
    };
  };
}

interface GtiIpReportResponse {
  data?: {
    attributes?: {
      gti_assessment?: unknown;
    };
  };
}

function throwGtiError(error: unknown): void {
  const { response } = error as GtiErrorResponse;
  const { code, message } = response?.data?.error ?? {};
  const detail = message ?? code;
  if (!detail) return;
  throw new Error(`GTI API error (${response?.status ?? 'unknown'}): ${detail}`);
}

function toGtiUrlId(url: string): string {
  return Buffer.from(url, 'utf-8').toString('base64url');
}

export const GoogleThreatIntelligenceConnector: ConnectorSpec = {
  metadata: {
    id: '.google_threat_intelligence',
    displayName: 'Google Threat Intelligence',
    description: i18n.translate('connectorSpecs.googleThreatIntelligence.metadata.description', {
      defaultMessage:
        'Get file sandbox behaviour, MITRE ATT&CK, and IOC reputation and relationship data for ' +
        'IP addresses, domains, URLs, and files from Google Threat Intelligence, and submit ' +
        'URLs for public or private scanning',
    }),
    minimumLicense: 'enterprise',
    supportedFeatureIds: ['workflows', 'agentBuilder'],
  },

  auth: {
    types: [
      {
        type: 'api_key_header',
        defaults: { headerField: 'x-apikey' },
        overrides: { meta: { 'x-apikey': { placeholder: 'gti-...' } } },
      },
    ],
  },

  actions: {
    getFileBehaviours: {
      isTool: true,
      description:
        'Get sandbox detonation reports for a file by hash (SHA-256, SHA-1, or MD5). Each report ' +
        'covers one sandbox run: process tree, files, registry keys and network activity it touched, ' +
        'plus the verdict. Returns up to 10 reports by default; use limit and cursor to page through ' +
        'more. Returns an empty collection when the hash is known to GTI but has not been sandboxed. ' +
        'Throws when GTI has no record of the hash at all.',
      input: GetFileBehavioursInputSchema,
      handler: async (ctx, input: GetFileBehavioursInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/files/${encodeURIComponent(input.fileHash)}/behaviours`,
            { headers: GTI_HEADERS, params: { limit: input.limit, cursor: input.cursor } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getFileMitreAttackTechniques: {
      isTool: true,
      description:
        'Get the MITRE ATT&CK tactics and techniques observed for a file by hash (SHA-256, SHA-1, or ' +
        'MD5), grouped by the sandbox that observed them. Each technique lists the signatures that ' +
        'triggered it and their severity. Throws when GTI has no record of the hash at all.',
      input: GetFileMitreAttackTechniquesInputSchema,
      handler: async (ctx, input: GetFileMitreAttackTechniquesInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/files/${encodeURIComponent(
              input.fileHash
            )}/behaviour_mitre_trees`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getIpReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for an IP address (IPv4 ' +
        'or IPv6). Returns the GTI assessment (verdict, threat score, severity), last analysis ' +
        'statistics, network ownership and geolocation where available, WHOIS data, and any tags GTI ' +
        'has applied. Has not been observed to fail for a well-formed IP address, even one with no ' +
        'real internet presence such as a private or reserved address; throws when the IP address ' +
        'itself is malformed.',
      input: GetIpReportInputSchema,
      handler: async (ctx, input: GetIpReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/ip_addresses/${encodeURIComponent(input.ipAddress)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getIpRelationship: {
      isTool: true,
      description:
        'Get objects related to an IP address (IPv4 or IPv6) by relationship type, for example files ' +
        'that communicate with it, URLs hosted on it, or its historical DNS resolutions. See the ' +
        '`relationship` parameter for examples and where to find the full current list. Returns up ' +
        'to 10 related objects by default; use limit and cursor to page through more. Throws when ' +
        'the relationship type is not one GTI currently recognizes for IP objects.',
      input: GetIpRelationshipInputSchema,
      handler: async (ctx, input: GetIpRelationshipInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/ip_addresses/${encodeURIComponent(
              input.ipAddress
            )}/${encodeURIComponent(input.relationship)}`,
            { headers: GTI_HEADERS, params: { limit: input.limit, cursor: input.cursor } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getDomainReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for a domain name. ' +
        'Returns the GTI assessment (verdict, threat score, severity), last analysis statistics, ' +
        'categorisation, WHOIS data, and any tags GTI has applied. Throws when GTI has no record ' +
        'of the domain at all.',
      input: GetDomainReportInputSchema,
      handler: async (ctx, input: GetDomainReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/domains/${encodeURIComponent(input.domain)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getDomainRelationship: {
      isTool: true,
      description:
        'Get objects related to a domain name by relationship type, for example its DNS ' +
        'resolutions, subdomains, or the files that communicate with it. See the `relationship` ' +
        'parameter for examples and where to find the full current list. Returns up to 10 related ' +
        'objects by default; use limit and cursor to page through more.',
      input: GetDomainRelationshipInputSchema,
      handler: async (ctx, input: GetDomainRelationshipInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/domains/${encodeURIComponent(
              input.domain
            )}/${encodeURIComponent(input.relationship)}`,
            { headers: GTI_HEADERS, params: { limit: input.limit, cursor: input.cursor } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getUrlReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for a URL. Returns ' +
        'the GTI assessment (verdict, threat score, severity), last analysis statistics, ' +
        'categorisation, and the final resolved destination after any redirects. Supply the URL ' +
        'in its natural form; the action derives the identifier GTI uses internally. Throws when ' +
        'GTI has no record of the URL at all.',
      input: GetUrlReportInputSchema,
      handler: async (ctx, input: GetUrlReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/urls/${toGtiUrlId(input.url)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getUrlRelationship: {
      isTool: true,
      description:
        'Get objects related to a URL by relationship type, for example the files downloaded ' +
        'from it, the domains and IP addresses it contacts, or the URLs it redirects to. See the ' +
        '`relationship` parameter for examples and where to find the full current list. Returns ' +
        'up to 10 related objects by default; use limit and cursor to page through more. Supply ' +
        'the URL in its natural form, the same as for `getUrlReport`.',
      input: GetUrlRelationshipInputSchema,
      handler: async (ctx, input: GetUrlRelationshipInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/urls/${toGtiUrlId(input.url)}/${encodeURIComponent(
              input.relationship
            )}`,
            { headers: GTI_HEADERS, params: { limit: input.limit, cursor: input.cursor } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getFileReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for a file by hash ' +
        '(SHA-256, SHA-1, or MD5). Returns the GTI assessment (verdict, threat score, severity), ' +
        'last analysis statistics, file type metadata, and popular threat classification. This is ' +
        'a different action from `getFileBehaviours`, which returns sandbox detonation reports ' +
        'rather than the reputation report. Throws when GTI has no record of the hash at all.',
      input: GetFileReportInputSchema,
      handler: async (ctx, input: GetFileReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/files/${encodeURIComponent(input.fileHash)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getFileRelationship: {
      isTool: true,
      description:
        'Get objects related to a file by hash (SHA-256, SHA-1, or MD5) by relationship type, ' +
        'for example the domains and IP addresses contacted during detonation, dropped files, or ' +
        'similar files. See the `relationship` parameter for examples and where to find the full ' +
        'current list. Returns up to 10 related objects by default; use limit and cursor to page ' +
        'through more.',
      input: GetFileRelationshipInputSchema,
      handler: async (ctx, input: GetFileRelationshipInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/files/${encodeURIComponent(
              input.fileHash
            )}/${encodeURIComponent(input.relationship)}`,
            { headers: GTI_HEADERS, params: { limit: input.limit, cursor: input.cursor } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    scanUrl: {
      isTool: true,
      description:
        'Submit a URL to Google Threat Intelligence for a fresh public analysis. Returns an ' +
        'analysis identifier; pass it to `getAnalysis` to poll for completion, then to ' +
        '`getUrlScanReport` to retrieve the full report once the analysis finishes. Supply the ' +
        'URL in its natural form, the same as for `getUrlReport`.',
      input: ScanUrlInputSchema,
      handler: async (ctx, input: ScanUrlInput) => {
        try {
          const response = await ctx.client.post(
            `${GTI_API_BASE_URL}/api/v3/urls`,
            new URLSearchParams({ url: input.url }),
            { headers: { ...GTI_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getAnalysis: {
      isTool: true,
      description:
        'Get the status and statistics of a public URL analysis submitted by `scanUrl`. The ' +
        'response also carries the URL identifier, at `meta.url_info.id`, needed by ' +
        '`getUrlScanReport` once the analysis reaches a completed state.',
      input: GetAnalysisInputSchema,
      handler: async (ctx, input: GetAnalysisInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/analyses/${encodeURIComponent(input.analysisId)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getUrlScanReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for a URL that was ' +
        'submitted through `scanUrl`, using the URL identifier from `getAnalysis` rather than ' +
        'the URL itself. Wraps the same endpoint as `getUrlReport`, kept as a separate action ' +
        'because its input is an identifier, not a URL to derive one from.',
      input: GetUrlScanReportInputSchema,
      handler: async (ctx, input: GetUrlScanReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/urls/${encodeURIComponent(input.urlId)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    scanPrivateUrl: {
      isTool: true,
      description:
        'Submit a URL to Google Threat Intelligence for a private analysis. Behaves like ' +
        '`scanUrl` but neither the submitted URL nor the resulting analysis is shared with the ' +
        'wider Google Threat Intelligence community. Returns an analysis identifier; pass it to ' +
        '`getPrivateAnalysis` to poll for completion, then to `getPrivateUrlReport` to retrieve ' +
        'the full report once the analysis finishes.',
      input: ScanPrivateUrlInputSchema,
      handler: async (ctx, input: ScanPrivateUrlInput) => {
        try {
          const body: Record<string, string> = { url: input.url };
          if (input.userAgent !== undefined) body.user_agent = input.userAgent;
          if (input.sandboxes !== undefined) body.sandboxes = input.sandboxes;
          if (input.retentionPeriodDays !== undefined) {
            body.retention_period_days = String(input.retentionPeriodDays);
          }
          if (input.storageRegion !== undefined) body.storage_region = input.storageRegion;
          if (input.interactionSandbox !== undefined) {
            body.interaction_sandbox = input.interactionSandbox;
          }
          if (input.interactionTimeout !== undefined) {
            body.interaction_timeout = String(input.interactionTimeout);
          }
          const response = await ctx.client.post(
            `${GTI_API_BASE_URL}/api/v3/private/urls`,
            new URLSearchParams(body),
            { headers: { ...GTI_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' } }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getPrivateAnalysis: {
      isTool: true,
      description:
        'Get the status and statistics of a private URL analysis submitted by ' +
        '`scanPrivateUrl`. Once the analysis reaches a completed state, retrieve the full ' +
        'report with `getPrivateUrlReport`.',
      input: GetPrivateAnalysisInputSchema,
      handler: async (ctx, input: GetPrivateAnalysisInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/private/analyses/${encodeURIComponent(input.analysisId)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },

    getPrivateUrlReport: {
      isTool: true,
      description:
        'Get the Google Threat Intelligence reputation and detection report for a URL that was ' +
        'submitted through `scanPrivateUrl`, using the URL identifier from `getPrivateAnalysis` ' +
        'rather than the URL itself.',
      input: GetPrivateUrlReportInputSchema,
      handler: async (ctx, input: GetPrivateUrlReportInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/private/urls/${encodeURIComponent(input.urlId)}`,
            { headers: GTI_HEADERS }
          );
          return response.data;
        } catch (error: unknown) {
          throwGtiError(error);
          throw error;
        }
      },
    },
  },

  skill: [
    '## Google Threat Intelligence connector',
    '',
    '## File sandbox behaviour',
    '- `getFileBehaviours` supports paging: pass `limit` (0-40, defaults to 10) to bound the response ' +
      'size, and pass the `cursor` from a previous response to fetch the next page.',
    '',
    '## MITRE ATT&CK techniques',
    '- `getFileMitreAttackTechniques` groups tactics, techniques, and signatures by sandbox name, not ' +
      'as a flat list. The same file can show a different ATT&CK tree per sandbox it was detonated in.',
    '',
    '## IP address report',
    '- `getIpReport` returns the full GTI report object as-is; there is no compact or pruned variant. ' +
      'Use `getIpRelationship` to traverse related objects such as communicating files or hosted URLs.',
    '',
    '## IP address relationships',
    '- `getIpRelationship` supports the same limit/cursor paging as `getFileBehaviours`.',
    '',
    '## Domain report',
    '- `getDomainReport` returns the full GTI domain report object as-is; there is no compact or ' +
      'pruned variant. Use `getDomainRelationship` to traverse related objects such as ' +
      'resolutions or subdomains.',
    '',
    '## Domain relationships',
    '- `getDomainRelationship` supports the same limit/cursor paging as `getIpRelationship`.',
    '',
    '## URL report',
    '- `getUrlReport` derives the URL identifier GTI uses internally from the URL you supply; ' +
      'pass the URL in its natural form, not a pre-encoded identifier.',
    '',
    '## URL relationships',
    '- `getUrlRelationship` takes the same URL and derives the identifier the same way as ' +
      '`getUrlReport`. It supports the same limit/cursor paging as `getIpRelationship`.',
    '',
    '## File report',
    '- `getFileReport` returns the full GTI file reputation report object as-is, the same shape ' +
      'as `getIpReport`/`getDomainReport`/`getUrlReport`. It is a different action from ' +
      '`getFileBehaviours`, which returns sandbox detonation reports rather than the reputation ' +
      'report.',
    '',
    '## File relationships',
    '- `getFileRelationship` supports the same limit/cursor paging as `getIpRelationship`.',
    '',
    '## Scan URL',
    '- `scanUrl` submits a URL for public analysis and returns an analysis identifier. Pass ' +
      'it to `getAnalysis` to poll for completion, then to `getUrlScanReport` to retrieve the ' +
      'full report.',
    '',
    '## Get analysis',
    '- `getAnalysis` polls a public analysis identifier from `scanUrl` until its status is ' +
      'completed. The response also carries the URL identifier, at `meta.url_info.id`, ' +
      'needed by `getUrlScanReport`. Re-invoke `getAnalysis` at an interval until the ' +
      'analysis completes; this connector does not poll on its own.',
    '',
    '## Get URL scan report',
    '- `getUrlScanReport` retrieves the full report for a URL submitted through `scanUrl`, ' +
      'using the identifier from `getAnalysis` rather than the URL itself.',
    '',
    '## Scan private URL',
    '- `scanPrivateUrl` behaves like `scanUrl`, but neither the submitted URL nor the ' +
      'resulting analysis is shared with the wider Google Threat Intelligence community. ' +
      'Accepts optional sandbox selection, retention period, storage region, and ' +
      'interactive-analysis parameters.',
    '',
    '## Get private analysis',
    '- `getPrivateAnalysis` polls a private analysis identifier from `scanPrivateUrl` the ' +
      'same way `getAnalysis` polls a public one, including the same `meta.url_info.id` ' +
      'field for the next step.',
    '',
    '## Get private URL report',
    '- `getPrivateUrlReport` retrieves the full report for a URL submitted through ' +
      '`scanPrivateUrl`, using the identifier from `getPrivateAnalysis` rather than the URL ' +
      'itself.',
  ].join('\n'),

  test: {
    enabled: true,
    description: i18n.translate('connectorSpecs.googleThreatIntelligence.test.description', {
      defaultMessage:
        'Verifies the API key and confirms your Google Threat Intelligence subscription tier',
    }),
    handler: async (ctx) => {
      try {
        const response = await ctx.client.get<GtiIpReportResponse>(
          `${GTI_API_BASE_URL}/api/v3/ip_addresses/8.8.8.8`,
          { headers: GTI_HEADERS }
        );
        const hasGtiAssessment = Boolean(response.data?.data?.attributes?.gti_assessment);
        if (!hasGtiAssessment) {
          throw new Error(
            'Your Google Threat Intelligence API Key does not have an Enterprise subscription. Verify your GTI subscription tier.'
          );
        }
        return {};
      } catch (error: unknown) {
        throwGtiError(error);
        throw error;
      }
    },
  },
};
