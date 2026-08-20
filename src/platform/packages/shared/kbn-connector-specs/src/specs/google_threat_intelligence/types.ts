/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { z, lazySchema } from '@kbn/zod/v4';

const FILE_HASH_RE = /^([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})$/;

export const FILE_HASH_SCHEMA = z
  .string()
  .regex(FILE_HASH_RE, {
    message:
      'Must be a SHA-256 (64 hex chars), SHA-1 (40 hex chars), or MD5 (32 hex chars) file hash',
  })
  .describe(
    'SHA-256, SHA-1, or MD5 hash identifying the file, e.g. a 64-character SHA-256 hex string'
  );

export const GetFileBehavioursInputSchema = lazySchema(() =>
  z.object({
    fileHash: FILE_HASH_SCHEMA,
    limit: z
      .number()
      .int()
      .min(0)
      .max(40)
      .optional()
      .describe(
        'Maximum number of behaviour reports to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.'
      ),
    cursor: z
      .string()
      .max(2048)
      .optional()
      .describe(
        'Continuation cursor from a previous response, used to retrieve the next page of results.'
      ),
  })
);
export type GetFileBehavioursInput = z.infer<typeof GetFileBehavioursInputSchema>;

export const GetFileMitreAttackTechniquesInputSchema = lazySchema(() =>
  z.object({
    fileHash: FILE_HASH_SCHEMA,
  })
);
export type GetFileMitreAttackTechniquesInput = z.infer<
  typeof GetFileMitreAttackTechniquesInputSchema
>;

export const IP_ADDRESS_SCHEMA = z
  .union([z.ipv4(), z.ipv6()])
  .describe('IPv4 or IPv6 address to look up, e.g. "8.8.8.8" or "2001:4860:4860::8888"');

export const GetIpReportInputSchema = lazySchema(() =>
  z.object({
    ipAddress: IP_ADDRESS_SCHEMA,
  })
);
export type GetIpReportInput = z.infer<typeof GetIpReportInputSchema>;

export const GetIpRelationshipInputSchema = lazySchema(() =>
  z.object({
    ipAddress: IP_ADDRESS_SCHEMA,
    relationship: z
      .string()
      .max(100)
      .describe(
        'Relationship to retrieve for the IP address, e.g. "communicating_files", "resolutions", ' +
          'or "urls". Full current list: ' +
          'https://gtidocs.virustotal.com/reference/ip-object#relationships'
      ),
    limit: z
      .number()
      .int()
      .min(0)
      .max(40)
      .optional()
      .describe(
        'Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.'
      ),
    cursor: z
      .string()
      .max(2048)
      .optional()
      .describe(
        'Continuation cursor from a previous response, used to retrieve the next page of results.'
      ),
  })
);
export type GetIpRelationshipInput = z.infer<typeof GetIpRelationshipInputSchema>;

export const DOMAIN_SCHEMA = z
  .string()
  .regex(z.regexes.domain, { message: 'Must be a valid domain name' })
  .describe('Domain name to look up, e.g. "example.com"');

export const GetDomainReportInputSchema = lazySchema(() =>
  z.object({
    domain: DOMAIN_SCHEMA,
  })
);
export type GetDomainReportInput = z.infer<typeof GetDomainReportInputSchema>;

export const GetDomainRelationshipInputSchema = lazySchema(() =>
  z.object({
    domain: DOMAIN_SCHEMA,
    relationship: z
      .string()
      .max(100)
      .describe(
        'Relationship to retrieve for the domain, e.g. "resolutions", "subdomains", or ' +
          '"communicating_files". Full current list: ' +
          'https://gtidocs.virustotal.com/reference/domains-object#relationships'
      ),
    limit: z
      .number()
      .int()
      .min(0)
      .max(40)
      .optional()
      .describe(
        'Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.'
      ),
    cursor: z
      .string()
      .max(2048)
      .optional()
      .describe(
        'Continuation cursor from a previous response, used to retrieve the next page of results.'
      ),
  })
);
export type GetDomainRelationshipInput = z.infer<typeof GetDomainRelationshipInputSchema>;
