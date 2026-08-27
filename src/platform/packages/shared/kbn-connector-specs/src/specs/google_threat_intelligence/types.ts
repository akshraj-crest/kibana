/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { z, lazySchema } from '@kbn/zod/v4';

const pagingLimitSchema = (noun: string) =>
  z
    .number()
    .int()
    .min(0)
    .max(40)
    .optional()
    .describe(
      `Maximum number of ${noun} to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted; ` +
        `pass 0 to get the total count without retrieving any items.`
    );

const CURSOR_SCHEMA = z
  .string()
  .max(2048)
  .optional()
  .describe(
    'Continuation cursor from a previous response, used to retrieve the next page of results.'
  );

const relationshipSchema = (objectType: string, examples: string, docPath: string) =>
  z
    .string()
    .min(1)
    .max(100)
    .describe(
      `Relationship to retrieve for the ${objectType}, e.g. ${examples}. Full current list: ` +
        `https://gtidocs.virustotal.com/reference/${docPath}#relationships`
    );

const FILE_HASH_RE = /^([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})$/;

export const FILE_HASH_SCHEMA = z
  .string()
  .max(64)
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
    limit: pagingLimitSchema('behavior reports'),
    cursor: CURSOR_SCHEMA,
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
    relationship: relationshipSchema(
      'IP address',
      '"communicating_files", "resolutions", or "urls"',
      'ip-object'
    ),
    limit: pagingLimitSchema('related objects'),
    cursor: CURSOR_SCHEMA,
  })
);
export type GetIpRelationshipInput = z.infer<typeof GetIpRelationshipInputSchema>;

export const DOMAIN_SCHEMA = z
  .string()
  .max(253)
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
    relationship: relationshipSchema(
      'domain',
      '"resolutions", "subdomains", or "communicating_files"',
      'domains-object'
    ),
    limit: pagingLimitSchema('related objects'),
    cursor: CURSOR_SCHEMA,
  })
);
export type GetDomainRelationshipInput = z.infer<typeof GetDomainRelationshipInputSchema>;

export const URL_SCHEMA = z
  .url()
  .max(2048)
  .describe('URL to look up, e.g. "https://example.com/path" or "ftp://example.com/file"');

export const GetUrlReportInputSchema = lazySchema(() =>
  z.object({
    url: URL_SCHEMA,
  })
);
export type GetUrlReportInput = z.infer<typeof GetUrlReportInputSchema>;

export const GetUrlRelationshipInputSchema = lazySchema(() =>
  z.object({
    url: URL_SCHEMA,
    relationship: relationshipSchema(
      'URL',
      '"downloaded_files", "contacted_domains", or "redirects_to"',
      'url-object'
    ),
    limit: pagingLimitSchema('related objects'),
    cursor: CURSOR_SCHEMA,
  })
);
export type GetUrlRelationshipInput = z.infer<typeof GetUrlRelationshipInputSchema>;

export const GetFileReportInputSchema = lazySchema(() =>
  z.object({
    fileHash: FILE_HASH_SCHEMA,
  })
);
export type GetFileReportInput = z.infer<typeof GetFileReportInputSchema>;

export const GetFileRelationshipInputSchema = lazySchema(() =>
  z.object({
    fileHash: FILE_HASH_SCHEMA,
    relationship: relationshipSchema(
      'file',
      '"contacted_domains", "dropped_files", or "similar_files"',
      'file-object'
    ),
    limit: pagingLimitSchema('related objects'),
    cursor: CURSOR_SCHEMA,
  })
);
export type GetFileRelationshipInput = z.infer<typeof GetFileRelationshipInputSchema>;
