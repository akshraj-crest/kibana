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
import { GetFileBehavioursInputSchema } from './types';
import type { GetFileBehavioursInput } from './types';

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

export const GoogleThreatIntelligenceConnector: ConnectorSpec = {
  metadata: {
    id: '.google_threat_intelligence',
    displayName: 'Google Threat Intelligence',
    description: i18n.translate('connectorSpecs.googleThreatIntelligence.metadata.description', {
      defaultMessage: 'Get sandbox detonation reports for a file from Google Threat Intelligence',
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
        'plus the verdict. Returns an empty collection when the hash is known to GTI but has not been ' +
        'sandboxed. Throws when GTI has no record of the hash at all.',
      input: GetFileBehavioursInputSchema,
      handler: async (ctx, input: GetFileBehavioursInput) => {
        try {
          const response = await ctx.client.get(
            `${GTI_API_BASE_URL}/api/v3/files/${encodeURIComponent(input.fileHash)}/behaviours`,
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
    '- This action has no pagination or limit parameter, so a file with many sandbox runs comes back ' +
      'in one response. Large files can hit the connector response-size limit as a result.',
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
