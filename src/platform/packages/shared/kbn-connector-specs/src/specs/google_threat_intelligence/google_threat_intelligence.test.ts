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

describe('GoogleThreatIntelligenceConnector', () => {
  const mockClient = {
    get: jest.fn(),
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

    it('throws on a network/API failure with no response envelope', async () => {
      mockClient.get.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(GoogleThreatIntelligenceConnector.test.handler(mockContext)).rejects.toThrow(
        'ECONNREFUSED'
      );
    });

    it('throws an enriched GTI error when the API returns an error envelope', async () => {
      mockClient.get.mockRejectedValue({
        response: {
          status: 401,
          data: { error: { code: 'WrongCredentialsError', message: 'Wrong API key' } },
        },
      });

      await expect(GoogleThreatIntelligenceConnector.test.handler(mockContext)).rejects.toThrow(
        'GTI API error (401): Wrong API key'
      );
    });

    it('falls back to the error code when the envelope has no message', async () => {
      mockClient.get.mockRejectedValue({
        response: { status: 400, data: { error: { code: 'BadRequestError' } } },
      });

      await expect(GoogleThreatIntelligenceConnector.test.handler(mockContext)).rejects.toThrow(
        'GTI API error (400): BadRequestError'
      );
    });
  });
});
