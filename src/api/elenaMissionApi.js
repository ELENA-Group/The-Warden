import { createHash, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { logger } from '../utils/logger.js';
import { ElenaMissionError } from '../services/elenaMissionError.js';

const MAX_BODY_BYTES = '16kb';
const APPROVAL_MAX_AGE_MS = 5 * 60 * 1000;
const APPROVAL_CLOCK_SKEW_MS = 30 * 1000;
const REPLAY_WINDOW_MS = 10 * 60 * 1000;
const MAX_TRACKED_APPROVALS = 10000;
const DISCORD_ID_PATTERN = /^\d{17,20}$/;
const WORKSPACE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_ACTIONS = new Set([
  'moderation.ban',
  'moderation.kick',
  'moderation.timeout',
  'moderation.untimeout',
]);

export function validateElenaApiConfig({ port, token, workspaceId, allowedGuildIds }) {
  if (port == null) {
    return false;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('ELENA_API_PORT must be a valid TCP port.');
  }
  if (Buffer.byteLength(token || '', 'utf8') < 32) {
    throw new Error('ELENA_API_TOKEN must contain at least 32 bytes when ELENA_API_PORT is set.');
  }
  if (!WORKSPACE_ID_PATTERN.test(workspaceId || '')) {
    throw new Error('ELENA_API_WORKSPACE_ID must be configured when ELENA_API_PORT is set.');
  }
  if (!Array.isArray(allowedGuildIds) || allowedGuildIds.length === 0) {
    throw new Error('ELENA_API_ALLOWED_GUILDS must list at least one Discord guild ID when ELENA_API_PORT is set.');
  }
  if (allowedGuildIds.some((guildId) => !DISCORD_ID_PATTERN.test(guildId))) {
    throw new Error('ELENA_API_ALLOWED_GUILDS contains an invalid Discord guild ID.');
  }
  return true;
}

function tokenMatches(providedToken, expectedToken) {
  if (typeof providedToken !== 'string' || !providedToken) {
    return false;
  }
  const providedDigest = createHash('sha256').update(providedToken).digest();
  const expectedDigest = createHash('sha256').update(expectedToken).digest();
  return timingSafeEqual(providedDigest, expectedDigest);
}

function validateRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ElenaMissionError(400, 'invalid_request', 'Request body must be a JSON object.');
  }

  const allowedKeys = [
    'version', 'requestId', 'approval', 'workspaceId', 'guildId', 'actorId',
    'action', 'targetId', 'reason', 'durationMs',
  ];
  if (Object.keys(body).some((key) => !allowedKeys.includes(key))) {
    throw new ElenaMissionError(400, 'invalid_request', 'Request contains unsupported fields.');
  }
  if (body.version !== 1 || !UUID_PATTERN.test(body.requestId || '')) {
    throw new ElenaMissionError(400, 'invalid_request', 'version must be 1 and requestId must be a UUID.');
  }

  const { approval } = body;
  if (
    !approval || typeof approval !== 'object' || Array.isArray(approval)
    || Object.keys(approval).some((key) => ![
      'id', 'authority', 'approvedAt', 'workspaceId', 'guildId', 'actorId', 'action', 'targetId',
      'reason', 'durationMs', 'rationale',
    ].includes(key))
    || !UUID_PATTERN.test(approval.id || '')
    || approval.authority !== 'ELENA'
    || typeof approval.approvedAt !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(approval.approvedAt)
    || !Number.isFinite(Date.parse(approval.approvedAt))
    || approval.workspaceId !== body.workspaceId
    || approval.guildId !== body.guildId
    || approval.actorId !== body.actorId
    || approval.action !== body.action
    || approval.targetId !== body.targetId
    || approval.reason !== body.reason
    || typeof approval.rationale !== 'string'
    || approval.rationale.trim().length < 1
    || approval.rationale.length > 512
  ) {
    throw new ElenaMissionError(400, 'invalid_approval', 'An explicit ELENA approval context is required.');
  }
  if (
    (body.action === 'moderation.timeout' && approval.durationMs !== body.durationMs)
    || (body.action !== 'moderation.timeout' && Object.hasOwn(approval, 'durationMs'))
  ) {
    throw new ElenaMissionError(400, 'invalid_approval', 'ELENA approval must bind the exact timeout duration.');
  }

  const approvedAt = Date.parse(approval.approvedAt);
  const now = Date.now();
  if (approvedAt > now + APPROVAL_CLOCK_SKEW_MS || now - approvedAt > APPROVAL_MAX_AGE_MS) {
    throw new ElenaMissionError(400, 'approval_expired', 'ELENA approval must be no more than five minutes old.');
  }

  for (const field of ['guildId', 'actorId', 'targetId']) {
    if (!DISCORD_ID_PATTERN.test(body[field] || '')) {
      throw new ElenaMissionError(400, 'invalid_request', `Invalid ${field}.`);
    }
    if (!WORKSPACE_ID_PATTERN.test(body.workspaceId || '')) {
      throw new ElenaMissionError(400, 'invalid_request', 'Invalid workspaceId.');
    }
  }
  if (!ALLOWED_ACTIONS.has(body.action)) {
    throw new ElenaMissionError(400, 'unsupported_action', 'Mission action is not allowlisted.');
  }
  if (typeof body.reason !== 'string' || body.reason.trim().length < 1 || body.reason.length > 512) {
    throw new ElenaMissionError(400, 'invalid_request', 'reason must contain 1-512 characters.');
  }
  if (body.action === 'moderation.timeout') {
    if (!Number.isSafeInteger(body.durationMs) || body.durationMs < 1 || body.durationMs > 28 * 24 * 60 * 60 * 1000) {
      throw new ElenaMissionError(400, 'invalid_request', 'durationMs must be between 1ms and 28 days.');
    }
  } else if (Object.hasOwn(body, 'durationMs')) {
    throw new ElenaMissionError(400, 'invalid_request', 'durationMs is only valid for moderation.timeout.');
  }
  if (body.actorId === body.targetId) {
    throw new ElenaMissionError(400, 'invalid_request', 'The actor cannot target themselves.');
  }

  return body;
}

export function createElenaMissionApp({
  token,
  workspaceId,
  allowedGuildIds,
  executeMission,
}) {
  if (Buffer.byteLength(token || '', 'utf8') < 32) {
    throw new Error('ELENA_API_TOKEN must contain at least 32 bytes.');
  }
  if (!WORKSPACE_ID_PATTERN.test(workspaceId || '')) {
    throw new Error('ELENA_API_WORKSPACE_ID must be configured.');
  }
  if (!Array.isArray(allowedGuildIds) || allowedGuildIds.length === 0
    || allowedGuildIds.some((guildId) => !DISCORD_ID_PATTERN.test(guildId))) {
    throw new Error('ELENA_API_ALLOWED_GUILDS must contain valid Discord guild IDs.');
  }
  if (typeof executeMission !== 'function') {
    throw new Error('ELENA mission executor must be a function.');
  }
  const app = express();
  const guildAllowlist = new Set(allowedGuildIds);
  const seenApprovals = new Map();

  app.post(
    '/v1/missions',
    (req, res, next) => {
      const match = /^Bearer ([^\s]+)$/.exec(req.get('authorization') || '');
      if (!match || !tokenMatches(match[1], token)) {
        logger.warn('ELENA mission authentication rejected', { ip: req.ip });
        return res.status(401).json({
          version: 1,
          error: { code: 'unauthorized', message: 'Valid bearer authentication is required.' },
        });
      }
      next();
    },
    express.json({ limit: MAX_BODY_BYTES, strict: true }),
    async (req, res) => {
      let requestId = null;
      let auditContext = {};
      try {
        const body = validateRequest(req.body);
        requestId = body.requestId;
        auditContext = {
          approvalId: body.approval.id,
          workspaceId: body.workspaceId,
          guildId: body.guildId,
          actorId: body.actorId,
          action: body.action,
          targetId: body.targetId,
        };
        if (body.workspaceId !== workspaceId) {
          throw new ElenaMissionError(403, 'workspace_not_allowed', 'ELENA workspace is not bound to this Warden instance.');
        }
        if (!guildAllowlist.has(body.guildId)) {
          throw new ElenaMissionError(403, 'guild_not_allowed', 'Guild is not allowlisted for ELENA missions.');
        }

        const now = Date.now();
        for (const [id, expiresAt] of seenApprovals) {
          if (expiresAt <= now) seenApprovals.delete(id);
        }
        if (seenApprovals.has(body.approval.id) || seenApprovals.has(body.requestId)) {
          throw new ElenaMissionError(409, 'replayed_approval', 'This approval or request has already been used.');
        }
        if (seenApprovals.size + 2 > MAX_TRACKED_APPROVALS) {
          throw new ElenaMissionError(503, 'approval_capacity_reached', 'Mission approval capacity is temporarily full.');
        }
        seenApprovals.set(body.approval.id, now + REPLAY_WINDOW_MS);
        seenApprovals.set(body.requestId, now + REPLAY_WINDOW_MS);

        const mission = {
          workspaceId: body.workspaceId,
          guildId: body.guildId,
          actorId: body.actorId,
          action: body.action,
          targetId: body.targetId,
          reason: body.reason,
          ...(body.action === 'moderation.timeout' ? { durationMs: body.durationMs } : {}),
          approval: body.approval,
          requestId: body.requestId,
        };
        const result = await executeMission(mission, guildAllowlist);
        logger.info('ELENA mission completed', {
          requestId,
          ...auditContext,
        });
        return res.status(200).json({ version: 1, requestId, status: 'completed', result });
      } catch (error) {
        const status = error instanceof ElenaMissionError ? error.status : 500;
        const code = error instanceof ElenaMissionError ? error.code : 'mission_failed';
        const message = error instanceof ElenaMissionError
          ? error.message
          : 'Mission could not be completed.';
        const audit = { requestId, ...auditContext, code, status };
        if (status === 500) {
          logger.error('ELENA mission execution failed', { ...audit, error });
        } else {
          logger.warn('ELENA mission rejected', audit);
        }
        return res.status(status).json({
          version: 1,
          ...(requestId ? { requestId } : {}),
          error: { code, message },
        });
      }
    },
  );

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const tooLarge = error?.type === 'entity.too.large';
    const status = tooLarge ? 413 : 400;
    const code = tooLarge ? 'request_too_large' : 'invalid_json';
    logger.warn('ELENA mission request parsing rejected', { code, status, ip: req.ip });
    return res.status(status).json({
      version: 1,
      error: { code, message: tooLarge ? 'Request body exceeds 16 KB.' : 'Request body must be valid JSON.' },
    });
  });

  return app;
}
