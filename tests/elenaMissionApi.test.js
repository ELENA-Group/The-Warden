import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createElenaMissionApp, validateElenaApiConfig } from '../src/api/elenaMissionApi.js';

const token = 'test-only-secret-that-is-at-least-32-bytes';
const workspaceId = 'elena-production';
const guildId = '12345678901234567';
const actorId = '22345678901234567';
const targetId = '32345678901234567';
const requestId = '42345678-1234-4234-8234-123456789012';
const approvalId = '52345678-1234-4234-8234-123456789012';

function makeRequest(overrides = {}) {
  const action = overrides.action || 'moderation.kick';
  const requestWorkspaceId = overrides.workspaceId || workspaceId;
  const requestGuildId = overrides.guildId || guildId;
  const requestActorId = overrides.actorId || actorId;
  const requestTargetId = overrides.targetId || targetId;
  return {
    version: 1,
    requestId: overrides.requestId || requestId,
    workspaceId: requestWorkspaceId,
    approval: {
      id: overrides.approvalId || approvalId,
      authority: 'ELENA',
      approvedAt: new Date().toISOString(),
      workspaceId: requestWorkspaceId,
      guildId: requestGuildId,
      actorId: requestActorId,
      action,
      targetId: requestTargetId,
      reason: 'Approved by ELENA',
      rationale: 'Approved moderation mission',
      ...(action === 'moderation.timeout' && overrides.durationMs !== undefined
        ? { durationMs: overrides.durationMs }
        : {}),
      ...overrides.approval,
    },
    guildId: requestGuildId,
    actorId: requestActorId,
    action,
    targetId: requestTargetId,
    reason: 'Approved by ELENA',
    ...(overrides.durationMs === undefined ? {} : { durationMs: overrides.durationMs }),
    ...overrides.body,
  };
}

describe('ELENA private mission API', () => {
  let server;
  let baseUrl;
  let executeMission;
  let missionHandler;

  before(async () => {
    missionHandler = async (mission) => ({ caseId: 'case-1', action: mission.action });
    executeMission = (mission) => missionHandler(mission);
    const app = createElenaMissionApp({
      token,
      workspaceId,
      allowedGuildIds: [guildId],
      executeMission,
    });
    server = app.listen(0, '127.0.0.1');
    await new Promise((resolve, reject) => {
      server.once('listening', resolve);
      server.once('error', reject);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
  });

  async function postMission(body, authorization = `Bearer ${token}`) {
    const response = await fetch(`${baseUrl}/v1/missions`, {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { response, json: await response.json() };
  }

  it('disables the integration when no port is configured and rejects weak/missing credentials', () => {
    assert.equal(validateElenaApiConfig({ port: null, token: '', workspaceId: '', allowedGuildIds: [] }), false);
    assert.throws(
      () => validateElenaApiConfig({ port: 3001, token: 'weak', workspaceId, allowedGuildIds: [guildId] }),
      /ELENA_API_TOKEN/,
    );
    assert.throws(
      () => validateElenaApiConfig({ port: 3001, token, workspaceId, allowedGuildIds: [] }),
      /ELENA_API_ALLOWED_GUILDS/,
    );
    assert.throws(
      () => validateElenaApiConfig({ port: 3001, token, workspaceId: '', allowedGuildIds: [guildId] }),
      /ELENA_API_WORKSPACE_ID/,
    );
  });

  it('requires bearer authentication before accepting a mission', async () => {
    const { response, json } = await postMission(makeRequest(), 'Bearer wrong-token');
    assert.equal(response.status, 401);
    assert.equal(json.error.code, 'unauthorized');
  });

  it('executes one approved allowlisted mission and rejects replay', async () => {
    let calls = 0;
    missionHandler = async (mission) => {
      calls += 1;
      assert.equal(mission.guildId, guildId);
      assert.equal(mission.workspaceId, workspaceId);
      assert.equal(mission.action, 'moderation.kick');
      return { caseId: 'case-1' };
    };
    const request = makeRequest();
    const first = await postMission(request);
    assert.equal(first.response.status, 200);
    assert.deepEqual(first.json, {
      version: 1,
      requestId,
      status: 'completed',
      result: { caseId: 'case-1' },
    });

    const replay = await postMission(request);
    assert.equal(replay.response.status, 409);
    assert.equal(replay.json.error.code, 'replayed_approval');
    assert.equal(calls, 1);
  });

  it('rejects absent or mismatched ELENA approval context', async () => {
    const noApproval = makeRequest({ requestId: '62345678-1234-4234-8234-123456789012' });
    delete noApproval.approval;
    const missing = await postMission(noApproval);
    assert.equal(missing.response.status, 400);
    assert.equal(missing.json.error.code, 'invalid_approval');

    const mismatched = makeRequest({
      requestId: '72345678-1234-4234-8234-123456789012',
      approvalId: '82345678-1234-4234-8234-123456789012',
      approval: { action: 'moderation.ban' },
    });
    const mismatch = await postMission(mismatched);
    assert.equal(mismatch.response.status, 400);
    assert.equal(mismatch.json.error.code, 'invalid_approval');
  });

  it('rejects unallowlisted guilds, actions, and invalid timeout duration', async () => {
    const wrongGuild = await postMission(makeRequest({
      guildId: '92345678901234567',
      requestId: '92345678-1234-4234-8234-123456789012',
      approvalId: 'a2345678-1234-4234-8234-123456789012',
    }));
    assert.equal(wrongGuild.response.status, 403);
    assert.equal(wrongGuild.json.error.code, 'guild_not_allowed');

    const wrongWorkspace = await postMission(makeRequest({
      workspaceId: 'another-workspace',
      requestId: 'b2345678-1234-4234-8234-123456789012',
      approvalId: 'c2345678-1234-4234-8234-123456789012',
    }));
    assert.equal(wrongWorkspace.response.status, 403);
    assert.equal(wrongWorkspace.json.error.code, 'workspace_not_allowed');

    const unsupported = makeRequest({
      action: 'admin.execute',
      requestId: 'd2345678-1234-4234-8234-123456789012',
      approvalId: 'e2345678-1234-4234-8234-123456789012',
    });
    unsupported.approval.action = unsupported.action;
    const badAction = await postMission(unsupported);
    assert.equal(badAction.response.status, 400);
    assert.equal(badAction.json.error.code, 'unsupported_action');

    const timeout = makeRequest({
      action: 'moderation.timeout',
      durationMs: 28 * 24 * 60 * 60 * 1000 + 1,
      requestId: 'f2345678-1234-4234-8234-123456789012',
      approvalId: '12345678-1234-4234-8234-123456789012',
    });
    const invalidDuration = await postMission(timeout);
    assert.equal(invalidDuration.response.status, 400);
    assert.equal(invalidDuration.json.error.code, 'invalid_request');
  });

  it('limits request bodies to 16 KB', async () => {
    const response = await fetch(`${baseUrl}/v1/missions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ data: 'x'.repeat(17 * 1024) }),
    });
    const json = await response.json();
    assert.equal(response.status, 413);
    assert.equal(json.error.code, 'request_too_large');
  });
});
