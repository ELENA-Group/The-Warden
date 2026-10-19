import { PermissionFlagsBits } from 'discord.js';
import { ErrorTypes, TitanBotError } from '../utils/errorHandler.js';
import { memberHasModerationCommandAccess } from '../utils/permissionGuard.js';
import { getGuildConfig } from './config/guildConfig.js';
import { ModerationService } from './moderation/moderationService.js';
import { ElenaMissionError } from './elenaMissionError.js';

const ALLOWED_ACTIONS = new Set([
  'moderation.ban',
  'moderation.kick',
  'moderation.timeout',
  'moderation.untimeout',
]);

export async function executeElenaMission(client, mission, workspaceId, allowedGuildIds) {
  const approval = mission?.approval;
  if (
    !approval
    || approval.authority !== 'ELENA'
    || approval.workspaceId !== mission.workspaceId
    || approval.guildId !== mission.guildId
    || approval.actorId !== mission.actorId
    || approval.action !== mission.action
    || approval.targetId !== mission.targetId
    || approval.reason !== mission.reason
    || (mission.action === 'moderation.timeout' && approval.durationMs !== mission.durationMs)
    || (mission.action !== 'moderation.timeout' && Object.hasOwn(approval, 'durationMs'))
  ) {
    throw new ElenaMissionError(403, 'invalid_approval', 'A matching ELENA approval context is required.');
  }
  if (!ALLOWED_ACTIONS.has(mission.action)) {
    throw new ElenaMissionError(400, 'unsupported_action', 'Mission action is not allowlisted.');
  }
  if (mission.workspaceId !== workspaceId) {
    throw new ElenaMissionError(403, 'workspace_not_allowed', 'ELENA workspace is not bound to this Warden instance.');
  }
  if (!(allowedGuildIds instanceof Set) || !allowedGuildIds.has(mission.guildId)) {
    throw new ElenaMissionError(403, 'guild_not_allowed', 'Guild is not allowlisted for ELENA missions.');
  }
  if (!client.isReady()) {
    throw new ElenaMissionError(503, 'warden_not_ready', 'Warden is not ready.');
  }
  const guild = client.guilds.cache.get(mission.guildId);
  if (!guild) {
    throw new ElenaMissionError(404, 'guild_not_found', 'Warden is not connected to the requested guild.');
  }

  if (mission.actorId === client.user.id || mission.targetId === client.user.id) {
    throw new ElenaMissionError(400, 'invalid_request', 'The bot cannot be the actor or target.');
  }

  let actor;
  try {
    actor = await guild.members.fetch(mission.actorId);
  } catch (error) {
    if (error?.code === 10007) {
      throw new ElenaMissionError(403, 'actor_not_in_guild', 'The approved Discord actor is not a member of this guild.');
    }
    throw error;
  }

  const guildConfig = await getGuildConfig(client, guild.id);
  const requiredPermissions = {
    'moderation.ban': PermissionFlagsBits.BanMembers,
    'moderation.kick': PermissionFlagsBits.KickMembers,
    'moderation.timeout': PermissionFlagsBits.ModerateMembers,
    'moderation.untimeout': PermissionFlagsBits.ModerateMembers,
  }[mission.action];
  if (!memberHasModerationCommandAccess(actor, guildConfig, requiredPermissions)) {
    throw new ElenaMissionError(403, 'actor_not_authorized', 'The approved Discord actor lacks the required moderation permission.');
  }

  try {
    if (mission.action === 'moderation.ban') {
      const user = await client.users.fetch(mission.targetId);
      return await ModerationService.banUser({
        guild,
        user,
        moderator: actor,
        reason: mission.reason,
        deleteDays: 0,
      });
    }

    const target = await guild.members.fetch(mission.targetId);
    if (mission.action === 'moderation.kick') {
      return await ModerationService.kickUser({
        guild,
        member: target,
        moderator: actor,
        reason: mission.reason,
      });
    }
    if (mission.action === 'moderation.timeout') {
      return await ModerationService.timeoutUser({
        guild,
        member: target,
        moderator: actor,
        durationMs: mission.durationMs,
        reason: mission.reason,
      });
    }
    return await ModerationService.removeTimeoutUser({
      guild,
      member: target,
      moderator: actor,
      reason: mission.reason,
    });
  } catch (error) {
    if (error instanceof TitanBotError && error.type === ErrorTypes.PERMISSION) {
      throw new ElenaMissionError(403, 'moderation_denied', error.userMessage || error.message);
    }
    if (error instanceof TitanBotError && error.type === ErrorTypes.VALIDATION) {
      throw new ElenaMissionError(400, 'moderation_rejected', error.userMessage || error.message);
    }
    if (error?.code === 10007 || error?.code === 10013) {
      throw new ElenaMissionError(404, 'target_not_found', 'The target user was not found.');
    }
    throw error;
  }
}
