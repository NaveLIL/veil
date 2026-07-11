package servers

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/db"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

// Broadcaster delivers WebSocket envelopes to a set of users.
type Broadcaster interface {
	BroadcastToUsers(userIDs []string, env *pb.Envelope)
}

// Service implements server/channel/role/invite business logic.
type Service struct {
	db    *db.DB
	bcast Broadcaster
}

const (
	maxInviteUses       int32 = 1_000_000
	maxInviteExpirySecs int64 = 365 * 24 * 60 * 60
	maxKickReasonBytes        = 512
)

var (
	ErrInvalidInviteInput = errors.New("invalid invite limits")
	ErrInvalidKickReason  = errors.New("invalid kick reason")
)

func NewService(database *db.DB, bcast Broadcaster) *Service {
	return &Service{db: database, bcast: bcast}
}

// SigningKeyLookup returns an authmw.UserKeyLookup backed by this service's
// database, used when constructing the shared signing middleware.
func (s *Service) SigningKeyLookup() authmw.UserKeyLookup {
	return authmw.LookupFunc(func(ctx context.Context, userID string) (ed25519.PublicKey, error) {
		u, err := s.db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(u.SigningKey), nil
	})
}

// memberIDs returns user IDs of all members of a server.
func (s *Service) memberIDs(ctx context.Context, serverID string) []string {
	members, err := s.db.GetServerMembers(ctx, serverID)
	if err != nil {
		return nil
	}
	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.UserID
	}
	return ids
}

// channelViewerIDs returns only members allowed to learn channel metadata.
// Message-history is intentionally not required for channel create/update
// events, but VIEW_CHANNEL is always enforced.
func (s *Service) channelViewerIDs(ctx context.Context, channelID string) []string {
	channel, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return nil
	}
	members, err := s.db.GetServerMembers(ctx, channel.ServerID)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(members))
	for _, member := range members {
		allowed, permissionErr := s.db.HasAllChannelPermissions(ctx, channelID, member.UserID, db.PermViewChannel)
		if permissionErr == nil && allowed {
			ids = append(ids, member.UserID)
		}
	}
	return ids
}

// ─── Server ──────────────────────────────────────────

func (s *Service) CreateServer(ctx context.Context, name, ownerID string) (*db.Server, error) {
	if err := validateServerName(name); err != nil {
		return nil, err
	}
	srv, err := s.db.CreateServer(ctx, name, ownerID)
	if err != nil {
		return nil, err
	}
	s.broadcastServerEvent(ctx, srv.ID, pb.ServerEvent_CREATED, &pb.ServerEvent{
		EventType: pb.ServerEvent_CREATED,
		ServerId:  srv.ID,
		ServerInfo: &pb.ServerInfo{
			Id:   srv.ID,
			Name: srv.Name,
		},
	})
	return srv, nil
}

func (s *Service) ListUserServers(ctx context.Context, userID string) ([]db.Server, error) {
	return s.db.GetUserServers(ctx, userID)
}

func (s *Service) GetServer(ctx context.Context, serverID, userID string) (*db.Server, error) {
	ok, err := s.db.IsServerMember(ctx, serverID, userID)
	if err != nil || !ok {
		return nil, errors.New("not a server member")
	}
	return s.db.GetServer(ctx, serverID)
}

func (s *Service) UpdateServer(ctx context.Context, serverID, requesterID string, name, description, iconURL *string) error {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageServer)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := validateServerMetadata(name, description, iconURL); err != nil {
		return err
	}
	if err := s.db.UpdateServer(ctx, serverID, name, description, iconURL); err != nil {
		return err
	}
	srv, _ := s.db.GetServer(ctx, serverID)
	if srv != nil {
		s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_UPDATED, &pb.ServerEvent{
			EventType:  pb.ServerEvent_UPDATED,
			ServerId:   srv.ID,
			ServerInfo: &pb.ServerInfo{Id: srv.ID, Name: srv.Name},
		})
	}
	return nil
}

func (s *Service) DeleteServer(ctx context.Context, serverID, requesterID string) error {
	owner, err := s.db.IsServerOwner(ctx, serverID, requesterID)
	if err != nil || !owner {
		return errors.New("only owner can delete server")
	}
	memberIDs := s.memberIDs(ctx, serverID)
	if err := s.db.DeleteServer(ctx, serverID); err != nil {
		return err
	}
	s.bcast.BroadcastToUsers(memberIDs, &pb.Envelope{
		Payload: &pb.Envelope_ServerEvent{ServerEvent: &pb.ServerEvent{
			EventType: pb.ServerEvent_DELETED, ServerId: serverID,
		}},
	})
	return nil
}

func (s *Service) LeaveServer(ctx context.Context, serverID, userID string) error {
	owner, _ := s.db.IsServerOwner(ctx, serverID, userID)
	if owner {
		return errors.New("owner cannot leave; transfer ownership or delete server")
	}
	user, _ := s.db.FindUserByID(ctx, userID)
	if err := s.db.RemoveServerMember(ctx, serverID, userID); err != nil {
		return err
	}
	if user != nil {
		s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_MEMBER_LEFT, &pb.ServerEvent{
			EventType:  pb.ServerEvent_MEMBER_LEFT,
			ServerId:   serverID,
			MemberInfo: &pb.MemberInfo{IdentityKey: user.IdentityKey, Username: user.Username},
		})
	}
	return nil
}

// KickMember removes a member; requires KICK_MEMBERS permission.
func (s *Service) KickMember(ctx context.Context, serverID, requesterID, targetID string, reason *string) error {
	normalizedReason, err := normalizeKickReason(reason)
	if err != nil {
		return err
	}
	reason = normalizedReason
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermKickMembers)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if requesterID == targetID {
		return errors.New("cannot kick yourself")
	}
	owner, _ := s.db.IsServerOwner(ctx, serverID, targetID)
	if owner {
		return errors.New("cannot kick the owner")
	}
	targetMember, err := s.db.IsServerMember(ctx, serverID, targetID)
	if err != nil || !targetMember {
		return errors.New("target is not a server member")
	}
	requesterOwner, err := s.db.IsServerOwner(ctx, serverID, requesterID)
	if err != nil {
		return errors.New("server not found")
	}
	if !requesterOwner {
		requesterHighest, requesterErr := s.db.GetHighestRolePosition(ctx, serverID, requesterID)
		targetHighest, targetErr := s.db.GetHighestRolePosition(ctx, serverID, targetID)
		if requesterErr != nil || targetErr != nil || requesterHighest <= targetHighest {
			return errors.New("target member is outside the requester's role hierarchy")
		}
	}
	user, _ := s.db.FindUserByID(ctx, targetID)
	memberIDs := s.memberIDs(ctx, serverID)
	if err := s.db.RemoveServerMember(ctx, serverID, targetID); err != nil {
		return err
	}
	if user != nil {
		ev := &pb.ServerEvent{
			EventType: pb.ServerEvent_MEMBER_KICKED,
			ServerId:  serverID,
			MemberInfo: &pb.MemberInfo{
				IdentityKey: user.IdentityKey,
				Username:    user.Username,
				Reason:      reason,
			},
		}
		s.bcast.BroadcastToUsers(memberIDs, &pb.Envelope{
			Payload: &pb.Envelope_ServerEvent{ServerEvent: ev},
		})
	}
	return nil
}

// ─── Members ─────────────────────────────────────────

func (s *Service) ListMembers(ctx context.Context, serverID, requesterID string) ([]db.ServerMember, error) {
	ok, err := s.db.IsServerMember(ctx, serverID, requesterID)
	if err != nil || !ok {
		return nil, errors.New("not a server member")
	}
	return s.db.GetServerMembers(ctx, serverID)
}

// ─── Channels ────────────────────────────────────────

func (s *Service) ListChannels(ctx context.Context, serverID, requesterID string) ([]db.Channel, error) {
	ok, err := s.db.IsServerMember(ctx, serverID, requesterID)
	if err != nil || !ok {
		return nil, errors.New("not a server member")
	}
	channels, err := s.db.GetVisibleServerChannels(ctx, serverID, requesterID)
	if err != nil {
		return nil, errors.New("insufficient permissions")
	}
	return channels, nil
}

func (s *Service) CreateChannel(ctx context.Context, serverID, requesterID, name string, channelType int16, categoryID, topic *string) (*db.Channel, error) {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	if channelType < 0 || channelType > 2 {
		return nil, errors.New("invalid channel type")
	}
	if err := validateChannelMetadata(&name, topic); err != nil {
		return nil, err
	}
	ch, err := s.db.CreateChannel(ctx, serverID, name, channelType, categoryID, topic)
	if err != nil {
		return nil, err
	}
	s.broadcastChannelEvent(ctx, ch.ID, pb.ChannelEvent_CREATED, channelToInfo(ch))
	return ch, nil
}

func (s *Service) UpdateChannel(ctx context.Context, channelID, requesterID string, name, topic *string, nsfw *bool, slowmode *int32) error {
	ch, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return errors.New("channel not found")
	}
	can, err := s.db.HasAllChannelPermissions(ctx, ch.ID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := validateChannelMetadata(name, topic); err != nil {
		return err
	}
	if err := s.db.UpdateChannel(ctx, channelID, name, topic, nsfw, slowmode, nil, nil, false); err != nil {
		return err
	}
	updated, _ := s.db.GetChannel(ctx, channelID)
	if updated != nil {
		s.broadcastChannelEvent(ctx, ch.ID, pb.ChannelEvent_UPDATED, channelToInfo(updated))
	}
	return nil
}

func validateServerName(name string) error {
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || len(name) > 100 {
		return errors.New("server name must be 1..100 UTF-8 bytes")
	}
	return nil
}

func validateServerMetadata(name, description, iconURL *string) error {
	if name != nil {
		if err := validateServerName(*name); err != nil {
			return err
		}
	}
	if description != nil && (!utf8.ValidString(*description) || len(*description) > 2000) {
		return errors.New("server description must be valid UTF-8 up to 2000 bytes")
	}
	if iconURL == nil || *iconURL == "" {
		return nil
	}
	if !utf8.ValidString(*iconURL) || len(*iconURL) > 2048 {
		return errors.New("server icon URL is too long or invalid")
	}
	parsed, err := url.Parse(*iconURL)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Opaque != "" ||
		parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("server icon URL must be an absolute HTTPS URL without credentials or fragment")
	}
	return nil
}

func validateChannelMetadata(name, topic *string) error {
	if name != nil && (!utf8.ValidString(*name) || strings.TrimSpace(*name) == "" || len(*name) > 100) {
		return errors.New("channel name must be 1..100 UTF-8 bytes")
	}
	if topic != nil && (!utf8.ValidString(*topic) || len(*topic) > 2000) {
		return errors.New("channel topic must be valid UTF-8 up to 2000 bytes")
	}
	return nil
}

// ReorderItem describes a single channel’s new placement.
type ReorderItem struct {
	ChannelID     string
	Position      int16
	CategoryID    *string // nil + ClearCategory=true means move to top-level
	ClearCategory bool
}

// ReorderChannels applies multiple position/category changes in one transaction-ish
// pass. Caller must have ManageChannels permission on the server. All channels
// referenced must belong to the same server.
func (s *Service) ReorderChannels(ctx context.Context, serverID, requesterID string, items []ReorderItem) error {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if len(items) == 0 {
		return nil
	}
	for _, it := range items {
		ch, err := s.db.GetChannel(ctx, it.ChannelID)
		if err != nil {
			return errors.New("channel not found: " + it.ChannelID)
		}
		if ch.ServerID != serverID {
			return errors.New("channel does not belong to server")
		}
		canManage, permissionErr := s.db.HasAllChannelPermissions(ctx, ch.ID, requesterID, db.PermManageChannels)
		if permissionErr != nil || !canManage {
			return errors.New("insufficient permissions")
		}
		pos := it.Position
		if err := s.db.UpdateChannel(ctx, it.ChannelID, nil, nil, nil, nil, &pos, it.CategoryID, it.ClearCategory); err != nil {
			return err
		}
	}
	// Broadcast a single UPDATED per channel so clients refresh the tree.
	for _, it := range items {
		if updated, _ := s.db.GetChannel(ctx, it.ChannelID); updated != nil {
			s.broadcastChannelEvent(ctx, updated.ID, pb.ChannelEvent_UPDATED, channelToInfo(updated))
		}
	}
	return nil
}

func (s *Service) DeleteChannel(ctx context.Context, channelID, requesterID string) error {
	ch, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return errors.New("channel not found")
	}
	can, err := s.db.HasAllChannelPermissions(ctx, ch.ID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	viewers := s.channelViewerIDs(ctx, ch.ID)
	if err := s.db.DeleteChannel(ctx, channelID); err != nil {
		return err
	}
	s.broadcastChannelEventTo(ctx, viewers, ch.ServerID, pb.ChannelEvent_DELETED, channelToInfo(ch))
	return nil
}

// ─── Roles ───────────────────────────────────────────

func (s *Service) authorizeChannelOverwriteManager(ctx context.Context, channelID, requesterID string, allow uint64) (*db.Channel, error) {
	channel, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return nil, errors.New("channel not found")
	}
	permissions, err := s.db.GetChannelPermissions(ctx, channelID, requesterID)
	if err != nil || permissions&db.PermAdministrator == 0 && permissions&db.PermManageChannels == 0 {
		return nil, errors.New("insufficient permissions")
	}
	if permissions&db.PermAdministrator == 0 && allow&^permissions != 0 {
		return nil, errors.New("cannot grant channel permissions the requester does not possess")
	}
	return channel, nil
}

func (s *Service) ListChannelOverwrites(ctx context.Context, channelID, requesterID string) ([]db.ChannelOverwrite, error) {
	if _, err := s.authorizeChannelOverwriteManager(ctx, channelID, requesterID, 0); err != nil {
		return nil, err
	}
	return s.db.GetChannelOverwrites(ctx, channelID)
}

func (s *Service) UpsertChannelOverwrite(ctx context.Context, requesterID string, overwrite db.ChannelOverwrite) error {
	channel, err := s.authorizeChannelOverwriteManager(ctx, overwrite.ChannelID, requesterID, overwrite.Allow)
	if err != nil {
		return err
	}
	before := s.channelViewerIDs(ctx, overwrite.ChannelID)
	if err := s.db.UpsertChannelOverwrite(ctx, overwrite); err != nil {
		if errors.Is(err, db.ErrInvalidChannelOverwrite) {
			return err
		}
		return db.ErrInvalidChannelOverwrite
	}
	after := s.channelViewerIDs(ctx, overwrite.ChannelID)
	s.broadcastChannelEventTo(
		ctx, unionUserIDs(before, after), channel.ServerID,
		pb.ChannelEvent_UPDATED, channelToInfo(channel),
	)
	return nil
}

func (s *Service) DeleteChannelOverwrite(ctx context.Context, channelID, requesterID, targetID string, targetType int16) error {
	channel, err := s.authorizeChannelOverwriteManager(ctx, channelID, requesterID, 0)
	if err != nil {
		return err
	}
	before := s.channelViewerIDs(ctx, channelID)
	if err := s.db.DeleteChannelOverwrite(ctx, channelID, targetID, targetType); err != nil {
		if errors.Is(err, db.ErrInvalidChannelOverwrite) {
			return err
		}
		return errors.New("channel overwrite not found")
	}
	after := s.channelViewerIDs(ctx, channelID)
	s.broadcastChannelEventTo(
		ctx, unionUserIDs(before, after), channel.ServerID,
		pb.ChannelEvent_UPDATED, channelToInfo(channel),
	)
	return nil
}

func unionUserIDs(groups ...[]string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, group := range groups {
		for _, userID := range group {
			if _, exists := seen[userID]; exists {
				continue
			}
			seen[userID] = struct{}{}
			result = append(result, userID)
		}
	}
	return result
}

type roleManager struct {
	owner       bool
	permissions uint64
	highest     int16
}

func (s *Service) authorizeRoleManager(ctx context.Context, serverID, requesterID string) (roleManager, error) {
	owner, err := s.db.IsServerOwner(ctx, serverID, requesterID)
	if err != nil {
		return roleManager{}, errors.New("server not found")
	}
	permissions, err := s.db.GetUserPermissions(ctx, serverID, requesterID)
	if err != nil || (!owner && permissions&db.PermAdministrator == 0 && permissions&db.PermManageRoles == 0) {
		return roleManager{}, errors.New("insufficient permissions")
	}
	if owner {
		return roleManager{owner: true, permissions: db.PermAdministrator, highest: 32767}, nil
	}
	highest, err := s.db.GetHighestRolePosition(ctx, serverID, requesterID)
	if err != nil {
		return roleManager{}, errors.New("insufficient permissions")
	}
	return roleManager{permissions: permissions, highest: highest}, nil
}

func (manager roleManager) canGrant(permissions uint64) bool {
	if permissions&^db.AllRolePermissions != 0 {
		return false
	}
	if manager.owner || manager.permissions&db.PermAdministrator != 0 {
		return true
	}
	return permissions&^manager.permissions == 0
}

func (s *Service) canManageRoleTarget(ctx context.Context, serverID, requesterID, targetID string, manager roleManager) bool {
	if manager.owner {
		return true
	}
	// A non-owner cannot alter their own assignments. This closes the
	// multi-role and equal-position variants of self-escalation.
	if requesterID == targetID {
		return false
	}
	targetOwner, err := s.db.IsServerOwner(ctx, serverID, targetID)
	if err != nil || targetOwner {
		return false
	}
	isMember, err := s.db.IsServerMember(ctx, serverID, targetID)
	if err != nil || !isMember {
		return false
	}
	targetHighest, err := s.db.GetHighestRolePosition(ctx, serverID, targetID)
	return err == nil && targetHighest < manager.highest
}

func (s *Service) ListRoles(ctx context.Context, serverID, requesterID string) ([]db.Role, error) {
	ok, err := s.db.IsServerMember(ctx, serverID, requesterID)
	if err != nil || !ok {
		return nil, errors.New("not a server member")
	}
	return s.db.GetServerRoles(ctx, serverID)
}

func (s *Service) CreateRole(ctx context.Context, serverID, requesterID, name string, perms uint64, color *int32) (*db.Role, error) {
	if name == "" || len(name) > 100 {
		return nil, errors.New("invalid role name")
	}
	manager, err := s.authorizeRoleManager(ctx, serverID, requesterID)
	if err != nil {
		return nil, err
	}
	if !manager.canGrant(perms) {
		return nil, errors.New("cannot grant permissions the requester does not possess")
	}
	var positionCeiling *int16
	if !manager.owner {
		if manager.highest <= 0 {
			return nil, errors.New("role hierarchy prevents creating a manageable role")
		}
		ceiling := manager.highest - 1
		positionCeiling = &ceiling
	}
	r, err := s.db.CreateRole(ctx, serverID, name, perms, color, positionCeiling)
	if err != nil {
		return nil, err
	}
	s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_ROLE_CREATED, &pb.ServerEvent{
		EventType: pb.ServerEvent_ROLE_CREATED,
		ServerId:  serverID,
		RoleInfo:  roleToInfo(r),
	})
	return r, nil
}

func (s *Service) UpdateRole(ctx context.Context, serverID, roleID, requesterID string, name *string, perms *uint64, color *int32) error {
	manager, err := s.authorizeRoleManager(ctx, serverID, requesterID)
	if err != nil {
		return err
	}
	role, err := s.db.GetRole(ctx, serverID, roleID)
	if err != nil {
		return errors.New("role not found in server")
	}
	if !manager.owner && role.Position >= manager.highest {
		return errors.New("role hierarchy prevents this update")
	}
	if name != nil && (*name == "" || len(*name) > 100) {
		return errors.New("invalid role name")
	}
	if perms != nil && !manager.canGrant(*perms) {
		return errors.New("cannot grant permissions the requester does not possess")
	}
	if err := s.db.UpdateRole(ctx, serverID, roleID, name, perms, color); err != nil {
		return err
	}
	roles, _ := s.db.GetServerRoles(ctx, serverID)
	for _, r := range roles {
		if r.ID == roleID {
			s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_ROLE_UPDATED, &pb.ServerEvent{
				EventType: pb.ServerEvent_ROLE_UPDATED,
				ServerId:  serverID,
				RoleInfo:  roleToInfo(&r),
			})
			break
		}
	}
	return nil
}

func (s *Service) DeleteRole(ctx context.Context, serverID, roleID, requesterID string) error {
	manager, err := s.authorizeRoleManager(ctx, serverID, requesterID)
	if err != nil {
		return err
	}
	role, err := s.db.GetRole(ctx, serverID, roleID)
	if err != nil {
		return errors.New("role not found in server")
	}
	if role.IsDefault {
		return errors.New("default role cannot be deleted")
	}
	if !manager.owner && role.Position >= manager.highest {
		return errors.New("role hierarchy prevents this deletion")
	}
	if err := s.db.DeleteRole(ctx, serverID, roleID); err != nil {
		return err
	}
	s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_ROLE_DELETED, &pb.ServerEvent{
		EventType: pb.ServerEvent_ROLE_DELETED,
		ServerId:  serverID,
		RoleInfo:  &pb.RoleInfo{Id: roleID},
	})
	return nil
}

func (s *Service) AssignRole(ctx context.Context, serverID, requesterID, targetID, roleID string) error {
	manager, err := s.authorizeRoleManager(ctx, serverID, requesterID)
	if err != nil {
		return err
	}
	role, err := s.db.GetRole(ctx, serverID, roleID)
	if err != nil || role.IsDefault {
		return errors.New("role not found or cannot be assigned")
	}
	if !manager.owner && (role.Position >= manager.highest || !manager.canGrant(role.Permissions)) {
		return errors.New("role hierarchy or permission scope prevents assignment")
	}
	if !s.canManageRoleTarget(ctx, serverID, requesterID, targetID, manager) {
		return errors.New("target member is outside the requester's role hierarchy")
	}
	if err := s.db.AssignRole(ctx, serverID, targetID, roleID); err != nil {
		return err
	}
	s.broadcastRoleAssignment(ctx, serverID, targetID, role)
	return nil
}

func (s *Service) UnassignRole(ctx context.Context, serverID, requesterID, targetID, roleID string) error {
	manager, err := s.authorizeRoleManager(ctx, serverID, requesterID)
	if err != nil {
		return err
	}
	role, err := s.db.GetRole(ctx, serverID, roleID)
	if err != nil || role.IsDefault {
		return errors.New("role not found or cannot be unassigned")
	}
	if !manager.owner && role.Position >= manager.highest {
		return errors.New("role hierarchy prevents unassignment")
	}
	if !s.canManageRoleTarget(ctx, serverID, requesterID, targetID, manager) {
		return errors.New("target member is outside the requester's role hierarchy")
	}
	if err := s.db.UnassignRole(ctx, serverID, targetID, roleID); err != nil {
		return err
	}
	s.broadcastRoleAssignment(ctx, serverID, targetID, role)
	return nil
}

// ─── Invites ─────────────────────────────────────────

func (s *Service) CreateInvite(ctx context.Context, serverID, requesterID string, maxUses int32, expiresInSecs int64) (*db.Invite, error) {
	if err := validateInviteInput(maxUses, expiresInSecs); err != nil {
		return nil, err
	}
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermCreateInvite)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	var expiresAt *time.Time
	if expiresInSecs > 0 {
		t := time.Now().Add(time.Duration(expiresInSecs) * time.Second)
		expiresAt = &t
	}
	return s.db.CreateInvite(ctx, serverID, requesterID, maxUses, expiresAt)
}

func validateInviteInput(maxUses int32, expiresInSecs int64) error {
	if maxUses < 0 || maxUses > maxInviteUses || expiresInSecs < 0 || expiresInSecs > maxInviteExpirySecs {
		return ErrInvalidInviteInput
	}
	return nil
}

func normalizeKickReason(reason *string) (*string, error) {
	if reason == nil {
		return nil, nil
	}
	if !utf8.ValidString(*reason) {
		return nil, ErrInvalidKickReason
	}
	normalized := strings.TrimSpace(*reason)
	if normalized == "" {
		return nil, nil
	}
	if len(normalized) > maxKickReasonBytes {
		return nil, ErrInvalidKickReason
	}
	return &normalized, nil
}

func (s *Service) ListInvites(ctx context.Context, serverID, requesterID string) ([]db.Invite, error) {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageServer)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	return s.db.GetServerInvites(ctx, serverID)
}

func (s *Service) RevokeInvite(ctx context.Context, code, requesterID string) error {
	inv, err := s.db.GetInvite(ctx, code)
	if err != nil {
		return errors.New("invite not found")
	}
	can, err := s.db.HasPermission(ctx, inv.ServerID, requesterID, db.PermManageServer)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	return s.db.RevokeInvite(ctx, code)
}

// UseInvite joins the requester to the server; returns the joined server.
func (s *Service) UseInvite(ctx context.Context, code, userID string) (*db.Server, error) {
	srv, joined, err := s.db.UseInvite(ctx, code, userID)
	if err != nil {
		return nil, err
	}
	user, _ := s.db.FindUserByID(ctx, userID)
	if joined && user != nil {
		s.broadcastServerEvent(ctx, srv.ID, pb.ServerEvent_MEMBER_JOINED, &pb.ServerEvent{
			EventType:  pb.ServerEvent_MEMBER_JOINED,
			ServerId:   srv.ID,
			MemberInfo: &pb.MemberInfo{IdentityKey: user.IdentityKey, Username: user.Username},
		})
	}
	return srv, nil
}

// PreviewInvite returns server info for an invite without joining.
func (s *Service) PreviewInvite(ctx context.Context, code string) (*db.Server, *db.Invite, error) {
	inv, err := s.db.GetInvite(ctx, code)
	if err != nil {
		return nil, nil, errors.New("invite not found")
	}
	srv, err := s.db.GetServer(ctx, inv.ServerID)
	if err != nil {
		return nil, nil, errors.New("server not found")
	}
	return srv, inv, nil
}

// ─── Internal broadcast helpers ──────────────────────

// broadcastServerEvent sends a ServerEvent envelope to all server members.
func (s *Service) broadcastServerEvent(ctx context.Context, serverID string, _ pb.ServerEvent_EventType, ev *pb.ServerEvent) {
	memberIDs := s.memberIDs(ctx, serverID)
	if len(memberIDs) == 0 {
		return
	}
	s.bcast.BroadcastToUsers(memberIDs, &pb.Envelope{
		Payload: &pb.Envelope_ServerEvent{ServerEvent: ev},
	})
}

func (s *Service) broadcastChannelEvent(ctx context.Context, channelID string, evType pb.ChannelEvent_EventType, info *pb.ChannelInfo) {
	channel, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return
	}
	s.broadcastChannelEventTo(ctx, s.channelViewerIDs(ctx, channelID), channel.ServerID, evType, info)
}

func (s *Service) broadcastChannelEventTo(_ context.Context, memberIDs []string, serverID string, evType pb.ChannelEvent_EventType, info *pb.ChannelInfo) {
	if len(memberIDs) == 0 {
		return
	}
	s.bcast.BroadcastToUsers(memberIDs, &pb.Envelope{
		Payload: &pb.Envelope_ChannelEvent{ChannelEvent: &pb.ChannelEvent{
			EventType:   evType,
			ServerId:    serverID,
			ChannelInfo: info,
		}},
	})
}

// broadcastRoleAssignment sends the target's complete current role set. The
// same ROLE_UPDATED event represents assign and unassign; clients compare the
// authoritative MemberInfo.RoleIds and then refresh authorized channel
// directories before distributing sender keys.
func (s *Service) broadcastRoleAssignment(ctx context.Context, serverID, targetID string, role *db.Role) {
	members, err := s.db.GetServerMembers(ctx, serverID)
	if err != nil {
		return
	}
	var info *pb.MemberInfo
	for _, member := range members {
		if member.UserID == targetID {
			info = &pb.MemberInfo{
				IdentityKey: member.IdentityKey,
				Username:    member.Username,
				RoleIds:     append([]string(nil), member.RoleIDs...),
			}
			break
		}
	}
	if info == nil {
		return
	}
	s.broadcastServerEvent(ctx, serverID, pb.ServerEvent_ROLE_UPDATED, &pb.ServerEvent{
		EventType:  pb.ServerEvent_ROLE_UPDATED,
		ServerId:   serverID,
		MemberInfo: info,
		RoleInfo:   roleToInfo(role),
	})
}

// ─── Conversion helpers ──────────────────────────────

func channelToInfo(c *db.Channel) *pb.ChannelInfo {
	if c == nil {
		return nil
	}
	info := &pb.ChannelInfo{
		Id:          c.ID,
		ServerId:    c.ServerID,
		Name:        c.Name,
		ChannelType: pb.ChannelType(c.ChannelType),
		Position:    uint32(c.Position),
		CategoryId:  c.CategoryID,
		Topic:       c.Topic,
	}
	return info
}

func roleToInfo(r *db.Role) *pb.RoleInfo {
	if r == nil {
		return nil
	}
	info := &pb.RoleInfo{
		Id:          r.ID,
		Name:        r.Name,
		Permissions: r.Permissions,
		Position:    uint32(r.Position),
	}
	if r.Color != nil {
		c := uint32(*r.Color)
		info.Color = &c
	}
	return info
}

// hexEncodePtr removed (unused).
