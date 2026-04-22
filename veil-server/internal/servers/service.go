package servers

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

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

// ─── Server ──────────────────────────────────────────

func (s *Service) CreateServer(ctx context.Context, name, ownerID string) (*db.Server, error) {
	if len(name) > 100 {
		return nil, errors.New("server name too long")
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
	return s.db.GetServerChannels(ctx, serverID)
}

func (s *Service) CreateChannel(ctx context.Context, serverID, requesterID, name string, channelType int16, categoryID, topic *string) (*db.Channel, error) {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	if name == "" || len(name) > 100 {
		return nil, errors.New("invalid channel name")
	}
	ch, err := s.db.CreateChannel(ctx, serverID, name, channelType, categoryID, topic)
	if err != nil {
		return nil, err
	}
	s.broadcastChannelEvent(ctx, serverID, pb.ChannelEvent_CREATED, channelToInfo(ch))
	return ch, nil
}

func (s *Service) UpdateChannel(ctx context.Context, channelID, requesterID string, name, topic *string, nsfw *bool, slowmode *int32) error {
	ch, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return errors.New("channel not found")
	}
	can, err := s.db.HasPermission(ctx, ch.ServerID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := s.db.UpdateChannel(ctx, channelID, name, topic, nsfw, slowmode, nil, nil, false); err != nil {
		return err
	}
	updated, _ := s.db.GetChannel(ctx, channelID)
	if updated != nil {
		s.broadcastChannelEvent(ctx, ch.ServerID, pb.ChannelEvent_UPDATED, channelToInfo(updated))
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
		pos := it.Position
		if err := s.db.UpdateChannel(ctx, it.ChannelID, nil, nil, nil, nil, &pos, it.CategoryID, it.ClearCategory); err != nil {
			return err
		}
	}
	// Broadcast a single UPDATED per channel so clients refresh the tree.
	for _, it := range items {
		if updated, _ := s.db.GetChannel(ctx, it.ChannelID); updated != nil {
			s.broadcastChannelEvent(ctx, serverID, pb.ChannelEvent_UPDATED, channelToInfo(updated))
		}
	}
	return nil
}

func (s *Service) DeleteChannel(ctx context.Context, channelID, requesterID string) error {
	ch, err := s.db.GetChannel(ctx, channelID)
	if err != nil {
		return errors.New("channel not found")
	}
	can, err := s.db.HasPermission(ctx, ch.ServerID, requesterID, db.PermManageChannels)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := s.db.DeleteChannel(ctx, channelID); err != nil {
		return err
	}
	s.broadcastChannelEvent(ctx, ch.ServerID, pb.ChannelEvent_DELETED, channelToInfo(ch))
	return nil
}

// ─── Roles ───────────────────────────────────────────

func (s *Service) ListRoles(ctx context.Context, serverID, requesterID string) ([]db.Role, error) {
	ok, err := s.db.IsServerMember(ctx, serverID, requesterID)
	if err != nil || !ok {
		return nil, errors.New("not a server member")
	}
	return s.db.GetServerRoles(ctx, serverID)
}

func (s *Service) CreateRole(ctx context.Context, serverID, requesterID, name string, perms uint64, color *int32) (*db.Role, error) {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageRoles)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	if name == "" || len(name) > 100 {
		return nil, errors.New("invalid role name")
	}
	r, err := s.db.CreateRole(ctx, serverID, name, perms, color)
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
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageRoles)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := s.db.UpdateRole(ctx, roleID, name, perms, color); err != nil {
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
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageRoles)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	if err := s.db.DeleteRole(ctx, roleID); err != nil {
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
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageRoles)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	return s.db.AssignRole(ctx, serverID, targetID, roleID)
}

func (s *Service) UnassignRole(ctx context.Context, serverID, requesterID, targetID, roleID string) error {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermManageRoles)
	if err != nil || !can {
		return errors.New("insufficient permissions")
	}
	return s.db.UnassignRole(ctx, serverID, targetID, roleID)
}

// ─── Invites ─────────────────────────────────────────

func (s *Service) CreateInvite(ctx context.Context, serverID, requesterID string, maxUses int32, expiresInSecs int64) (*db.Invite, error) {
	can, err := s.db.HasPermission(ctx, serverID, requesterID, db.PermCreateInvite)
	if err != nil || !can {
		return nil, errors.New("insufficient permissions")
	}
	var expiresAt *time.Time
	if expiresInSecs > 0 {
		t := time.Now().Add(time.Duration(expiresInSecs) * time.Second)
		expiresAt = &t
	}
	if maxUses < 0 {
		maxUses = 0
	}
	return s.db.CreateInvite(ctx, serverID, requesterID, maxUses, expiresAt)
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
	srv, err := s.db.UseInvite(ctx, code, userID)
	if err != nil {
		return nil, err
	}
	user, _ := s.db.FindUserByID(ctx, userID)
	if user != nil {
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

func (s *Service) broadcastChannelEvent(ctx context.Context, serverID string, evType pb.ChannelEvent_EventType, info *pb.ChannelInfo) {
	memberIDs := s.memberIDs(ctx, serverID)
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
