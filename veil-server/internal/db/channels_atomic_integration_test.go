//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/servers"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type channelBroadcastProbe struct{ check func(*pb.Envelope) }

func (p channelBroadcastProbe) BroadcastToUsers(_ []string, envelope *pb.Envelope) { p.check(envelope) }

func newChannelOwner(t *testing.T, database *db.DB, ctx context.Context) *db.User {
	t.Helper()
	identity := make([]byte, 32)
	if _, err := rand.Read(identity); err != nil {
		t.Fatal(err)
	}
	signing, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := database.CreateUser(ctx, identity, signing, "channel-owner")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestDeletePopulatedChannelPreservesSendOutcome(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner := newChannelOwner(t, database, ctx)
	server, err := database.CreateServer(ctx, "purge-regression", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	channels, err := database.GetServerChannels(ctx, server.ID)
	if err != nil || len(channels) != 1 {
		t.Fatalf("channels=%v err=%v", channels, err)
	}
	channel := channels[0]
	conversationID := *channel.ConversationID
	messageID, clientID := uuid.NewString(), uuid.NewString()
	digest := sha256.Sum256([]byte("exact-original-send-request"))
	// Seed an already accepted Sender-Key v5 message. The ciphertext is opaque;
	// all current SQL security-context constraints and triggers remain enabled.
	if _, err := database.Pool.Exec(ctx, `INSERT INTO messages
		(id, conversation_id, sender_id, ciphertext, crypto_profile, crypto_era,
		 roster_version, roster_commitment, sender_device_id, sender_binding_version)
		VALUES ($1, $2, $3, $4, 'sender_key_v5', 1, 1, $5, $6, 1)`,
		messageID, conversationID, owner.ID, []byte("opaque-ciphertext"), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO message_send_idempotency
		(sender_id, client_message_id, request_digest, message_id, server_timestamp, ack_roster_version)
		SELECT sender_id, $2::uuid, $3, id, created_at, roster_version FROM messages WHERE id=$1::uuid`, messageID, clientID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO reactions (message_id, conversation_id, user_id, emoji) VALUES ($1,$2,$3,'ok')`, messageID, conversationID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO tus_uploads (file_id,user_id,size_bytes,expires_at) VALUES ('purge-file',$1,3,now()+interval '1 day')`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO message_attachments (message_id,file_id,position,encrypted_key,nonce,size_bytes,content_type)
		VALUES ($1,'purge-file',0,$2,$3,3,'application/octet-stream')`, messageID, []byte{1}, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO mls_welcomes (recipient_user_id,recipient_device_id,conversation_id,blob) VALUES ($1,$2,$3,$4)`, owner.ID, bytes.Repeat([]byte{2}, 16), conversationID, []byte{3}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO mls_commits (conversation_id,epoch,sender_user_id,blob) VALUES ($1,1,$2,$3)`, conversationID, owner.ID, []byte{4}); err != nil {
		t.Fatal(err)
	}
	before, err := database.LookupMessageSendOutcome(ctx, owner.ID, clientID, digest[:])
	if err != nil || before == nil {
		t.Fatalf("outcome before purge=%v err=%v", before, err)
	}

	broadcasts := 0
	service := servers.NewService(database, channelBroadcastProbe{check: func(envelope *pb.Envelope) {
		broadcasts++
		if envelope.GetChannelEvent().GetEventType() != pb.ChannelEvent_DELETED {
			t.Fatal("unexpected event")
		}
		if _, err := database.GetChannel(ctx, channel.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("broadcast before delete commit: %v", err)
		}
	}})
	// A failure at the last dependency delete must restore earlier purges and
	// suppress the event. This exercises a real transaction rollback.
	if _, err := database.Pool.Exec(ctx, `CREATE FUNCTION reject_conversation_purge() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced purge rollback'; END $$;
		CREATE TRIGGER reject_conversation_purge BEFORE DELETE ON conversations FOR EACH ROW EXECUTE FUNCTION reject_conversation_purge()`); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteChannel(ctx, channel.ID, owner.ID); err == nil {
		t.Fatal("expected purge rollback")
	}
	if _, err := database.GetChannel(ctx, channel.ID); err != nil || broadcasts != 0 {
		t.Fatalf("failed purge leaked channel/broadcast: %v count=%d", err, broadcasts)
	}
	for _, table := range []string{"messages", "reactions", "mls_welcomes", "mls_commits"} {
		var count int
		if err := database.Pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE conversation_id::text=$1", conversationID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("failed purge leaked %s: count=%d err=%v", table, count, err)
		}
	}
	if _, err := database.Pool.Exec(ctx, `DROP TRIGGER reject_conversation_purge ON conversations; DROP FUNCTION reject_conversation_purge()`); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteChannel(ctx, channel.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if broadcasts != 1 {
		t.Fatalf("broadcasts=%d", broadcasts)
	}
	for _, table := range []string{"messages", "reactions", "mls_welcomes", "mls_commits", "conversation_members"} {
		var count int
		if err := database.Pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE conversation_id::text=$1", conversationID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows", table, count)
		}
	}
	var attachments int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM message_attachments WHERE message_id=$1`, messageID).Scan(&attachments); err != nil || attachments != 0 {
		t.Fatalf("attachments=%d err=%v", attachments, err)
	}
	replay, err := database.StoreMessageIdempotent(ctx, &db.Message{ConversationID: conversationID, SenderID: owner.ID, Ciphertext: []byte("opaque-ciphertext")}, clientID, digest[:])
	if err != nil || replay == nil || !replay.Replayed || replay.MessageID != before.MessageID || !replay.ServerTimestamp.Equal(before.ServerTimestamp) || *replay.AckRosterVersion != *before.AckRosterVersion {
		t.Fatalf("outcome changed after purge: before=%+v replay=%+v err=%v", before, replay, err)
	}
	changedDigest := sha256.Sum256([]byte("different-request"))
	if _, err := database.LookupMessageSendOutcome(ctx, owner.ID, clientID, changedDigest[:]); !errors.Is(err, db.ErrMessageSendIDConflict) {
		t.Fatalf("conflicting replay=%v", err)
	}
}

func TestReorderChannelsRejectsWholeBatchAndBroadcastsOnlyCommit(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner := newChannelOwner(t, database, ctx)
	server, err := database.CreateServer(ctx, "reorder-regression", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := database.CreateChannel(ctx, server.ID, "first", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.CreateChannel(ctx, server.ID, "second", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	category, err := database.CreateChannel(ctx, server.ID, "category", 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreignServer, err := database.CreateServer(ctx, "foreign", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := database.CreateChannel(ctx, foreignServer.ID, "foreign", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	broadcasts := 0
	service := servers.NewService(database, channelBroadcastProbe{check: func(*pb.Envelope) { broadcasts++ }})
	valid := servers.ReorderItem{ChannelID: first.ID, Position: 20}
	unknown := uuid.NewString()
	cases := []struct {
		name  string
		items []servers.ReorderItem
	}{
		{"missing later channel", []servers.ReorderItem{valid, {ChannelID: unknown, Position: 21}}},
		{"foreign later channel", []servers.ReorderItem{valid, {ChannelID: foreign.ID, Position: 21}}},
		{"duplicate", []servers.ReorderItem{valid, valid}},
		{"negative", []servers.ReorderItem{valid, {ChannelID: second.ID, Position: -1}}},
		{"wrong category type", []servers.ReorderItem{valid, {ChannelID: second.ID, Position: 21, CategoryID: &first.ID}}},
		{"foreign category", []servers.ReorderItem{valid, {ChannelID: second.ID, Position: 21, CategoryID: &foreign.ID}}},
		{"self category", []servers.ReorderItem{valid, {ChannelID: category.ID, Position: 21, CategoryID: &category.ID}}},
		{"conflicting clear", []servers.ReorderItem{valid, {ChannelID: second.ID, Position: 21, CategoryID: &category.ID, ClearCategory: true}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := service.ReorderChannels(ctx, server.ID, owner.ID, test.items); err == nil {
				t.Fatal("accepted invalid batch")
			}
			got, err := database.GetChannel(ctx, first.ID)
			if err != nil || got.Position != first.Position || got.CategoryID != nil {
				t.Fatalf("partial reorder: %+v err=%v", got, err)
			}
			if broadcasts != 0 {
				t.Fatalf("broadcast rejected batch: %d", broadcasts)
			}
		})
	}
	manager := newChannelOwner(t, database, ctx)
	if err := database.AddServerMember(ctx, server.ID, manager.ID); err != nil {
		t.Fatal(err)
	}
	role, err := database.CreateRole(ctx, server.ID, "channel-manager", db.PermManageChannels, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AssignRole(ctx, server.ID, manager.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{ChannelID: second.ID, TargetID: manager.ID, TargetType: db.ChannelOverwriteUser, Deny: db.PermManageChannels}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderChannels(ctx, server.ID, manager.ID, []servers.ReorderItem{valid, {ChannelID: second.ID, Position: 21}}); err == nil {
		t.Fatal("accepted denied later item")
	}
	gotAfterDenied, err := database.GetChannel(ctx, first.ID)
	if err != nil || gotAfterDenied.Position != first.Position || broadcasts != 0 {
		t.Fatalf("ACL failure partially applied: %+v broadcasts=%d err=%v", gotAfterDenied, broadcasts, err)
	}
	// The DB entry point must also enforce authority, rather than trusting the
	// service's preliminary check or a previous snapshot.
	if _, err := database.ReorderChannels(ctx, server.ID, manager.ID, []db.ChannelReorderItem{{ChannelID: second.ID, Position: 21}}); err == nil {
		t.Fatal("DB bypassed current channel ACL")
	}
	// Force a failure during the second actual write, after validation passed.
	if _, err := database.Pool.Exec(ctx, `CREATE FUNCTION reject_second_reorder() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.name='second' THEN RAISE EXCEPTION 'forced regression rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_second_reorder BEFORE UPDATE OF position ON channels FOR EACH ROW EXECUTE FUNCTION reject_second_reorder()`); err != nil {
		t.Fatal(err)
	}
	if err := service.ReorderChannels(ctx, server.ID, owner.ID, []servers.ReorderItem{valid, {ChannelID: second.ID, Position: 21}}); err == nil {
		t.Fatal("expected write failure")
	}
	got, err := database.GetChannel(ctx, first.ID)
	if err != nil || got.Position != first.Position || broadcasts != 0 {
		t.Fatalf("failed transaction leaked: %+v broadcasts=%d err=%v", got, broadcasts, err)
	}
	if _, err := database.Pool.Exec(ctx, `DROP TRIGGER reject_second_reorder ON channels; DROP FUNCTION reject_second_reorder()`); err != nil {
		t.Fatal(err)
	}
	service = servers.NewService(database, channelBroadcastProbe{check: func(*pb.Envelope) {
		broadcasts++
		for _, id := range []string{first.ID, second.ID} {
			ch, err := database.GetChannel(ctx, id)
			if err != nil || ch.CategoryID == nil || *ch.CategoryID != category.ID || ch.Position < 20 {
				t.Fatalf("broadcast before entire batch commit: %+v err=%v", ch, err)
			}
		}
	}})
	if err := service.ReorderChannels(ctx, server.ID, owner.ID, []servers.ReorderItem{{ChannelID: first.ID, Position: 20, CategoryID: &category.ID}, {ChannelID: second.ID, Position: 21, CategoryID: &category.ID}}); err != nil {
		t.Fatal(err)
	}
	if broadcasts != 2 {
		t.Fatalf("broadcasts=%d", broadcasts)
	}
	if err := database.DeleteChannel(ctx, category.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ID, second.ID} {
		ch, err := database.GetChannel(ctx, id)
		if err != nil || ch.CategoryID != nil {
			t.Fatalf("category delete left dangling child: %+v err=%v", ch, err)
		}
	}
	// Opposite caller order must produce two complete batches without a lock
	// cycle. A bounded retry reruns all validation on serialization conflicts.
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, batch := range [][]db.ChannelReorderItem{
		{{ChannelID: first.ID, Position: 30}, {ChannelID: second.ID, Position: 31}},
		{{ChannelID: second.ID, Position: 41}, {ChannelID: first.ID, Position: 40}},
	} {
		wg.Add(1)
		go func(items []db.ChannelReorderItem) {
			defer wg.Done()
			<-start
			_, err := database.ReorderChannels(ctx, server.ID, owner.ID, items)
			results <- err
		}(batch)
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := database.GetChannel(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := database.GetChannel(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !((a.Position == 30 && b.Position == 31) || (a.Position == 40 && b.Position == 41)) {
		t.Fatalf("mixed concurrent batches: %d,%d", a.Position, b.Position)
	}
}
