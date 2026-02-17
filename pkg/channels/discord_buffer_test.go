package channels

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
)

func TestDiscordBuffer_Triggers(t *testing.T) {
	// Setup
	msgBus := bus.NewMessageBus()
	cfg := config.DiscordConfig{Token: "test", AllowFrom: []string{"user1"}}
	
	// Mock session state
	session, _ := discordgo.New("Bot test")
	session.State.User = &discordgo.User{
		ID: "bot_id",
	}
	
	// Create base channel manually to avoid Discord connection
	base := NewBaseChannel("discord", cfg, msgBus, cfg.AllowFrom)
	channel := &DiscordChannel{
		BaseChannel: base,
		session:     session,
		config:      cfg,
		ctx:         context.Background(),
	}
	// Init internal maps
	channel.setRunning(true)

	// Override params for test
	bufferTriggerCount = 5
	bufferPruneCount = 3
	keywordWaitTime = 100 * time.Millisecond
	
	buffer := NewDiscordChannelBuffer("channel1", channel)

	t.Run("Mention Trigger", func(t *testing.T) {
		// Prepare listener
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		
		received := make(chan bus.InboundMessage, 1)
		go func() {
			msg, ok := msgBus.ConsumeInbound(ctx)
			if ok {
				received <- msg
			}
		}()

		// Send Mention
		m := &discordgo.MessageCreate{
			Message: &discordgo.Message{
				ID:        "msg1",
				ChannelID: "channel1",
				GuildID:   "guild1",
				Author:    &discordgo.User{ID: "user1", Username: "User1"},
				Content:   "Hello @Bot",
				Mentions:  []*discordgo.User{{ID: "bot_id"}},
				Timestamp: time.Now(),
			},
		}
		buffer.AddMessage(m, "Hello @Bot", nil)

		select {
		case msg := <-received:
			if msg.Metadata["priority"] != "true" {
				t.Errorf("Expected priority true, got %s", msg.Metadata["priority"])
			}
			if len(buffer.messages) != 1-bufferPruneCount && len(buffer.messages) != 0 {
				// 1 message added, triggered immediately -> prune 3 -> 0 left
				t.Errorf("Expected buffer empty or pruned, got len %d", len(buffer.messages))
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for trigger")
		}
	})

	t.Run("Keyword Trigger", func(t *testing.T) {
		// Reset buffer
		buffer.messages = make([]BufferedMessage, 0)
		
		received := make(chan bus.InboundMessage, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msg, ok := msgBus.ConsumeInbound(ctx)
					if ok {
						received <- msg
						return
					}
				}
			}
		}()

		// Send Keyword
		m := &discordgo.MessageCreate{
			Message: &discordgo.Message{
				ID:        "msg2",
				ChannelID: "channel1",
				GuildID:   "guild1",
				Author:    &discordgo.User{ID: "user1", Username: "User1"},
				Content:   "pipi help",
				Timestamp: time.Now(),
			},
		}
		buffer.AddMessage(m, "pipi help", nil)

		// Should NOT trigger immediately
		select {
		case <-received:
			t.Fatal("Triggered too early")
		case <-time.After(50 * time.Millisecond):
			// Good
		}

		// Wait for timeout
		select {
		case msg := <-received:
			if msg.Metadata["priority"] != "true" {
				t.Errorf("Expected priority true for keyword, got %s", msg.Metadata["priority"])
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("Timeout waiting for keyword trigger")
		}
	})

	t.Run("Passive Trigger", func(t *testing.T) {
		// Reset buffer
		buffer.messages = make([]BufferedMessage, 0)
		
		received := make(chan bus.InboundMessage, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msg, ok := msgBus.ConsumeInbound(ctx)
					if ok {
						received <- msg
						return
					}
				}
			}
		}()

		// Send messages up to trigger count (5)
		for i := 0; i < 5; i++ {
			m := &discordgo.MessageCreate{
				Message: &discordgo.Message{
					ID:        "msg_passive",
					ChannelID: "channel1",
					GuildID:   "guild1",
					Author:    &discordgo.User{ID: "user1", Username: "User1"},
					Content:   "chat",
					Timestamp: time.Now(),
				},
			}
			buffer.AddMessage(m, "chat", nil)
		}

		select {
		case msg := <-received:
			if msg.Metadata["priority"] != "false" {
				t.Errorf("Expected priority false for passive, got %s", msg.Metadata["priority"])
			}
			// Verify prune
			// 5 messages -> Trigger -> Prune 3 -> 2 left
			if len(buffer.messages) != 2 {
				t.Errorf("Expected 2 messages left, got %d", len(buffer.messages))
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for passive trigger")
		}
	})
	
	t.Run("Keyword Reset", func(t *testing.T) {
		// Send keyword -> Start Timer
		// Send normal -> Reset Timer
		
		// Reset buffer
		buffer.messages = make([]BufferedMessage, 0)
		buffer.keywordTimer = nil

		received := make(chan bus.InboundMessage, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msg, ok := msgBus.ConsumeInbound(ctx)
					if ok {
						received <- msg
						return
					}
				}
			}
		}()

		// 1. Send Keyword "pipi"
		m1 := &discordgo.MessageCreate{
			Message: &discordgo.Message{Author: &discordgo.User{ID: "user1", Username: "U1"}, Content: "pipi", Timestamp: time.Now()},
		}
		buffer.AddMessage(m1, "pipi", nil)
		
		// Wait 50ms (half of 100ms timeout)
		time.Sleep(50 * time.Millisecond)
		
		// 2. Send Normal Message
		m2 := &discordgo.MessageCreate{
			Message: &discordgo.Message{Author: &discordgo.User{ID: "user1", Username: "U1"}, Content: "normal", Timestamp: time.Now()},
		}
		buffer.AddMessage(m2, "normal", nil)
		
		// Timer should reset to another 100ms. 
		// Original timer would fire at T+100ms.
		// New timer fires at T+50ms+100ms = T+150ms.
		
		// If we wait another 150ms (Total ~200ms), original timer would have fired.
		// But since reset, it shouldn't fire yet.
		
		select {
		case <-received:
			t.Fatal("Timer did not reset!")
		case <-time.After(60 * time.Millisecond):
			// Good, verify it fires later
			t.Log("Timer correctly did not fire early")
		}
		
		select {
		case <-received:
			// Good
			t.Log("Timer fired successfully after reset")
		case <-time.After(200 * time.Millisecond):
			// Debug buffer state
			t.Logf("Buffer state: Timer=%v Messages=%d", buffer.keywordTimer, len(buffer.messages))
			t.Fatal("Timer never fired after reset")
		}
	})
	t.Run("Reply Content", func(t *testing.T) {
		// Reset buffer
		buffer.messages = make([]BufferedMessage, 0)
		
		received := make(chan bus.InboundMessage, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msg, ok := msgBus.ConsumeInbound(ctx)
					if ok {
						received <- msg
						return
					}
				}
			}
		}()

		// Message with Reply
		refMsg := &discordgo.Message{
			Author: &discordgo.User{Username: "OriginalUser"},
			Content: "This is the original message",
		}
		m := &discordgo.MessageCreate{
			Message: &discordgo.Message{
				ID:        "msg_reply",
				ChannelID: "channel1",
				GuildID:   "guild1",
				Author:    &discordgo.User{ID: "user1", Username: "User1"},
				Content:   "I agree @Bot",
				Mentions:  []*discordgo.User{{ID: "bot_id"}}, // Trigger immediately
				ReferencedMessage: refMsg,
				Timestamp: time.Now(),
			},
		}
		buffer.AddMessage(m, "I agree @Bot", nil)

		select {
		case msg := <-received:
			// Check content for reply format
			expected := `[Replying to OriginalUser: "This is the original message"] I agree @Bot`
			if !strings.Contains(msg.Content, expected) {
				t.Errorf("Expected content to contain reply quote. Got:\n%s", msg.Content)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for reply trigger")
		}
	})
}
