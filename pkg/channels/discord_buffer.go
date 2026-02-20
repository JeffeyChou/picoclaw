package channels

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/sipeed/picoclaw/pkg/logger"
)

var (
	bufferTriggerCount = 13
	keywordWaitTime    = 5 * time.Second
)

type BufferedMessage struct {
	*discordgo.MessageCreate
	Content string // Can be modified (e.g. attachments appended)
	Media   []string
}

type DiscordChannelBuffer struct {
	channelID    string
	messages     []BufferedMessage
	mutex        sync.Mutex
	parent       *DiscordChannel
	keywordTimer *time.Timer
}

func NewDiscordChannelBuffer(channelID string, parent *DiscordChannel) *DiscordChannelBuffer {
	return &DiscordChannelBuffer{
		channelID: channelID,
		messages:  make([]BufferedMessage, 0),
		parent:    parent,
	}
}

func (b *DiscordChannelBuffer) AddMessage(m *discordgo.MessageCreate, content string, media []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// 1. Add to buffer
	b.messages = append(b.messages, BufferedMessage{
		MessageCreate: m,
		Content:       content,
		Media:         media,
	})

	// 2. Check Triggers

	// A. Direct Mention (@Bot) - Immediate
	if b.isMentioned(m) {
		logger.DebugCF("discord", "Trigger: Mention", map[string]any{"channel": b.channelID, "user": m.Author.Username})
		b.triggerFunction(true) // High priority
		return
	}

	// B. Keywords - Delayed (5s)
	if b.hasKeyword(content) {
		logger.DebugCF("discord", "Trigger: Keyword detected", map[string]any{"channel": b.channelID, "keyword": content})
		if b.keywordTimer != nil {
			b.keywordTimer.Stop()
		}
		b.keywordTimer = time.AfterFunc(keywordWaitTime, func() {
			b.mutex.Lock()
			defer b.mutex.Unlock()
			b.keywordTimer = nil
			logger.DebugCF("discord", "Trigger: Keyword timeout", map[string]any{"channel": b.channelID})
			b.triggerFunction(true) // Treat keyword as high priority (it's an explicit call)
		})
		return
	}

	if b.keywordTimer != nil {
		b.keywordTimer.Stop()
		b.keywordTimer = time.AfterFunc(keywordWaitTime, func() {
			b.mutex.Lock()
			defer b.mutex.Unlock()
			b.keywordTimer = nil
			logger.DebugCF("discord", "Trigger: Keyword timeout (reset)", map[string]any{"channel": b.channelID})
			b.triggerFunction(true)
		})
	}

	// C. Passive Count - "Judge"
	// Only trigger if no keyword timer is pending
	if b.keywordTimer == nil && len(b.messages) >= bufferTriggerCount {
		logger.DebugCF("discord", "Trigger: Buffer full", map[string]any{"channel": b.channelID, "count": len(b.messages)})
		b.triggerFunction(false) // Low priority, let LLM judge
	}
}

func (b *DiscordChannelBuffer) isMentioned(m *discordgo.MessageCreate) bool {
	// Check direct mentions
	for _, user := range m.Mentions {
		if user.ID == b.parent.session.State.User.ID {
			return true
		}
	}
	// Check if this is a reply to the bot
	if m.ReferencedMessage != nil && m.ReferencedMessage.Author != nil {
		if m.ReferencedMessage.Author.ID == b.parent.session.State.User.ID {
			return true
		}
	}
	return false
}

func (b *DiscordChannelBuffer) hasKeyword(content string) bool {
	lower := strings.ToLower(content)
	keywords := []string{"pipi", "派派"}
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// triggerFunction constructs the aggregated message and calls the parent.
// priority: true for Mentions/Keywords (force reply), false for Passive (judge).
func (b *DiscordChannelBuffer) triggerFunction(priority bool) {
	if len(b.messages) == 0 {
		return
	}

	// Construct Aggregated Content
	var sb strings.Builder

	var aggregatedMedia []string

	// We send ALL currently buffered messages to the LLM for context
	for _, msg := range b.messages {
		timestamp := msg.Timestamp.Format("15:04:05")

		content := msg.Content
		if msg.ReferencedMessage != nil {
			refAuthor := "Unknown"
			if msg.ReferencedMessage.Author != nil {
				refAuthor = msg.ReferencedMessage.Author.Username
			}
			refContent := msg.ReferencedMessage.Content
			// Check if the referenced content itself contains a reply to someone else
			replyPrefix := "[Replying to "
			if strings.Count(refContent, replyPrefix) > 1 {
				firstIdx := strings.Index(refContent, replyPrefix)
				secondIdx := strings.Index(refContent[firstIdx+len(replyPrefix):], replyPrefix)
				if secondIdx != -1 {
					secondIdx += firstIdx + len(replyPrefix)
					closeIdx := strings.Index(refContent[secondIdx:], "] ")
					if closeIdx != -1 {
						closeIdx += secondIdx
						refContent = refContent[:secondIdx] + "[引用内容已省略] " + refContent[closeIdx+2:]
					}
				}
			}

			if len(refContent) > 50 {
				refContent = refContent[:47] + "..."
			}
			content = fmt.Sprintf("[Replying to %s: %q] %s", refAuthor, refContent, msg.Content)
		}

		// Format: [Time] User: Content
		sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", timestamp, msg.Author.Username, content))

		if len(msg.Media) > 0 {
			aggregatedMedia = append(aggregatedMedia, msg.Media...)
		}
	}

	finalContent := sb.String()
	if !priority {
		finalContent += "\n\n(System: This is a generic chat log check. If this conversation does not require your intervention, reply with exactly [NO_REPLY]. Do not reply with 'I have no comment'.)"
	}

	// Use the LAST message's metadata for the "Trigger" event
	lastMsg := b.messages[len(b.messages)-1]

	metadata := map[string]string{
		"message_id":    lastMsg.ID,
		"user_id":       lastMsg.Author.ID,
		"username":      lastMsg.Author.Username,
		"channel_id":    b.channelID,
		"guild_id":      lastMsg.GuildID,
		"is_aggregated": "true",
		"priority":      fmt.Sprintf("%t", priority),
	}

	// Call Parent
	b.parent.HandleMessage(lastMsg.Author.ID, b.channelID, finalContent, aggregatedMedia, metadata)

	// Prune buffer completely to avoid duplicates
	b.Prune(len(b.messages))
}

func (b *DiscordChannelBuffer) Prune(count int) {
	if count > len(b.messages) {
		count = len(b.messages)
	}
	b.messages = b.messages[count:]
}
