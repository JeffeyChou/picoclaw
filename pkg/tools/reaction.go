package tools

import (
	"context"
	"fmt"

	"github.com/sipeed/picoclaw/pkg/channels"
)

type ReactionTool struct {
	channelManager *channels.Manager
	channel        string
	chatID         string
}

func NewReactionTool() *ReactionTool {
	return &ReactionTool{}
}

func (t *ReactionTool) Name() string {
	return "reaction"
}

func (t *ReactionTool) Description() string {
	return "Send an emoji reaction to a message. " +
		"Args: emoji (string, required) - The emoji to react with (e.g., '👀', '👍' etc). " +
		"message_id (string, optional) - The message ID to react to. If empty or 'last', reacts to the last message."
}

func (t *ReactionTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"emoji": map[string]interface{}{
				"type":        "string",
				"description": "The emoji to react with",
			},
			"message_id": map[string]interface{}{
				"type":        "string",
				"description": "Optional: message ID to react to (default: last message)",
			},
		},
		"required": []string{"emoji"},
	}
}

func (t *ReactionTool) SetContext(channel, chatID string) {
	t.channel = channel
	t.chatID = chatID
}

func (t *ReactionTool) SetChannelManager(cm *channels.Manager) {
	t.channelManager = cm
}

func (t *ReactionTool) Execute(ctx context.Context, args map[string]interface{}) *ToolResult {
	if t.channelManager == nil {
		return ErrorResult("channel manager not initialized")
	}

	if t.channel == "" || t.chatID == "" {
		return ErrorResult("context not set (channel/chatID missing)")
	}

	emoji, ok := args["emoji"].(string)
	if !ok || emoji == "" {
		return ErrorResult("emoji argument is required")
	}

	messageID, _ := args["message_id"].(string)

	channel, ok := t.channelManager.GetChannel(t.channel)
	if !ok {
		return ErrorResult(fmt.Sprintf("channel %s not found", t.channel))
	}

	if err := channel.Reaction(ctx, t.chatID, messageID, emoji); err != nil {
		return ErrorResult(fmt.Sprintf("failed to send reaction: %v", err))
	}

	return UserResult(fmt.Sprintf("Reacted with %s", emoji))
}
