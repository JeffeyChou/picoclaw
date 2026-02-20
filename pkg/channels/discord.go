package channels

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/utils"
	"github.com/sipeed/picoclaw/pkg/voice"
)

const (
	transcriptionTimeout = 30 * time.Second
	sendTimeout          = 10 * time.Second
)

type DiscordChannel struct {
	*BaseChannel
	session        *discordgo.Session
	config         config.DiscordConfig
	transcriber    *voice.GroqTranscriber
	ctx            context.Context
	typingMap      sync.Map // Stores cancel functions for typing loops: map[channelID]context.CancelFunc
	lastMessageMap sync.Map // Stores last user message ID for reaction: map[channelID]string
	buffers        sync.Map // Stores channel buffers: map[channelID]*DiscordChannelBuffer
}

func NewDiscordChannel(cfg config.DiscordConfig, bus *bus.MessageBus) (*DiscordChannel, error) {
	session, err := discordgo.New("Bot " + cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create discord session: %w", err)
	}

	base := NewBaseChannel("discord", cfg, bus, cfg.AllowFrom)
	base.SetAllowedChannels(cfg.AllowedChannels)

	return &DiscordChannel{
		BaseChannel: base,
		session:     session,
		config:      cfg,
		transcriber: nil,
		ctx:         context.Background(),
	}, nil
}

func (c *DiscordChannel) SetTranscriber(transcriber *voice.GroqTranscriber) {
	c.transcriber = transcriber
}

func (c *DiscordChannel) getContext() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

func (c *DiscordChannel) Start(ctx context.Context) error {
	logger.InfoC("discord", "Starting Discord bot")

	c.ctx = ctx
	c.session.AddHandler(c.handleMessage)
	c.session.AddHandler(c.handleInteraction)

	if err := c.session.Open(); err != nil {
		return fmt.Errorf("failed to open discord session: %w", err)
	}

	c.registerCommands()

	c.setRunning(true)

	botUser, err := c.session.User("@me")
	if err != nil {
		return fmt.Errorf("failed to get bot user: %w", err)
	}
	logger.InfoCF("discord", "Discord bot connected", map[string]any{
		"username": botUser.Username,
		"user_id":  botUser.ID,
	})

	return nil
}

func (c *DiscordChannel) Stop(ctx context.Context) error {
	logger.InfoC("discord", "Stopping Discord bot")
	c.setRunning(false)

	if err := c.session.Close(); err != nil {
		return fmt.Errorf("failed to close discord session: %w", err)
	}

	return nil
}

func (c *DiscordChannel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("discord bot not running")
	}

	channelID := msg.ChatID
	if channelID == "" {
		return fmt.Errorf("channel ID is empty")
	}

	// Parse and handle [REACT:emoji] command
	if strings.Contains(msg.Content, "[REACT:") {
		start := strings.Index(msg.Content, "[REACT:")
		end := strings.Index(msg.Content[start:], "]")
		if end != -1 {
			end += start
			command := msg.Content[start : end+1]
			emoji := strings.TrimSuffix(strings.TrimPrefix(command, "[REACT:"), "]")

			// Find the last message to react to
			if lastMsgID, ok := c.lastMessageMap.Load(channelID); ok {
				if err := c.session.MessageReactionAdd(channelID, lastMsgID.(string), emoji); err != nil {
					logger.WarnCF("discord", "Failed to add agent reaction", map[string]any{
						"emoji": emoji,
						"error": err.Error(),
					})
				}
			}

			// Remove command from content
			msg.Content = strings.Replace(msg.Content, command, "", 1)
			msg.Content = strings.TrimSpace(msg.Content)

			// If content is empty after removing command, return
			if msg.Content == "" {
				return nil
			}
		}
	}

	runes := []rune(msg.Content)
	if len(runes) == 0 {
		return nil
	}

	// [NO_REPLY] handling
	if strings.Contains(msg.Content, "[NO_REPLY]") {
		logger.InfoCF("discord", "Agent decided not to reply", map[string]any{
			"channel_id": channelID,
		})
		return nil
	}

	// Suppress error messages in Group Chats to avoid spam
	if strings.Contains(msg.Content, "Error processing message") || strings.Contains(msg.Content, "API request failed") {
		// Check if it's a group chat (has buffer or GuildID check)
		if _, ok := c.buffers.Load(channelID); ok {
			logger.InfoCF("discord", "Suppressed error message in group chat", map[string]any{
				"channel_id": channelID,
				"error":      utils.Truncate(msg.Content, 50),
			})
			return nil
		}
	}

	// Suppress "Memory threshold reached" in Group Chats
	if strings.Contains(msg.Content, "⚠️ Memory threshold reached") {
		// Check if it's a group chat (has buffer or GuildID check)
		// We trust c.buffers map as it only stores group channels
		if _, ok := c.buffers.Load(channelID); ok {
			logger.InfoCF("discord", "Suppressed memory warning in group chat", map[string]any{
				"channel_id": channelID,
			})
			return nil
		}
	}

	// Handle mentions by prepending to content
	if len(msg.MentionUserIDs) > 0 {
		var mentions []string
		for _, uid := range msg.MentionUserIDs {
			mentions = append(mentions, fmt.Sprintf("<@%s>", uid))
		}
		msg.Content = strings.Join(mentions, " ") + " " + msg.Content
	}

	chunks := splitMessage(msg.Content, 1500) // Discord has a limit of 2000 characters per message, leave 500 for natural split e.g. code blocks

	// Stop typing indicator if running
	if cancel, ok := c.typingMap.LoadAndDelete(channelID); ok {
		cancel.(context.CancelFunc)()
	}

	// Resolve reply reference
	var replyReference *discordgo.MessageReference
	if msg.ReplyToID != "" {
		targetID := msg.ReplyToID
		if targetID == "last" {
			if lastID, ok := c.lastMessageMap.Load(channelID); ok {
				targetID = lastID.(string)
			} else {
				targetID = "" // No last message to reply to
			}
		}

		if targetID != "" {
			replyReference = &discordgo.MessageReference{
				MessageID: targetID,
				ChannelID: channelID,
				GuildID:   "", // Optional usually
			}
		}
	}

	for i, chunk := range chunks {
		// Only attach reply reference to the first chunk
		var ref *discordgo.MessageReference
		if i == 0 {
			ref = replyReference
		}

		if err := c.sendChunk(ctx, channelID, chunk, ref); err != nil {
			return err
		}
	}

	return nil
}

func (c *DiscordChannel) Reaction(ctx context.Context, chatID, messageID, emoji string) error {
	if !c.IsRunning() {
		return fmt.Errorf("discord bot not running")
	}

	// If messageID is empty or "last", try to find the last message ID for this channel
	targetMsgID := messageID
	if targetMsgID == "" || targetMsgID == "last" {
		if lastID, ok := c.lastMessageMap.Load(chatID); ok {
			targetMsgID = lastID.(string)
		} else {
			return fmt.Errorf("no last message found for channel %s", chatID)
		}
	}

	if err := c.session.MessageReactionAdd(chatID, targetMsgID, emoji); err != nil {
		return fmt.Errorf("failed to add reaction: %w", err)
	}

	return nil
}

// splitMessage splits long messages into chunks, preserving code block integrity
// Uses natural boundaries (newlines, spaces) and extends messages slightly to avoid breaking code blocks
func splitMessage(content string, limit int) []string {
	var messages []string

	for len(content) > 0 {
		if len(content) <= limit {
			messages = append(messages, content)
			break
		}

		msgEnd := limit

		// Find natural split point within the limit
		msgEnd = findLastNewline(content[:limit], 200)
		if msgEnd <= 0 {
			msgEnd = findLastSpace(content[:limit], 100)
		}
		if msgEnd <= 0 {
			msgEnd = limit
		}

		// Check if this would end with an incomplete code block
		candidate := content[:msgEnd]
		unclosedIdx := findLastUnclosedCodeBlock(candidate)

		if unclosedIdx >= 0 {
			// Message would end with incomplete code block
			// Try to extend to include the closing ``` (with some buffer)
			extendedLimit := limit + 500 // Allow 500 char buffer for code blocks
			if len(content) > extendedLimit {
				closingIdx := findNextClosingCodeBlock(content, msgEnd)
				if closingIdx > 0 && closingIdx <= extendedLimit {
					// Extend to include the closing ```
					msgEnd = closingIdx
				} else {
					// Can't find closing, split before the code block
					msgEnd = findLastNewline(content[:unclosedIdx], 200)
					if msgEnd <= 0 {
						msgEnd = findLastSpace(content[:unclosedIdx], 100)
					}
					if msgEnd <= 0 {
						msgEnd = unclosedIdx
					}
				}
			} else {
				// Remaining content fits within extended limit
				msgEnd = len(content)
			}
		}

		if msgEnd <= 0 {
			msgEnd = limit
		}

		messages = append(messages, content[:msgEnd])
		content = strings.TrimSpace(content[msgEnd:])
	}

	return messages
}

// findLastUnclosedCodeBlock finds the last opening ``` that doesn't have a closing ```
// Returns the position of the opening ``` or -1 if all code blocks are complete
func findLastUnclosedCodeBlock(text string) int {
	count := 0
	lastOpenIdx := -1

	for i := 0; i < len(text); i++ {
		if i+2 < len(text) && text[i] == '`' && text[i+1] == '`' && text[i+2] == '`' {
			if count == 0 {
				lastOpenIdx = i
			}
			count++
			i += 2
		}
	}

	// If odd number of ``` markers, last one is unclosed
	if count%2 == 1 {
		return lastOpenIdx
	}
	return -1
}

// findNextClosingCodeBlock finds the next closing ``` starting from a position
// Returns the position after the closing ``` or -1 if not found
func findNextClosingCodeBlock(text string, startIdx int) int {
	for i := startIdx; i < len(text); i++ {
		if i+2 < len(text) && text[i] == '`' && text[i+1] == '`' && text[i+2] == '`' {
			return i + 3
		}
	}
	return -1
}

// findLastNewline finds the last newline character within the last N characters
// Returns the position of the newline or -1 if not found
func findLastNewline(s string, searchWindow int) int {
	searchStart := len(s) - searchWindow
	if searchStart < 0 {
		searchStart = 0
	}
	for i := len(s) - 1; i >= searchStart; i-- {
		if s[i] == '\n' {
			return i
		}
	}
	return -1
}

// findLastSpace finds the last space character within the last N characters
// Returns the position of the space or -1 if not found
func findLastSpace(s string, searchWindow int) int {
	searchStart := len(s) - searchWindow
	if searchStart < 0 {
		searchStart = 0
	}
	for i := len(s) - 1; i >= searchStart; i-- {
		if s[i] == ' ' || s[i] == '\t' {
			return i
		}
	}
	return -1
}

func (c *DiscordChannel) sendChunk(ctx context.Context, channelID, content string, replyTo *discordgo.MessageReference) error {
	// 使用传入的 ctx 进行超时控制
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var err error
		if replyTo != nil {
			_, err = c.session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
				Content:   content,
				Reference: replyTo,
				// Default AllowedMentions usually allows calling out users we mention in content
			})
		} else {
			_, err = c.session.ChannelMessageSend(channelID, content)
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to send discord message: %w", err)
		}
		return nil
	case <-sendCtx.Done():
		return fmt.Errorf("send message timeout: %w", sendCtx.Err())
	}
}

// appendContent 安全地追加内容到现有文本
func appendContent(content, suffix string) string {
	if content == "" {
		return suffix
	}
	return content + "\n" + suffix
}

func (c *DiscordChannel) handleMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m == nil || m.Author == nil {
		return
	}

	if m.Author.ID == s.State.User.ID {
		return
	}

	// Check whitelist for channel ID
	if !c.IsChannelAllowed(m.ChannelID) {
		logger.DebugCF("discord", "Message rejected (channel not in whitelist)", map[string]any{
			"channel_id": m.ChannelID,
			"user_id":    m.Author.ID,
		})
		return
	}

	// 检查白名单，避免为被拒绝的用户下载附件和转录
	if !c.IsAllowed(m.Author.ID) {
		logger.DebugCF("discord", "Message rejected by allowlist", map[string]any{
			"user_id": m.Author.ID,
		})
		return
	}

	senderID := m.Author.ID
	senderName := m.Author.Username
	if m.Author.Discriminator != "" && m.Author.Discriminator != "0" {
		senderName += "#" + m.Author.Discriminator
	}

	content := m.Content
	mediaPaths := make([]string, 0, len(m.Attachments))
	localFiles := make([]string, 0, len(m.Attachments))

	// 确保临时文件在函数返回时被清理
	defer func() {
		for _, file := range localFiles {
			if err := os.Remove(file); err != nil {
				logger.DebugCF("discord", "Failed to cleanup temp file", map[string]any{
					"file":  file,
					"error": err.Error(),
				})
			}
		}
	}()

	for _, attachment := range m.Attachments {
		isAudio := utils.IsAudioFile(attachment.Filename, attachment.ContentType)

		if isAudio {
			localPath := c.downloadAttachment(attachment.URL, attachment.Filename)
			if localPath != "" {
				localFiles = append(localFiles, localPath)

				transcribedText := ""
				if c.transcriber != nil && c.transcriber.IsAvailable() {
					ctx, cancel := context.WithTimeout(c.getContext(), transcriptionTimeout)
					result, err := c.transcriber.Transcribe(ctx, localPath)
					cancel() // 立即释放context资源，避免在for循环中泄漏

					if err != nil {
						logger.ErrorCF("discord", "Voice transcription failed", map[string]any{
							"error": err.Error(),
						})
						transcribedText = fmt.Sprintf("[audio: %s (transcription failed)]", attachment.Filename)
					} else {
						transcribedText = fmt.Sprintf("[audio transcription: %s]", result.Text)
						logger.DebugCF("discord", "Audio transcribed successfully", map[string]any{
							"text": result.Text,
						})
					}
				} else {
					transcribedText = fmt.Sprintf("[audio: %s]", attachment.Filename)
				}

				content = appendContent(content, transcribedText)
			} else {
				logger.WarnCF("discord", "Failed to download audio attachment", map[string]any{
					"url":      attachment.URL,
					"filename": attachment.Filename,
				})
				mediaPaths = append(mediaPaths, attachment.URL)
				content = appendContent(content, fmt.Sprintf("[attachment: %s]", attachment.URL))
			}
		} else {
			isImage := strings.HasPrefix(strings.ToLower(attachment.ContentType), "image/")
			isPDF := strings.HasSuffix(strings.ToLower(attachment.Filename), ".pdf")

			if isImage {
				mediaPaths = append(mediaPaths, attachment.URL)
				content = appendContent(content, fmt.Sprintf("[image attachment: %s]", attachment.URL))
			} else if isPDF {
				localPath := c.downloadAttachment(attachment.URL, attachment.Filename)
				if localPath != "" {
					localFiles = append(localFiles, localPath)
					cmd := exec.Command("python3", "/home/ubuntu/.picoclaw/workspace/scripts/pdf_parser.py", localPath)
					output, err := cmd.CombinedOutput()
					if err == nil {
						text := string(output)
						if len(text) > 20000 {
							text = text[:20000] + "...\n[Text truncated due to length]"
						}
						content = appendContent(content, fmt.Sprintf("[PDF attachment (%s)]:\n%s", attachment.Filename, strings.TrimSpace(text)))
					} else {
						logger.WarnCF("discord", "Failed to parse pdf attachment", map[string]any{
							"error":  err.Error(),
							"output": string(output),
						})
						content = appendContent(content, fmt.Sprintf("[file attachment (%s): %s]", attachment.Filename, attachment.URL))
					}
				} else {
					content = appendContent(content, fmt.Sprintf("[file attachment (%s): %s]", attachment.Filename, attachment.URL))
				}
			} else {
				// Don't add to mediaPaths so it isn't parsed as a Vision API image_url payload
				content = appendContent(content, fmt.Sprintf("[file attachment (%s): %s]", attachment.Filename, attachment.URL))
			}
		}
	}

	if content == "" && len(mediaPaths) == 0 {
		return
	}

	if content == "" {
		content = "[media only]"
	}

	logger.DebugCF("discord", "Received message", map[string]any{
		"sender_name": senderName,
		"sender_id":   senderID,
		"preview":     utils.Truncate(content, 50),
	})

	// Store message ID for future reactions
	c.lastMessageMap.Store(m.ChannelID, m.ID)

	// Only react in DMs (GuildID == "") or specific private channel
	isPrivateChannel := m.GuildID == ""
	if !isPrivateChannel {
		for _, pc := range c.config.PrivateChannels {
			if m.ChannelID == pc {
				isPrivateChannel = true
				break
			}
		}
	}

	if isPrivateChannel {
		go func() {
			if err := s.MessageReactionAdd(m.ChannelID, m.ID, "👀"); err != nil {
				logger.WarnCF("discord", "Failed to add reaction", map[string]any{"error": err.Error()})
			}
		}()
	}

	// 2. Start persistent typing loop
	if isPrivateChannel {
		c.startTypingLoop(m.ChannelID)
	}

	metadata := map[string]string{
		"message_id":   m.ID,
		"user_id":      senderID,
		"username":     m.Author.Username,
		"display_name": senderName,
		"guild_id":     m.GuildID,
		"channel_id":   m.ChannelID,
		"is_dm":        fmt.Sprintf("%t", m.GuildID == ""),
	}

	if isPrivateChannel {
		c.HandleMessage(senderID, m.ChannelID, content, mediaPaths, metadata)
	} else {
		// Group chat buffering
		val, _ := c.buffers.LoadOrStore(m.ChannelID, NewDiscordChannelBuffer(m.ChannelID, c))
		buffer := val.(*DiscordChannelBuffer)
		buffer.AddMessage(m, content, mediaPaths)
	}
}

func (c *DiscordChannel) downloadAttachment(url, filename string) string {
	return utils.DownloadFile(url, filename, utils.DownloadOptions{
		LoggerPrefix: "discord",
	})
}

// startTypingLoop starts a persistent typing indicator for the channel.
// It refreshes every 8 seconds (Discord typing lasts ~10s).
// It stops when c.Send() is called or after a hard timeout.
func (c *DiscordChannel) startTypingLoop(channelID string) {
	// Cancel previous loop if exists
	if cancel, ok := c.typingMap.Load(channelID); ok {
		cancel.(context.CancelFunc)()
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.typingMap.Store(channelID, cancel)

	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		defer cancel() // Ensure cleanup

		// Initial typing
		_ = c.session.ChannelTyping(channelID)

		// Hard timeout to prevent infinite typing
		timeout := time.After(300 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return
			case <-timeout:
				c.typingMap.Delete(channelID)
				return
			case <-ticker.C:
				if err := c.session.ChannelTyping(channelID); err != nil {
					logger.WarnCF("discord", "Failed to send typing", map[string]any{"error": err.Error()})
					// If we can't send typing (e.g. network issue), maybe we should stop?
					// For now, keep trying until timeout or done.
				}
			}
		}
	}()
}
func (c *DiscordChannel) registerCommands() {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "status",
			Description: "Get the service status and the last 30 lines of logs",
		},
		{
			Name:        "restart",
			Description: "Restart the picoclaw service",
		},
	}

	validCommands := make(map[string]bool)
	for _, v := range commands {
		validCommands[v.Name] = true
	}

	// 1. Clean up old Global commands
	if existingGlobal, err := c.session.ApplicationCommands(c.session.State.User.ID, ""); err == nil {
		for _, cmd := range existingGlobal {
			if !validCommands[cmd.Name] {
				c.session.ApplicationCommandDelete(c.session.State.User.ID, "", cmd.ID)
				logger.InfoCF("discord", "Deleted old global command", map[string]any{"name": cmd.Name})
			}
		}
	}

	// 2. Clean up old Guild commands
	for _, guild := range c.session.State.Guilds {
		if existingGuild, err := c.session.ApplicationCommands(c.session.State.User.ID, guild.ID); err == nil {
			for _, cmd := range existingGuild {
				if !validCommands[cmd.Name] {
					c.session.ApplicationCommandDelete(c.session.State.User.ID, guild.ID, cmd.ID)
					logger.InfoCF("discord", "Deleted old guild command", map[string]any{"name": cmd.Name, "guild_id": guild.ID})
				}
			}
		}
	}

	for _, v := range commands {
		// 1. Register Global (can take up to 1 hour)
		_, err := c.session.ApplicationCommandCreate(c.session.State.User.ID, "", v)
		if err != nil {
			logger.ErrorCF("discord", "Failed to create global application command", map[string]any{
				"name":  v.Name,
				"error": err.Error(),
			})
		} else {
			logger.InfoCF("discord", "Created global application command", map[string]any{
				"name": v.Name,
			})
		}

		// 2. Register for all Guilds (instant update)
		for _, guild := range c.session.State.Guilds {
			_, err := c.session.ApplicationCommandCreate(c.session.State.User.ID, guild.ID, v)
			if err != nil {
				logger.ErrorCF("discord", "Failed to create guild application command", map[string]any{
					"name":     v.Name,
					"guild_id": guild.ID,
					"error":    err.Error(),
				})
			} else {
				logger.InfoCF("discord", "Created guild application command", map[string]any{
					"name":     v.Name,
					"guild_id": guild.ID,
				})
			}
		}
	}
}

func (c *DiscordChannel) handleInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}

	data := i.ApplicationCommandData()
	if data.Name != "status" && data.Name != "restart" {
		return
	}

	// Determine User ID
	var userID string
	if i.Member != nil {
		userID = i.Member.User.ID
	} else if i.User != nil {
		userID = i.User.ID
	}

	// Check Permission
	if !c.IsAllowed(userID) {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "You are not authorized to use this command.",
				Flags:   discordgo.MessageFlagsEphemeral,
			},
		})
		return
	}

	// Permission check handled above
	_ = userID // Keep used indicator

	if data.Name == "restart" {
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "🔄 Restarting picoclaw service... Please wait.",
			},
		})

		if err != nil {
			logger.ErrorCF("discord", "Failed to respond to restart interaction", map[string]any{"error": err.Error()})
		}

		go func() {
			time.Sleep(3 * time.Second)
			logger.InfoC("discord", "Executing service restart via slash command")
			exec.Command("sudo", "systemctl", "restart", "picoclaw").Run()
		}()
		return
	}

	// Defer response as log fetching might take some time
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})
	if err != nil {
		logger.ErrorCF("discord", "Failed to defer interaction response", map[string]any{"error": err.Error()})
		return
	}

	// Fetch status and logs
	statusCmd := exec.Command("systemctl", "is-active", "picoclaw")
	statusOutput, _ := statusCmd.CombinedOutput()
	serviceStatus := strings.TrimSpace(string(statusOutput))

	cmd := exec.Command("journalctl", "-u", "picoclaw", "-n", "30", "--no-pager")
	output, err := cmd.CombinedOutput()

	var content string
	if err != nil {
		content = fmt.Sprintf("Failed to fetch logs: %v\nStatus: %s\nOutput: %s", err, serviceStatus, string(output))
	} else {
		logText := string(output)
		if len(logText) > 1850 {
			logText = logText[len(logText)-1850:] // Keep the last 1850 chars
			logText = "... " + logText
		}

		emoji := "🟢"
		if serviceStatus != "active" {
			emoji = "🔴"
		}

		content = fmt.Sprintf("Service Status: %s **%s**\n\nLast 30 lines of logs:\n```\n%s\n```", emoji, serviceStatus, logText)
	}

	// Final check on length
	if len(content) > 2000 {
		content = content[:1997] + "..."
	}

	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
	if err != nil {
		logger.ErrorCF("discord", "Failed to edit interaction response", map[string]any{"error": err.Error()})
	}
}
