package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/providers"
	"github.com/sipeed/picoclaw/pkg/skills"
	"github.com/sipeed/picoclaw/pkg/tools"
)

type ContextBuilder struct {
	workspace    string
	model        string
	skillsLoader *skills.SkillsLoader
	memory       *MemoryStore
	tools        *tools.ToolRegistry // Direct reference to tool registry
}

func getGlobalConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".picoclaw")
}

func NewContextBuilder(workspace, model string) *ContextBuilder {
	// builtin skills: skills directory in current project
	// Use the skills/ directory under the current working directory
	wd, _ := os.Getwd()
	builtinSkillsDir := filepath.Join(wd, "skills")
	globalSkillsDir := filepath.Join(getGlobalConfigDir(), "skills")

	return &ContextBuilder{
		workspace:    workspace,
		model:        model,
		skillsLoader: skills.NewSkillsLoader(workspace, globalSkillsDir, builtinSkillsDir),
		memory:       NewMemoryStore(workspace),
	}
}

// SetToolsRegistry sets the tools registry for dynamic tool summary generation.
func (cb *ContextBuilder) SetToolsRegistry(registry *tools.ToolRegistry) {
	cb.tools = registry
}

func (cb *ContextBuilder) getIdentity() string {
	now := time.Now().Format("2006-01-02 15:04 (Monday)")
	workspacePath, _ := filepath.Abs(filepath.Join(cb.workspace))
	runtime := fmt.Sprintf("%s %s, Go %s", runtime.GOOS, runtime.GOARCH, runtime.Version())

	// Build tools section dynamically
	toolsSection := cb.buildToolsSection()

	return fmt.Sprintf(`# picoclaw 🦞

You are picoclaw, a helpful AI assistant.

## Current Time
%s

## Runtime
%s

## Workspace
Your workspace is at: %s
- Memory: %s/memory/MEMORY.md
- Daily Notes: %s/memory/YYYYMM/YYYYMMDD.md
- Skills: %s/skills/{skill-name}/SKILL.md
- Configuration:
  - Global: %s/[SOUL|IDENTITY|USER|AGENT].md
  - Channel Specific: %s/memory/[SOUL|IDENTITY|USER|AGENT].[channel].[chat_id].md (Highest Priority)

%s

## Important Rules

1. **ALWAYS use tools** - When you need to perform an action (schedule reminders, send messages, execute commands, etc.), you MUST call the appropriate tool. Do NOT just say you'll do it or pretend to do it.

2. **Be helpful and accurate** - When using tools, briefly explain what you're doing.

3. **Memory** - When remembering something, write to %s/memory/MEMORY.md

4. **Configuration** - If you need to modify your persona for a specific channel, create or edit the corresponding file in the memory directory (e.g., memory/SOUL.discord.123456.md).`,
		now, runtime, workspacePath, workspacePath, workspacePath, workspacePath, workspacePath, workspacePath, toolsSection, workspacePath)
}

func (cb *ContextBuilder) buildToolsSection() string {
	if cb.tools == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Available Tools\n\n")
	sb.WriteString("**CRITICAL**: You MUST use tools to perform actions. Do NOT pretend to execute commands or schedule tasks.\n\n")
	sb.WriteString("You have access to the following tools:\n\n")

	// If Grok model, use renamed tools
	isGrok := providers.IsGrokModel(cb.model)
	
	if isGrok {
		// Use provider defs to get descriptions, but apply renaming
		defs := cb.tools.ToProviderDefs()
		filtered := providers.FilterAndRenameGrokTools(defs)
		for _, def := range filtered {
			sb.WriteString(fmt.Sprintf("- `%s` - %s\n", def.Function.Name, def.Function.Description))
		}
	} else {
		// Standard behavior
		summaries := cb.tools.GetSummaries()
		for _, s := range summaries {
			sb.WriteString(s)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (cb *ContextBuilder) BuildSystemPrompt(channel, chatID string) string {
	parts := []string{}

	// Core identity section
	parts = append(parts, cb.getIdentity())

	// Bootstrap files
	bootstrapContent := cb.LoadBootstrapFiles(channel, chatID)
	if bootstrapContent != "" {
		parts = append(parts, bootstrapContent)
	}

	// Skills - show summary, AI can read full content with read_file tool
	skillsSummary := cb.skillsLoader.BuildSkillsSummary()
	if skillsSummary != "" {
		parts = append(parts, fmt.Sprintf(`# Skills

The following skills extend your capabilities. To use a skill, read its SKILL.md file using the read_file tool.

%s`, skillsSummary))
	}

	// Memory context
	memoryContext := cb.memory.GetMemoryContext()
	if memoryContext != "" {
		parts = append(parts, "# Memory\n\n"+memoryContext)
	}

	// Join with "---" separator
	return strings.Join(parts, "\n\n---\n\n")
}

func (cb *ContextBuilder) LoadBootstrapFiles(channel, chatID string) string {
	bootstrapFiles := []string{
		"AGENT.md",
		"SOUL.md",
		"USER.md",
		"IDENTITY.md",
	}

	var result string
	for _, filename := range bootstrapFiles {
		base := strings.TrimSuffix(filename, ".md")
		ext := ".md"

		// Define search paths in order of priority:
		// 1. memory/[file].[channel].[chat_id].md
		// 2. [file].[channel].[chat_id].md
		// 3. memory/[file].[channel].md
		// 4. [file].[channel].md
		// 5. memory/[file].md
		// 6. [file].md

		var potentialFiles []string

		if channel != "" && chatID != "" {
			specificName := fmt.Sprintf("%s.%s.%s%s", base, channel, chatID, ext)
			potentialFiles = append(potentialFiles,
				filepath.Join(cb.workspace, "memory", specificName),
				filepath.Join(cb.workspace, specificName),
			)
		}

		if channel != "" {
			channelName := fmt.Sprintf("%s.%s%s", base, channel, ext)
			potentialFiles = append(potentialFiles,
				filepath.Join(cb.workspace, "memory", channelName),
				filepath.Join(cb.workspace, channelName),
			)
		}

		potentialFiles = append(potentialFiles,
			filepath.Join(cb.workspace, "memory", filename),
			filepath.Join(cb.workspace, filename),
		)

		for _, path := range potentialFiles {
			if data, err := os.ReadFile(path); err == nil {
				result += fmt.Sprintf("## %s\n\n%s\n\n", filename, string(data))
				break // Found the most specific file, stop searching for others of this type
			}
		}
	}

	return result
}

func (cb *ContextBuilder) BuildMessages(history []providers.Message, summary string, currentMessage string, media []string, channel, chatID string) []providers.Message {
	messages := []providers.Message{}

	systemPrompt := cb.BuildSystemPrompt(channel, chatID)

	// Add Current Session info if provided
	if channel != "" && chatID != "" {
		systemPrompt += fmt.Sprintf("\n\n## Current Session\nChannel: %s\nChat ID: %s", channel, chatID)
	}

	// Log system prompt summary for debugging (debug mode only)
	logger.DebugCF("agent", "System prompt built",
		map[string]interface{}{
			"total_chars":   len(systemPrompt),
			"total_lines":   strings.Count(systemPrompt, "\n") + 1,
			"section_count": strings.Count(systemPrompt, "\n\n---\n\n") + 1,
		})

	// Log preview of system prompt (avoid logging huge content)
	preview := systemPrompt
	if len(preview) > 500 {
		preview = preview[:500] + "... (truncated)"
	}
	logger.DebugCF("agent", "System prompt preview",
		map[string]interface{}{
			"preview": preview,
		})

	if summary != "" {
		systemPrompt += "\n\n## Summary of Previous Conversation\n\n" + summary
	}

	//This fix prevents the session memory from LLM failure due to elimination of toolu_IDs required from LLM
	// --- INICIO DEL FIX ---
	//Diegox-17
	for len(history) > 0 && (history[0].Role == "tool") {
		logger.DebugCF("agent", "Removing orphaned tool message from history to prevent LLM error",
			map[string]interface{}{"role": history[0].Role})
		history = history[1:]
	}
	//Diegox-17
	// --- FIN DEL FIX ---

	messages = append(messages, providers.Message{
		Role:    "system",
		Content: systemPrompt,
	})

	// Sanitize history: Filter out messages with empty content and no tool calls
	// For messages WITH tool calls but empty content, fill with a placeholder to satisfy strict APIs (Grok/NewAPI)
	// Sanitize history: Filter out messages with empty content and no tool calls
	// For messages WITH tool calls but empty content, fill with a placeholder to satisfy strict APIs (Grok/NewAPI)
	// Also ensure all tool calls have a corresponding result.
	for i, msg := range history {
		trimmed := strings.TrimSpace(msg.Content)
		if trimmed == "" {
			if len(msg.ToolCalls) == 0 {
				logger.DebugCF("agent", "Filtering empty message from history", map[string]interface{}{"role": msg.Role})
				continue
			} else {
				// Has tool calls but empty content. Some providers (Grok) fail on this.
				// Inject placeholder.
				msg.Content = "(calling tool)" // logic: never empty
			}
		}
		messages = append(messages, msg)

		// Check for pending tool calls that might be missing results (e.g. crash/restart)
		if len(msg.ToolCalls) > 0 {
			// Look ahead to see if the next message is a tool result for these calls
			// If not, we found an interrupted session. Inject synthetic error results.
			// We need to check if we have enough subsequent messages to cover all tool calls
			// Actually, typical flow is: Assistant(calls T1, T2) -> Tool(T1) -> Tool(T2).
			// If we are at 'msg' (Assistant), check if i+1, i+2... are Tool/User.
			
			// Simply: if we are at the end of history, or next message is NOT a tool result,
			// or next message is User role... we assume they are missing.
			// (Note: This is a heuristic. Ideally looking up by ID is safer but order is usually sequential)
			
			expectedResults := len(msg.ToolCalls)
			foundResults := 0
			
			// Scan ahead
			for j := i + 1; j < len(history); j++ {
				if history[j].Role == "tool" {
					foundResults++
				} else {
					// Found non-tool message (likely User or Assistant), stop scanning
					break
				}
			}
			
			if foundResults < expectedResults {
				logger.WarnCF("agent", "Found pending tool calls without results, injecting errors", 
					map[string]interface{}{
						"expected": expectedResults,
						"found": foundResults,
						"msg_index": i,
					})
					
				// Inject missing results
				// We need to inject (expected - found) results. 
				// BUT we don't know WHICH ones are missing easily without ID matching.
				// However, 'messages' is being built sequentially.
				// If we just blindly append errors for ALL tool calls of this message, 
				// we might duplicate if some *were* present in history but we missed them?
				// Wait, we generate 'messages' from 'history'.
				// If history has [Assistant(T1, T2), Tool(T1)], we append [Assistant].
				// Next loop iteration will append Tool(T1).
				// We need to insert Tool(T2) *after* Tool(T1) is processed?
				// Or can we just patch 'history' before this loop? 
				// Patching history in-place or creating a sanitized list first is cleaner.
			}
		}
	}
	
	// Better approach: Re-build the list cleanly
	cleanMessages := make([]providers.Message, 0, len(messages))
	// Add system prompt first
	cleanMessages = append(cleanMessages, messages[0]) 
	
	// We need to process the *rest* of the messages (which came from history) and the final new message?
	// The current function structure appends history items one by one to 'messages' (which started with System).
	// Let's refine the loop above to handle injection directly.
	
	// Reset messages to just System Prompt for the rebuild
	messages = []providers.Message{{Role: "system", Content: systemPrompt}}
	
	for i := 0; i < len(history); i++ {
		msg := history[i]
		
		// 1. Filter empty non-tool messages
		if strings.TrimSpace(msg.Content) == "" && len(msg.ToolCalls) == 0 {
			continue
		}
		// 2. Fix empty tool-call messages
		if strings.TrimSpace(msg.Content) == "" && len(msg.ToolCalls) > 0 {
			msg.Content = "(calling tool)"
		}
		
		messages = append(messages, msg)
		
		// 3. If this is an assistant message with tool calls, verify/inject results
		if len(msg.ToolCalls) > 0 {
			// We expect the next len(msg.ToolCalls) messages in 'history' to be tool results
			// matching these IDs.
			
			for _, tc := range msg.ToolCalls {
				// Check if the confirmation exists in the *remaining* history
				found := false
				// Look ahead
				scanIdx := i + 1
				for scanIdx < len(history) {
					nextMsg := history[scanIdx]
					if nextMsg.Role != "tool" {
						break // sequence broken
					}
					if nextMsg.ToolCallID == tc.ID {
						found = true
						break
					}
					scanIdx++
				}
				
				if !found {
					// Inject synthetic error
					synthetic := providers.Message{
						Role: "tool",
						ToolCallID: tc.ID,
						Content: "Error: Tool execution interrupted (system restart or crash).",
					}
					messages = append(messages, synthetic)
					logger.InfoCF("agent", "Injected synthetic tool error", map[string]interface{}{"id": tc.ID})
				}
			}
		}
	}

	messages = append(messages, providers.Message{
		Role:    "user",
		Content: currentMessage,
	})

	return messages
}

func (cb *ContextBuilder) AddToolResult(messages []providers.Message, toolCallID, toolName, result string) []providers.Message {
	messages = append(messages, providers.Message{
		Role:       "tool",
		Content:    result,
		ToolCallID: toolCallID,
	})
	return messages
}

func (cb *ContextBuilder) AddAssistantMessage(messages []providers.Message, content string, toolCalls []map[string]interface{}) []providers.Message {
	msg := providers.Message{
		Role:    "assistant",
		Content: content,
	}
	// Always add assistant message, whether or not it has tool calls
	messages = append(messages, msg)
	return messages
}

func (cb *ContextBuilder) loadSkills() string {
	allSkills := cb.skillsLoader.ListSkills()
	if len(allSkills) == 0 {
		return ""
	}

	var skillNames []string
	for _, s := range allSkills {
		skillNames = append(skillNames, s.Name)
	}

	content := cb.skillsLoader.LoadSkillsForContext(skillNames)
	if content == "" {
		return ""
	}

	return "# Skill Definitions\n\n" + content
}

// GetSkillsInfo returns information about loaded skills.
func (cb *ContextBuilder) GetSkillsInfo() map[string]interface{} {
	allSkills := cb.skillsLoader.ListSkills()
	skillNames := make([]string, 0, len(allSkills))
	for _, s := range allSkills {
		skillNames = append(skillNames, s.Name)
	}
	return map[string]interface{}{
		"total":     len(allSkills),
		"available": len(allSkills),
		"names":     skillNames,
	}
}
