package providers

import "strings"

// IsGrokModel checks if the model name corresponds to a Grok model.
func IsGrokModel(model string) bool {
	lower := strings.ToLower(model)
	return strings.Contains(lower, "grok") || strings.Contains(lower, "xai")
}

// FilterAndRenameGrokTools processes tool definitions for Grok.
// It renames allowed tools to Grok's specific names and filters out unsupported tools.
func FilterAndRenameGrokTools(tools []ToolDefinition) []ToolDefinition {
	// Strict whitelist mapping: Internal Name -> Grok Name
	validMappings := map[string]string{
		"exec":       "code_execution",
		"web_search": "web_search",
		"web_fetch":  "browse_page",
		"read_file":  "code_execution", // Fallback to code execution for file ops
		"write_file": "code_execution",
		"edit_file":  "code_execution",
	}

	filtered := make([]ToolDefinition, 0)

	for _, t := range tools {
		grokName, ok := validMappings[t.Function.Name]
		if !ok {
			// Skip tools not in the whitelist
			continue
		}

		newTool := t
		newTool.Function.Name = grokName

		// Special handling for code_execution mapping
		if grokName == "code_execution" && t.Function.Name != "exec" {
			// TODO: We might need to adjust parameters here if we map file ops to code_exec.
			// For now, let's just stick to direct mappings where possible.
			// Actually, mapping file ops to code_execution is complex without changing parameters.
			// Let's simplified: Only map 'exec' -> 'code_execution' for now.
			// File tools will be hidden.
			continue
		}

		filtered = append(filtered, newTool)
	}

	return filtered
}

// GetOriginalToolName returns the original tool name from a safe Grok tool name.
// Note: This is ambiguous if multiple tools map to the same Grok tool.
// For now, we inverse the primary mappings.
func GetOriginalToolName(safeName string) string {
	// Inverse mapping
	if safeName == "code_execution" {
		return "exec"
	}
	if safeName == "web_search" {
		return "web_search"
	}
	if safeName == "browse_page" {
		return "web_fetch"
	}
	return safeName
}

// RenameGrokToolCalls renames tool calls in messages to Grok's expected names.
func RenameGrokToolCalls(messages []Message) []Message {
	// Logic to map original name -> Grok name
	mappings := map[string]string{
		"exec":       "code_execution",
		"web_search": "web_search",
		"web_fetch":  "browse_page",
	}

	newMessages := make([]Message, len(messages))
	for i, msg := range messages {
		newMsg := msg
		if len(msg.ToolCalls) > 0 {
			newToolCalls := make([]ToolCall, len(msg.ToolCalls))
			for j, tc := range msg.ToolCalls {
				newTC := tc
				if grokName, ok := mappings[tc.Name]; ok {
					newTC.Name = grokName
				}
				if tc.Function != nil {
					if grokName, ok := mappings[tc.Function.Name]; ok {
						newTC.Function.Name = grokName
					}
				}
				newToolCalls[j] = newTC
			}
			newMsg.ToolCalls = newToolCalls
		}
		newMessages[i] = newMsg
	}
	return newMessages
}
