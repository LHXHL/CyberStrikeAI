package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

// Agent AI代理
type Agent struct {
	openAIClient  *http.Client
	config        *config.OpenAIConfig
	mcpServer     *mcp.Server
	logger        *zap.Logger
	maxIterations int
	mu            sync.RWMutex // 添加互斥锁以支持并发更新
}

// NewAgent 创建新的Agent
func NewAgent(cfg *config.OpenAIConfig, mcpServer *mcp.Server, logger *zap.Logger, maxIterations int) *Agent {
	// 如果 maxIterations 为 0 或负数，使用默认值 30
	if maxIterations <= 0 {
		maxIterations = 30
	}
	
	// 配置HTTP Transport，优化连接管理和超时设置
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   300 * time.Second,
			KeepAlive: 300 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Minute, // 响应头超时：增加到15分钟，应对大响应
		DisableKeepAlives:   false, // 启用连接复用
	}
	
	// 增加超时时间到30分钟，以支持长时间运行的AI推理
	// 特别是当使用流式响应或处理复杂任务时
	return &Agent{
		openAIClient: &http.Client{
			Timeout:   30 * time.Minute, // 从5分钟增加到30分钟
			Transport: transport,
		},
		config:        cfg,
		mcpServer:     mcpServer,
		logger:        logger,
		maxIterations: maxIterations,
	}
}

// ChatMessage 聊天消息
type ChatMessage struct {
	Role      string     `json:"role"`
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string    `json:"tool_call_id,omitempty"`
}

// MarshalJSON 自定义JSON序列化，将tool_calls中的arguments转换为JSON字符串
func (cm ChatMessage) MarshalJSON() ([]byte, error) {
	// 构建序列化结构
	aux := map[string]interface{}{
		"role": cm.Role,
	}

	// 添加content（如果存在）
	if cm.Content != "" {
		aux["content"] = cm.Content
	}

	// 添加tool_call_id（如果存在）
	if cm.ToolCallID != "" {
		aux["tool_call_id"] = cm.ToolCallID
	}

	// 转换tool_calls，将arguments转换为JSON字符串
	if len(cm.ToolCalls) > 0 {
		toolCallsJSON := make([]map[string]interface{}, len(cm.ToolCalls))
		for i, tc := range cm.ToolCalls {
			// 将arguments转换为JSON字符串
			argsJSON := ""
			if tc.Function.Arguments != nil {
				argsBytes, err := json.Marshal(tc.Function.Arguments)
				if err != nil {
					return nil, err
				}
				argsJSON = string(argsBytes)
			}
			
			toolCallsJSON[i] = map[string]interface{}{
				"id":   tc.ID,
				"type": tc.Type,
				"function": map[string]interface{}{
					"name":      tc.Function.Name,
					"arguments": argsJSON,
				},
			}
		}
		aux["tool_calls"] = toolCallsJSON
	}

	return json.Marshal(aux)
}

// OpenAIRequest OpenAI API请求
type OpenAIRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Tools    []Tool        `json:"tools,omitempty"`
}

// OpenAIResponse OpenAI API响应
type OpenAIResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
	Error   *Error   `json:"error,omitempty"`
}

// Choice 选择
type Choice struct {
	Message      MessageWithTools `json:"message"`
	FinishReason string           `json:"finish_reason"`
}

// MessageWithTools 带工具调用的消息
type MessageWithTools struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// Tool OpenAI工具定义
type Tool struct {
	Type     string                 `json:"type"`
	Function FunctionDefinition     `json:"function"`
}

// FunctionDefinition 函数定义
type FunctionDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// Error OpenAI错误
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// ToolCall 工具调用
type ToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function FunctionCall           `json:"function"`
}

// FunctionCall 函数调用
type FunctionCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// UnmarshalJSON 自定义JSON解析，处理arguments可能是字符串或对象的情况
func (fc *FunctionCall) UnmarshalJSON(data []byte) error {
	type Alias FunctionCall
	aux := &struct {
		Name      string      `json:"name"`
		Arguments interface{} `json:"arguments"`
		*Alias
	}{
		Alias: (*Alias)(fc),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	fc.Name = aux.Name

	// 处理arguments可能是字符串或对象的情况
	switch v := aux.Arguments.(type) {
	case map[string]interface{}:
		fc.Arguments = v
	case string:
		// 如果是字符串，尝试解析为JSON
		if err := json.Unmarshal([]byte(v), &fc.Arguments); err != nil {
			// 如果解析失败，创建一个包含原始字符串的map
			fc.Arguments = map[string]interface{}{
				"raw": v,
			}
		}
	case nil:
		fc.Arguments = make(map[string]interface{})
	default:
		// 其他类型，尝试转换为map
		fc.Arguments = map[string]interface{}{
			"value": v,
		}
	}

	return nil
}

// AgentLoopResult Agent Loop执行结果
type AgentLoopResult struct {
	Response      string
	MCPExecutionIDs []string
}

// ProgressCallback 进度回调函数类型
type ProgressCallback func(eventType, message string, data interface{})

// AgentLoop 执行Agent循环
func (a *Agent) AgentLoop(ctx context.Context, userInput string, historyMessages []ChatMessage) (*AgentLoopResult, error) {
	return a.AgentLoopWithProgress(ctx, userInput, historyMessages, nil)
}

// AgentLoopWithProgress 执行Agent循环（带进度回调）
func (a *Agent) AgentLoopWithProgress(ctx context.Context, userInput string, historyMessages []ChatMessage, callback ProgressCallback) (*AgentLoopResult, error) {
	// 发送进度更新
	sendProgress := func(eventType, message string, data interface{}) {
		if callback != nil {
			callback(eventType, message, data)
		}
	}

	// 系统提示词，指导AI如何处理工具错误
	systemPrompt := `你是一个专业的网络安全渗透测试专家。你可以使用各种安全工具进行自主渗透测试。分析目标并选择最佳测试策略。

重要：当工具调用失败时，请遵循以下原则：
1. 仔细分析错误信息，理解失败的具体原因
2. 如果工具不存在或未启用，尝试使用其他替代工具完成相同目标
3. 如果参数错误，根据错误提示修正参数后重试
4. 如果工具执行失败但输出了有用信息，可以基于这些信息继续分析
5. 如果确实无法使用某个工具，向用户说明问题，并建议替代方案或手动操作
6. 不要因为单个工具失败就停止整个测试流程，尝试其他方法继续完成任务

当工具返回错误时，错误信息会包含在工具响应中，请仔细阅读并做出合理的决策。`
	
	messages := []ChatMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
	}
	
	// 添加历史消息（数据库只保存user和assistant消息）
	a.logger.Info("处理历史消息",
		zap.Int("count", len(historyMessages)),
	)
	addedCount := 0
	for i, msg := range historyMessages {
		// 只添加有内容的消息
		if msg.Content != "" {
			messages = append(messages, ChatMessage{
				Role:    msg.Role,
				Content: msg.Content,
			})
			addedCount++
			contentPreview := msg.Content
			if len(contentPreview) > 50 {
				contentPreview = contentPreview[:50] + "..."
			}
			a.logger.Info("添加历史消息到上下文",
				zap.Int("index", i),
				zap.String("role", msg.Role),
				zap.String("content", contentPreview),
			)
		}
	}
	
	a.logger.Info("构建消息数组",
		zap.Int("historyMessages", len(historyMessages)),
		zap.Int("addedMessages", addedCount),
		zap.Int("totalMessages", len(messages)),
	)
	
	// 添加当前用户消息
	messages = append(messages, ChatMessage{
		Role:    "user",
		Content: userInput,
	})

	result := &AgentLoopResult{
		MCPExecutionIDs: make([]string, 0),
	}

	maxIterations := a.maxIterations
	for i := 0; i < maxIterations; i++ {
		// 检查是否是最后一次迭代
		isLastIteration := (i == maxIterations-1)
		
		// 获取可用工具
		tools := a.getAvailableTools()

		// 发送迭代开始事件
		if i == 0 {
			sendProgress("iteration", "开始分析请求并制定测试策略", map[string]interface{}{
				"iteration": i + 1,
				"total":     maxIterations,
			})
		} else if isLastIteration {
			sendProgress("iteration", fmt.Sprintf("第 %d 轮迭代（最后一次）", i+1), map[string]interface{}{
				"iteration": i + 1,
				"total":     maxIterations,
				"isLast":    true,
			})
		} else {
			sendProgress("iteration", fmt.Sprintf("第 %d 轮迭代", i+1), map[string]interface{}{
				"iteration": i + 1,
				"total":     maxIterations,
			})
		}

		// 记录每次调用OpenAI
		if i == 0 {
			a.logger.Info("调用OpenAI",
				zap.Int("iteration", i+1),
				zap.Int("messagesCount", len(messages)),
			)
			// 记录前几条消息的内容（用于调试）
			for j, msg := range messages {
				if j >= 5 { // 只记录前5条
					break
				}
				contentPreview := msg.Content
				if len(contentPreview) > 100 {
					contentPreview = contentPreview[:100] + "..."
				}
				a.logger.Debug("消息内容",
					zap.Int("index", j),
					zap.String("role", msg.Role),
					zap.String("content", contentPreview),
				)
			}
		} else {
			a.logger.Info("调用OpenAI",
				zap.Int("iteration", i+1),
				zap.Int("messagesCount", len(messages)),
			)
		}

		// 调用OpenAI
		sendProgress("progress", "正在调用AI模型...", nil)
		response, err := a.callOpenAI(ctx, messages, tools)
		if err != nil {
			result.Response = ""
			return result, fmt.Errorf("调用OpenAI失败: %w", err)
		}

		if response.Error != nil {
			result.Response = ""
			return result, fmt.Errorf("OpenAI错误: %s", response.Error.Message)
		}

		if len(response.Choices) == 0 {
			result.Response = ""
			return result, fmt.Errorf("没有收到响应")
		}

		choice := response.Choices[0]

		// 检查是否有工具调用
		if len(choice.Message.ToolCalls) > 0 {
			// 如果有思考内容，先发送思考事件
			if choice.Message.Content != "" {
				sendProgress("thinking", choice.Message.Content, map[string]interface{}{
					"iteration": i + 1,
				})
			}

			// 添加assistant消息（包含工具调用）
			messages = append(messages, ChatMessage{
				Role:      "assistant",
				Content:   choice.Message.Content,
				ToolCalls: choice.Message.ToolCalls,
			})

			// 发送工具调用进度
			sendProgress("tool_calls_detected", fmt.Sprintf("检测到 %d 个工具调用", len(choice.Message.ToolCalls)), map[string]interface{}{
				"count":     len(choice.Message.ToolCalls),
				"iteration": i + 1,
			})

			// 执行所有工具调用
			for idx, toolCall := range choice.Message.ToolCalls {
				// 发送工具调用开始事件
				toolArgsJSON, _ := json.Marshal(toolCall.Function.Arguments)
				sendProgress("tool_call", fmt.Sprintf("正在调用工具: %s", toolCall.Function.Name), map[string]interface{}{
					"toolName":  toolCall.Function.Name,
					"arguments": string(toolArgsJSON),
					"argumentsObj": toolCall.Function.Arguments,
					"toolCallId": toolCall.ID,
					"index":     idx + 1,
					"total":     len(choice.Message.ToolCalls),
					"iteration": i + 1,
				})

				// 执行工具
				execResult, err := a.executeToolViaMCP(ctx, toolCall.Function.Name, toolCall.Function.Arguments)
				if err != nil {
					// 构建详细的错误信息，帮助AI理解问题并做出决策
					errorMsg := a.formatToolError(toolCall.Function.Name, toolCall.Function.Arguments, err)
					messages = append(messages, ChatMessage{
						Role:      "tool",
						ToolCallID: toolCall.ID,
						Content:   errorMsg,
					})
					
					// 发送工具执行失败事件
					sendProgress("tool_result", fmt.Sprintf("工具 %s 执行失败", toolCall.Function.Name), map[string]interface{}{
						"toolName":  toolCall.Function.Name,
						"success":   false,
						"isError":   true,
						"error":     err.Error(),
						"toolCallId": toolCall.ID,
						"index":     idx + 1,
						"total":     len(choice.Message.ToolCalls),
						"iteration": i + 1,
					})
					
					a.logger.Warn("工具执行失败，已返回详细错误信息",
						zap.String("tool", toolCall.Function.Name),
						zap.Error(err),
					)
				} else {
					// 即使工具返回了错误结果（IsError=true），也继续处理，让AI决定下一步
					messages = append(messages, ChatMessage{
						Role:      "tool",
						ToolCallID: toolCall.ID,
						Content:   execResult.Result,
					})
					// 收集执行ID
					if execResult.ExecutionID != "" {
						result.MCPExecutionIDs = append(result.MCPExecutionIDs, execResult.ExecutionID)
					}
					
					// 发送工具执行成功事件
					resultPreview := execResult.Result
					if len(resultPreview) > 200 {
						resultPreview = resultPreview[:200] + "..."
					}
					sendProgress("tool_result", fmt.Sprintf("工具 %s 执行完成", toolCall.Function.Name), map[string]interface{}{
						"toolName":    toolCall.Function.Name,
						"success":     !execResult.IsError,
						"isError":     execResult.IsError,
						"result":      execResult.Result, // 完整结果
						"resultPreview": resultPreview,   // 预览结果
						"executionId": execResult.ExecutionID,
						"toolCallId":  toolCall.ID,
						"index":       idx + 1,
						"total":       len(choice.Message.ToolCalls),
						"iteration":   i + 1,
					})
					
					// 如果工具返回了错误，记录日志但不中断流程
					if execResult.IsError {
						a.logger.Warn("工具返回错误结果，但继续处理",
							zap.String("tool", toolCall.Function.Name),
							zap.String("result", execResult.Result),
						)
					}
				}
			}
			
			// 如果是最后一次迭代，执行完工具后要求AI进行总结
			if isLastIteration {
				sendProgress("progress", "最后一次迭代：正在生成总结和下一步计划...", nil)
				// 添加用户消息，要求AI进行总结
				messages = append(messages, ChatMessage{
					Role:    "user",
					Content: "这是最后一次迭代。请总结到目前为止的所有测试结果、发现的问题和已完成的工作。如果需要继续测试，请提供详细的下一步执行计划。请直接回复，不要调用工具。",
				})
				// 立即调用OpenAI获取总结
				summaryResponse, err := a.callOpenAI(ctx, messages, []Tool{}) // 不提供工具，强制AI直接回复
				if err == nil && summaryResponse != nil && len(summaryResponse.Choices) > 0 {
					summaryChoice := summaryResponse.Choices[0]
					if summaryChoice.Message.Content != "" {
						result.Response = summaryChoice.Message.Content
						sendProgress("progress", "总结生成完成", nil)
						return result, nil
					}
				}
				// 如果获取总结失败，跳出循环，让后续逻辑处理
				break
			}
			
			continue
		}

		// 添加assistant响应
		messages = append(messages, ChatMessage{
			Role:    "assistant",
			Content: choice.Message.Content,
		})

		// 发送AI思考内容（如果没有工具调用）
		if choice.Message.Content != "" {
			sendProgress("thinking", choice.Message.Content, map[string]interface{}{
				"iteration": i + 1,
			})
		}

		// 如果是最后一次迭代，无论finish_reason是什么，都要求AI进行总结
		if isLastIteration {
			sendProgress("progress", "最后一次迭代：正在生成总结和下一步计划...", nil)
			// 添加用户消息，要求AI进行总结
			messages = append(messages, ChatMessage{
				Role:    "user",
				Content: "这是最后一次迭代。请总结到目前为止的所有测试结果、发现的问题和已完成的工作。如果需要继续测试，请提供详细的下一步执行计划。请直接回复，不要调用工具。",
			})
			// 立即调用OpenAI获取总结
			summaryResponse, err := a.callOpenAI(ctx, messages, []Tool{}) // 不提供工具，强制AI直接回复
			if err == nil && summaryResponse != nil && len(summaryResponse.Choices) > 0 {
				summaryChoice := summaryResponse.Choices[0]
				if summaryChoice.Message.Content != "" {
					result.Response = summaryChoice.Message.Content
					sendProgress("progress", "总结生成完成", nil)
					return result, nil
				}
			}
			// 如果获取总结失败，使用当前回复作为结果
			if choice.Message.Content != "" {
				result.Response = choice.Message.Content
				return result, nil
			}
			// 如果都没有内容，跳出循环，让后续逻辑处理
			break
		}
		
		// 如果完成，返回结果
		if choice.FinishReason == "stop" {
			sendProgress("progress", "正在生成最终回复...", nil)
			result.Response = choice.Message.Content
			return result, nil
		}
	}

	// 如果循环结束仍未返回，说明达到了最大迭代次数
	// 尝试最后一次调用AI获取总结
	sendProgress("progress", "达到最大迭代次数，正在生成总结...", nil)
	finalSummaryPrompt := ChatMessage{
		Role:    "user",
		Content: fmt.Sprintf("已达到最大迭代次数（%d轮）。请总结到目前为止的所有测试结果、发现的问题和已完成的工作。如果需要继续测试，请提供详细的下一步执行计划。请直接回复，不要调用工具。", a.maxIterations),
	}
	messages = append(messages, finalSummaryPrompt)
	
	summaryResponse, err := a.callOpenAI(ctx, messages, []Tool{}) // 不提供工具，强制AI直接回复
	if err == nil && summaryResponse != nil && len(summaryResponse.Choices) > 0 {
		summaryChoice := summaryResponse.Choices[0]
		if summaryChoice.Message.Content != "" {
			result.Response = summaryChoice.Message.Content
			sendProgress("progress", "总结生成完成", nil)
			return result, nil
		}
	}
	
	// 如果无法生成总结，返回友好的提示
	result.Response = fmt.Sprintf("已达到最大迭代次数（%d轮）。系统已执行了多轮测试，但由于达到迭代上限，无法继续自动执行。建议您查看已执行的工具结果，或提出新的测试请求以继续测试。", a.maxIterations)
	return result, nil
}

// getAvailableTools 获取可用工具
// 从MCP服务器动态获取工具列表，使用简短描述以减少token消耗
func (a *Agent) getAvailableTools() []Tool {
	// 从MCP服务器获取所有已注册的工具
	mcpTools := a.mcpServer.GetAllTools()
	
	// 转换为OpenAI格式的工具定义
	tools := make([]Tool, 0, len(mcpTools))
	for _, mcpTool := range mcpTools {
		// 使用简短描述（如果存在），否则使用详细描述
		description := mcpTool.ShortDescription
		if description == "" {
			description = mcpTool.Description
		}
		
		// 转换schema中的类型为OpenAI标准类型
		convertedSchema := a.convertSchemaTypes(mcpTool.InputSchema)
		
		tools = append(tools, Tool{
			Type: "function",
			Function: FunctionDefinition{
				Name:        mcpTool.Name,
				Description: description, // 使用简短描述减少token消耗
				Parameters:  convertedSchema,
			},
		})
	}
	
	a.logger.Debug("获取可用工具列表",
		zap.Int("count", len(tools)),
	)
	
	return tools
}

// convertSchemaTypes 递归转换schema中的类型为OpenAI标准类型
func (a *Agent) convertSchemaTypes(schema map[string]interface{}) map[string]interface{} {
	if schema == nil {
		return schema
	}
	
	// 创建新的schema副本
	converted := make(map[string]interface{})
	for k, v := range schema {
		converted[k] = v
	}
	
	// 转换properties中的类型
	if properties, ok := converted["properties"].(map[string]interface{}); ok {
		convertedProperties := make(map[string]interface{})
		for propName, propValue := range properties {
			if prop, ok := propValue.(map[string]interface{}); ok {
				convertedProp := make(map[string]interface{})
				for pk, pv := range prop {
					if pk == "type" {
						// 转换类型
						if typeStr, ok := pv.(string); ok {
							convertedProp[pk] = a.convertToOpenAIType(typeStr)
						} else {
							convertedProp[pk] = pv
						}
					} else {
						convertedProp[pk] = pv
					}
				}
				convertedProperties[propName] = convertedProp
			} else {
				convertedProperties[propName] = propValue
			}
		}
		converted["properties"] = convertedProperties
	}
	
	return converted
}

// convertToOpenAIType 将配置中的类型转换为OpenAI/JSON Schema标准类型
func (a *Agent) convertToOpenAIType(configType string) string {
	switch configType {
	case "bool":
		return "boolean"
	case "int", "integer":
		return "number"
	case "float", "double":
		return "number"
	case "string", "array", "object":
		return configType
	default:
		// 默认返回原类型
		return configType
	}
}

// isRetryableError 判断错误是否可重试
func (a *Agent) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 网络相关错误，可以重试
	retryableErrors := []string{
		"connection reset",
		"connection reset by peer",
		"connection refused",
		"timeout",
		"i/o timeout",
		"context deadline exceeded",
		"no such host",
		"network is unreachable",
		"broken pipe",
		"EOF",
		"read tcp",
		"write tcp",
		"dial tcp",
	}
	for _, retryable := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), retryable) {
			return true
		}
	}
	return false
}

// callOpenAI 调用OpenAI API（带重试机制）
func (a *Agent) callOpenAI(ctx context.Context, messages []ChatMessage, tools []Tool) (*OpenAIResponse, error) {
	maxRetries := 3
	var lastErr error
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		response, err := a.callOpenAISingle(ctx, messages, tools)
		if err == nil {
			if attempt > 0 {
				a.logger.Info("OpenAI API调用重试成功",
					zap.Int("attempt", attempt+1),
					zap.Int("maxRetries", maxRetries),
				)
			}
			return response, nil
		}
		
		lastErr = err
		
		// 如果不是可重试的错误，直接返回
		if !a.isRetryableError(err) {
			return nil, err
		}
		
		// 如果不是最后一次重试，等待后重试
		if attempt < maxRetries-1 {
			// 指数退避：2s, 4s, 8s...
			backoff := time.Duration(1<<uint(attempt+1)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second // 最大30秒
			}
			a.logger.Warn("OpenAI API调用失败，准备重试",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Int("maxRetries", maxRetries),
				zap.Duration("backoff", backoff),
			)
			
			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("上下文已取消: %w", ctx.Err())
			case <-time.After(backoff):
				// 继续重试
			}
		}
	}
	
	return nil, fmt.Errorf("重试%d次后仍然失败: %w", maxRetries, lastErr)
}

// callOpenAISingle 单次调用OpenAI API（不包含重试逻辑）
func (a *Agent) callOpenAISingle(ctx context.Context, messages []ChatMessage, tools []Tool) (*OpenAIResponse, error) {
	reqBody := OpenAIRequest{
		Model:    a.config.Model,
		Messages: messages,
	}

	if len(tools) > 0 {
		reqBody.Tools = tools
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// 记录请求大小（用于诊断）
	requestSize := len(jsonData)
	a.logger.Debug("准备发送OpenAI请求",
		zap.Int("messagesCount", len(messages)),
		zap.Int("requestSizeKB", requestSize/1024),
		zap.Int("toolsCount", len(tools)),
	)

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)

	// 记录请求开始时间
	requestStartTime := time.Now()
	resp, err := a.openAIClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 记录响应头接收时间
	headerReceiveTime := time.Now()
	headerReceiveDuration := headerReceiveTime.Sub(requestStartTime)
	
	a.logger.Debug("收到OpenAI响应头",
		zap.Int("statusCode", resp.StatusCode),
		zap.Duration("headerReceiveDuration", headerReceiveDuration),
		zap.Int64("contentLength", resp.ContentLength),
	)

	// 使用带超时的读取（通过context控制）
	bodyChan := make(chan []byte, 1)
	errChan := make(chan error, 1)
	
	go func() {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errChan <- err
			return
		}
		bodyChan <- body
	}()
	
	var body []byte
	select {
	case body = <-bodyChan:
		// 读取成功
		bodyReceiveTime := time.Now()
		bodyReceiveDuration := bodyReceiveTime.Sub(headerReceiveTime)
		totalDuration := bodyReceiveTime.Sub(requestStartTime)
		
		a.logger.Debug("完成读取OpenAI响应体",
			zap.Int("bodySizeKB", len(body)/1024),
			zap.Duration("bodyReceiveDuration", bodyReceiveDuration),
			zap.Duration("totalDuration", totalDuration),
		)
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("读取响应体超时: %w", ctx.Err())
	case <-time.After(25 * time.Minute):
		// 额外的安全超时：25分钟（小于30分钟的总超时）
		return nil, fmt.Errorf("读取响应体超时（超过25分钟）")
	}

	// 记录响应内容（用于调试）
	if resp.StatusCode != http.StatusOK {
		a.logger.Warn("OpenAI API返回非200状态码",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)),
		)
	}

	var response OpenAIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		a.logger.Error("解析OpenAI响应失败",
			zap.Error(err),
			zap.String("body", string(body)),
		)
		return nil, fmt.Errorf("解析响应失败: %w, 响应内容: %s", err, string(body))
	}

	return &response, nil
}

// parseToolCall 解析工具调用
func (a *Agent) parseToolCall(content string) (map[string]interface{}, error) {
	// 简单解析，实际应该更复杂
	// 格式: [TOOL_CALL]tool_name:arg1=value1,arg2=value2
	if !strings.HasPrefix(content, "[TOOL_CALL]") {
		return nil, fmt.Errorf("不是有效的工具调用格式")
	}

	parts := strings.Split(content[len("[TOOL_CALL]"):], ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("工具调用格式错误")
	}

	toolName := strings.TrimSpace(parts[0])
	argsStr := strings.TrimSpace(parts[1])

	args := make(map[string]interface{})
	argPairs := strings.Split(argsStr, ",")
	for _, pair := range argPairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			args[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	args["_tool_name"] = toolName
	return args, nil
}

// ToolExecutionResult 工具执行结果
type ToolExecutionResult struct {
	Result      string
	ExecutionID string
	IsError     bool // 标记是否为错误结果
}

// executeToolViaMCP 通过MCP执行工具
// 即使工具执行失败，也返回结果而不是错误，让AI能够处理错误情况
func (a *Agent) executeToolViaMCP(ctx context.Context, toolName string, args map[string]interface{}) (*ToolExecutionResult, error) {
	a.logger.Info("通过MCP执行工具",
		zap.String("tool", toolName),
		zap.Any("args", args),
	)

	// 通过MCP服务器调用工具
	result, executionID, err := a.mcpServer.CallTool(ctx, toolName, args)
	
	// 如果调用失败（如工具不存在），返回友好的错误信息而不是抛出异常
	if err != nil {
		errorMsg := fmt.Sprintf(`工具调用失败

工具名称: %s
错误类型: 系统错误
错误详情: %v

可能的原因：
- 工具 "%s" 不存在或未启用
- 系统配置问题
- 网络或权限问题

建议：
- 检查工具名称是否正确
- 尝试使用其他替代工具
- 如果这是必需的工具，请向用户说明情况`, toolName, err, toolName)
		
		return &ToolExecutionResult{
			Result:      errorMsg,
			ExecutionID: executionID,
			IsError:     true,
		}, nil // 返回 nil 错误，让调用者处理结果
	}

	// 格式化结果
	var resultText strings.Builder
	for _, content := range result.Content {
		resultText.WriteString(content.Text)
		resultText.WriteString("\n")
	}

	return &ToolExecutionResult{
		Result:      resultText.String(),
		ExecutionID: executionID,
		IsError:     result != nil && result.IsError,
	}, nil
}

// UpdateConfig 更新OpenAI配置
func (a *Agent) UpdateConfig(cfg *config.OpenAIConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = cfg
	a.logger.Info("Agent配置已更新",
		zap.String("base_url", cfg.BaseURL),
		zap.String("model", cfg.Model),
	)
}

// UpdateMaxIterations 更新最大迭代次数
func (a *Agent) UpdateMaxIterations(maxIterations int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maxIterations > 0 {
		a.maxIterations = maxIterations
		a.logger.Info("Agent最大迭代次数已更新", zap.Int("max_iterations", maxIterations))
	}
}

// formatToolError 格式化工具错误信息，提供更友好的错误描述
func (a *Agent) formatToolError(toolName string, args map[string]interface{}, err error) string {
	errorMsg := fmt.Sprintf(`工具执行失败

工具名称: %s
调用参数: %v
错误信息: %v

请分析错误原因并采取以下行动之一：
1. 如果参数错误，请修正参数后重试
2. 如果工具不可用，请尝试使用替代工具
3. 如果这是系统问题，请向用户说明情况并提供建议
4. 如果错误信息中包含有用信息，可以基于这些信息继续分析`, toolName, args, err)
	
	return errorMsg
}

