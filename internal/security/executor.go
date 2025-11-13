package security

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

// Executor 安全工具执行器
type Executor struct {
	config    *config.SecurityConfig
	toolIndex map[string]*config.ToolConfig // 工具索引，用于 O(1) 查找
	mcpServer *mcp.Server
	logger    *zap.Logger
}

// NewExecutor 创建新的执行器
func NewExecutor(cfg *config.SecurityConfig, mcpServer *mcp.Server, logger *zap.Logger) *Executor {
	executor := &Executor{
		config:    cfg,
		toolIndex: make(map[string]*config.ToolConfig),
		mcpServer: mcpServer,
		logger:    logger,
	}
	// 构建工具索引
	executor.buildToolIndex()
	return executor
}

// buildToolIndex 构建工具索引，将 O(n) 查找优化为 O(1)
func (e *Executor) buildToolIndex() {
	e.toolIndex = make(map[string]*config.ToolConfig)
	for i := range e.config.Tools {
		if e.config.Tools[i].Enabled {
			e.toolIndex[e.config.Tools[i].Name] = &e.config.Tools[i]
		}
	}
	e.logger.Info("工具索引构建完成",
		zap.Int("totalTools", len(e.config.Tools)),
		zap.Int("enabledTools", len(e.toolIndex)),
	)
}

// ExecuteTool 执行安全工具
func (e *Executor) ExecuteTool(ctx context.Context, toolName string, args map[string]interface{}) (*mcp.ToolResult, error) {
	e.logger.Info("ExecuteTool被调用",
		zap.String("toolName", toolName),
		zap.Any("args", args),
	)

	// 特殊处理：exec工具直接执行系统命令
	if toolName == "exec" {
		e.logger.Info("执行exec工具")
		return e.executeSystemCommand(ctx, args)
	}

	// 使用索引查找工具配置（O(1) 查找）
	toolConfig, exists := e.toolIndex[toolName]
	if !exists {
		e.logger.Error("工具未找到或未启用",
			zap.String("toolName", toolName),
			zap.Int("totalTools", len(e.config.Tools)),
			zap.Int("enabledTools", len(e.toolIndex)),
		)
		return nil, fmt.Errorf("工具 %s 未找到或未启用", toolName)
	}

	e.logger.Info("找到工具配置",
		zap.String("toolName", toolName),
		zap.String("command", toolConfig.Command),
		zap.Strings("args", toolConfig.Args),
	)

	// 构建命令 - 根据工具类型使用不同的参数格式
	cmdArgs := e.buildCommandArgs(toolName, toolConfig, args)

	e.logger.Info("构建命令参数完成",
		zap.String("toolName", toolName),
		zap.Strings("cmdArgs", cmdArgs),
		zap.Int("argsCount", len(cmdArgs)),
	)

	// 验证命令参数
	if len(cmdArgs) == 0 {
		e.logger.Warn("命令参数为空",
			zap.String("toolName", toolName),
			zap.Any("inputArgs", args),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: fmt.Sprintf("错误: 工具 %s 缺少必需的参数。接收到的参数: %v", toolName, args),
				},
			},
			IsError: true,
		}, nil
	}

	// 执行命令
	cmd := exec.CommandContext(ctx, toolConfig.Command, cmdArgs...)

	e.logger.Info("执行安全工具",
		zap.String("tool", toolName),
		zap.Strings("args", cmdArgs),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		e.logger.Error("工具执行失败",
			zap.String("tool", toolName),
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: fmt.Sprintf("工具执行失败: %v\n输出: %s", err, string(output)),
				},
			},
			IsError: true,
		}, nil
	}

	e.logger.Info("工具执行成功",
		zap.String("tool", toolName),
		zap.String("output", string(output)),
	)

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: string(output),
			},
		},
		IsError: false,
	}, nil
}

// RegisterTools 注册工具到MCP服务器
func (e *Executor) RegisterTools(mcpServer *mcp.Server) {
	e.logger.Info("开始注册工具",
		zap.Int("totalTools", len(e.config.Tools)),
		zap.Int("enabledTools", len(e.toolIndex)),
	)

	// 重新构建索引（以防配置更新）
	e.buildToolIndex()

	for i, toolConfig := range e.config.Tools {
		if !toolConfig.Enabled {
			e.logger.Debug("跳过未启用的工具",
				zap.String("tool", toolConfig.Name),
			)
			continue
		}

		// 创建工具配置的副本，避免闭包问题
		toolName := toolConfig.Name
		toolConfigCopy := toolConfig

		// 使用简短描述（如果存在），否则使用详细描述的前100个字符
		shortDesc := toolConfigCopy.ShortDescription
		if shortDesc == "" {
			// 如果没有简短描述，从详细描述中提取第一行或前100个字符
			desc := toolConfigCopy.Description
			if len(desc) > 100 {
				// 尝试找到第一个换行符
				if idx := strings.Index(desc, "\n"); idx > 0 && idx < 100 {
					shortDesc = strings.TrimSpace(desc[:idx])
				} else {
					shortDesc = desc[:100] + "..."
				}
			} else {
				shortDesc = desc
			}
		}

		tool := mcp.Tool{
			Name:             toolConfigCopy.Name,
			Description:      toolConfigCopy.Description,
			ShortDescription: shortDesc,
			InputSchema:      e.buildInputSchema(&toolConfigCopy),
		}

		handler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			e.logger.Info("工具handler被调用",
				zap.String("toolName", toolName),
				zap.Any("args", args),
			)
			return e.ExecuteTool(ctx, toolName, args)
		}

		mcpServer.RegisterTool(tool, handler)
		e.logger.Info("注册安全工具成功",
			zap.String("tool", toolConfigCopy.Name),
			zap.String("command", toolConfigCopy.Command),
			zap.Int("index", i),
		)
	}

	e.logger.Info("工具注册完成",
		zap.Int("registeredCount", len(e.config.Tools)),
	)
}

// buildCommandArgs 构建命令参数
func (e *Executor) buildCommandArgs(toolName string, toolConfig *config.ToolConfig, args map[string]interface{}) []string {
	cmdArgs := make([]string, 0)

	// 如果配置中定义了参数映射，使用配置中的映射规则
	if len(toolConfig.Parameters) > 0 {
		// 检查是否有 scan_type 参数，如果有则替换默认的扫描类型参数
		hasScanType := false
		var scanTypeValue string
		if scanType, ok := args["scan_type"].(string); ok && scanType != "" {
			hasScanType = true
			scanTypeValue = scanType
		}

		// 添加固定参数（如果指定了 scan_type，可能需要过滤掉默认的扫描类型参数）
		if hasScanType && toolName == "nmap" {
			// 对于 nmap，如果指定了 scan_type，跳过默认的 -sT -sV -sC
			// 这些参数会被 scan_type 参数替换
		} else {
			cmdArgs = append(cmdArgs, toolConfig.Args...)
		}

		// 按位置参数排序
		positionalParams := make([]config.ParameterConfig, 0)
		flagParams := make([]config.ParameterConfig, 0)

		for _, param := range toolConfig.Parameters {
			if param.Position != nil {
				positionalParams = append(positionalParams, param)
			} else {
				flagParams = append(flagParams, param)
			}
		}

		// 先处理标志参数（对于大多数命令，标志应该在位置参数之前）
		// 处理标志参数
		for _, param := range flagParams {
			// 跳过特殊参数，它们会在后面单独处理
			// action 参数仅用于工具内部逻辑，不传递给命令
			if param.Name == "additional_args" || param.Name == "scan_type" || param.Name == "action" {
				continue
			}

			value := e.getParamValue(args, param)
			if value == nil {
				if param.Required {
					// 必需参数缺失，返回空数组让上层处理错误
					e.logger.Warn("缺少必需的标志参数",
						zap.String("tool", toolName),
						zap.String("param", param.Name),
					)
					return []string{}
				}
				continue
			}

			// 布尔值特殊处理：如果为 false，跳过；如果为 true，只添加标志
			if param.Type == "bool" {
				var boolVal bool
				var ok bool

				// 尝试多种类型转换
				if boolVal, ok = value.(bool); ok {
					// 已经是布尔值
				} else if numVal, ok := value.(float64); ok {
					// JSON 数字类型（float64）
					boolVal = numVal != 0
					ok = true
				} else if numVal, ok := value.(int); ok {
					// int 类型
					boolVal = numVal != 0
					ok = true
				} else if strVal, ok := value.(string); ok {
					// 字符串类型
					boolVal = strVal == "true" || strVal == "1" || strVal == "yes"
					ok = true
				}

				if ok {
					if !boolVal {
						continue // false 时不添加任何参数
					}
					// true 时只添加标志，不添加值
					if param.Flag != "" {
						cmdArgs = append(cmdArgs, param.Flag)
					}
					continue
				}
			}

			format := param.Format
			if format == "" {
				format = "flag" // 默认格式
			}

			switch format {
			case "flag":
				// --flag value 或 -f value
				if param.Flag != "" {
					cmdArgs = append(cmdArgs, param.Flag)
				}
				formattedValue := e.formatParamValue(param, value)
				if formattedValue != "" {
					cmdArgs = append(cmdArgs, formattedValue)
				}
			case "combined":
				// --flag=value 或 -f=value
				if param.Flag != "" {
					cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", param.Flag, e.formatParamValue(param, value)))
				} else {
					cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
				}
			case "template":
				// 使用模板字符串
				if param.Template != "" {
					template := param.Template
					template = strings.ReplaceAll(template, "{flag}", param.Flag)
					template = strings.ReplaceAll(template, "{value}", e.formatParamValue(param, value))
					template = strings.ReplaceAll(template, "{name}", param.Name)
					cmdArgs = append(cmdArgs, strings.Fields(template)...)
				} else {
					// 如果没有模板，使用默认格式
					if param.Flag != "" {
						cmdArgs = append(cmdArgs, param.Flag)
					}
					cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
				}
			case "positional":
				// 位置参数（已在上面处理）
				cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
			default:
				// 默认：直接添加值
				cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
			}
		}

		// 然后处理位置参数（位置参数通常在标志参数之后）
		// 对位置参数按位置排序
		for i := 0; i < len(positionalParams); i++ {
			for _, param := range positionalParams {
				// 跳过特殊参数，它们会在后面单独处理
				// action 参数仅用于工具内部逻辑，不传递给命令
				if param.Name == "additional_args" || param.Name == "scan_type" || param.Name == "action" {
					continue
				}

				if param.Position != nil && *param.Position == i {
					value := e.getParamValue(args, param)
					if value == nil {
						if param.Required {
							// 必需参数缺失，返回空数组让上层处理错误
							e.logger.Warn("缺少必需的位置参数",
								zap.String("tool", toolName),
								zap.String("param", param.Name),
								zap.Int("position", *param.Position),
							)
							return []string{}
						}
						// 对于非必需参数，如果值为 nil，尝试使用默认值
						if param.Default != nil {
							value = param.Default
						} else {
							break
						}
					}
					cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
					break
				}
			}
		}

		// 特殊处理：additional_args 参数（需要按空格分割成多个参数）
		if additionalArgs, ok := args["additional_args"].(string); ok && additionalArgs != "" {
			// 按空格分割，但保留引号内的内容
			additionalArgsList := e.parseAdditionalArgs(additionalArgs)
			cmdArgs = append(cmdArgs, additionalArgsList...)
		}

		// 特殊处理：scan_type 参数（需要按空格分割并插入到合适位置）
		if hasScanType {
			scanTypeArgs := e.parseAdditionalArgs(scanTypeValue)
			if len(scanTypeArgs) > 0 {
				// 对于 nmap，scan_type 应该替换默认的扫描类型参数
				// 由于我们已经跳过了默认的 args，现在需要将 scan_type 插入到合适位置
				// 找到 target 参数的位置（通常是最后一个位置参数）
				insertPos := len(cmdArgs)
				for i := len(cmdArgs) - 1; i >= 0; i-- {
					// target 通常是最后一个非标志参数
					if !strings.HasPrefix(cmdArgs[i], "-") {
						insertPos = i
						break
					}
				}
				// 在 target 之前插入 scan_type 参数
				newArgs := make([]string, 0, len(cmdArgs)+len(scanTypeArgs))
				newArgs = append(newArgs, cmdArgs[:insertPos]...)
				newArgs = append(newArgs, scanTypeArgs...)
				newArgs = append(newArgs, cmdArgs[insertPos:]...)
				cmdArgs = newArgs
			}
		}

		return cmdArgs
	}

	// 如果没有定义参数配置，使用固定参数和通用处理
	// 添加固定参数
	cmdArgs = append(cmdArgs, toolConfig.Args...)

	// 通用处理：将参数转换为命令行参数
	for key, value := range args {
		if key == "_tool_name" {
			continue
		}
		// 使用 --key value 格式
		cmdArgs = append(cmdArgs, fmt.Sprintf("--%s", key))
		if strValue, ok := value.(string); ok {
			cmdArgs = append(cmdArgs, strValue)
		} else {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%v", value))
		}
	}

	return cmdArgs
}

// parseAdditionalArgs 解析 additional_args 字符串，按空格分割但保留引号内的内容
func (e *Executor) parseAdditionalArgs(argsStr string) []string {
	if argsStr == "" {
		return []string{}
	}

	result := make([]string, 0)
	var current strings.Builder
	inQuotes := false
	var quoteChar rune
	escapeNext := false

	runes := []rune(argsStr)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if r == '\\' {
			// 检查下一个字符是否是引号
			if i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\'') {
				// 转义的引号：跳过反斜杠，将引号作为普通字符写入
				i++
				current.WriteRune(runes[i])
			} else {
				// 其他转义字符：写入反斜杠，下一个字符会在下次迭代处理
				escapeNext = true
				current.WriteRune(r)
			}
			continue
		}

		if !inQuotes && (r == '"' || r == '\'') {
			inQuotes = true
			quoteChar = r
			continue
		}

		if inQuotes && r == quoteChar {
			inQuotes = false
			quoteChar = 0
			continue
		}

		if !inQuotes && (r == ' ' || r == '\t' || r == '\n') {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	// 处理最后一个参数（如果存在）
	if current.Len() > 0 {
		result = append(result, current.String())
	}

	// 如果解析结果为空，使用简单的空格分割作为降级方案
	if len(result) == 0 {
		result = strings.Fields(argsStr)
	}

	return result
}

// getParamValue 获取参数值，支持默认值
func (e *Executor) getParamValue(args map[string]interface{}, param config.ParameterConfig) interface{} {
	// 从参数中获取值
	if value, ok := args[param.Name]; ok && value != nil {
		return value
	}

	// 如果参数是必需的但没有提供，返回 nil（让上层处理错误）
	if param.Required {
		return nil
	}

	// 返回默认值
	return param.Default
}

// formatParamValue 格式化参数值
func (e *Executor) formatParamValue(param config.ParameterConfig, value interface{}) string {
	switch param.Type {
	case "bool":
		// 布尔值应该在上层处理，这里不应该被调用
		if boolVal, ok := value.(bool); ok {
			return fmt.Sprintf("%v", boolVal)
		}
		return "false"
	case "array":
		// 数组：转换为逗号分隔的字符串
		if arr, ok := value.([]interface{}); ok {
			strs := make([]string, 0, len(arr))
			for _, item := range arr {
				strs = append(strs, fmt.Sprintf("%v", item))
			}
			return strings.Join(strs, ",")
		}
		return fmt.Sprintf("%v", value)
	default:
		formattedValue := fmt.Sprintf("%v", value)
		// 特殊处理：对于 ports 参数（通常是 nmap 等工具的端口参数），清理空格
		// nmap 不接受端口列表中有空格，例如 "80,443, 22" 应该变成 "80,443,22"
		if param.Name == "ports" {
			// 移除所有空格，但保留逗号和其他字符
			formattedValue = strings.ReplaceAll(formattedValue, " ", "")
		}
		return formattedValue
	}
}

// executeSystemCommand 执行系统命令
func (e *Executor) executeSystemCommand(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
	// 获取命令
	command, ok := args["command"].(string)
	if !ok {
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: "错误: 缺少command参数",
				},
			},
			IsError: true,
		}, nil
	}

	if command == "" {
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: "错误: command参数不能为空",
				},
			},
			IsError: true,
		}, nil
	}

	// 安全检查：记录执行的命令
	e.logger.Warn("执行系统命令",
		zap.String("command", command),
	)

	// 获取shell类型（可选，默认为sh）
	shell := "sh"
	if s, ok := args["shell"].(string); ok && s != "" {
		shell = s
	}

	// 获取工作目录（可选）
	workDir := ""
	if wd, ok := args["workdir"].(string); ok && wd != "" {
		workDir = wd
	}

	// 构建命令
	var cmd *exec.Cmd
	if workDir != "" {
		cmd = exec.CommandContext(ctx, shell, "-c", command)
		cmd.Dir = workDir
	} else {
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}

	// 执行命令
	e.logger.Info("执行系统命令",
		zap.String("command", command),
		zap.String("shell", shell),
		zap.String("workdir", workDir),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		e.logger.Error("系统命令执行失败",
			zap.String("command", command),
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: fmt.Sprintf("命令执行失败: %v\n输出: %s", err, string(output)),
				},
			},
			IsError: true,
		}, nil
	}

	e.logger.Info("系统命令执行成功",
		zap.String("command", command),
		zap.String("output_length", fmt.Sprintf("%d", len(output))),
	)

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: string(output),
			},
		},
		IsError: false,
	}, nil
}

// buildInputSchema 构建输入模式
func (e *Executor) buildInputSchema(toolConfig *config.ToolConfig) map[string]interface{} {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []string{},
	}

	// 如果配置中定义了参数，优先使用配置中的参数定义
	if len(toolConfig.Parameters) > 0 {
		properties := make(map[string]interface{})
		required := []string{}

		for _, param := range toolConfig.Parameters {
			// 转换类型为OpenAI/JSON Schema标准类型
			openAIType := e.convertToOpenAIType(param.Type)

			prop := map[string]interface{}{
				"type":        openAIType,
				"description": param.Description,
			}

			// 添加默认值
			if param.Default != nil {
				prop["default"] = param.Default
			}

			// 添加枚举选项
			if len(param.Options) > 0 {
				prop["enum"] = param.Options
			}

			properties[param.Name] = prop

			// 添加到必需参数列表
			if param.Required {
				required = append(required, param.Name)
			}
		}

		schema["properties"] = properties
		schema["required"] = required
		return schema
	}

	// 如果没有定义参数配置，返回空schema
	// 这种情况下工具可能只使用固定参数（args字段）
	// 或者需要通过YAML配置文件定义参数
	e.logger.Warn("工具未定义参数配置，返回空schema",
		zap.String("tool", toolConfig.Name),
	)
	return schema
}

// convertToOpenAIType 将配置中的类型转换为OpenAI/JSON Schema标准类型
func (e *Executor) convertToOpenAIType(configType string) string {
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
		// 默认返回原类型，但记录警告
		e.logger.Warn("未知的参数类型，使用原类型",
			zap.String("type", configType),
		)
		return configType
	}
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Target      string    `json:"target"`
	FoundAt     time.Time `json:"foundAt"`
	Details     string    `json:"details"`
}

// AnalyzeResults 分析工具执行结果，提取漏洞信息
// 注意：硬编码的漏洞解析逻辑已移除，此函数现在返回空数组
// 漏洞检测应该由工具本身或专门的漏洞扫描工具来完成
func (e *Executor) AnalyzeResults(toolName string, result *mcp.ToolResult) []Vulnerability {
	// 不再进行硬编码的漏洞解析
	// 漏洞检测应该由工具本身（如sqlmap、nmap等）的输出结果来体现
	return []Vulnerability{}
}

// GetVulnerabilityReport 生成漏洞报告
func (e *Executor) GetVulnerabilityReport(vulnerabilities []Vulnerability) map[string]interface{} {
	severityCount := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, vuln := range vulnerabilities {
		severityCount[vuln.Severity]++
	}

	return map[string]interface{}{
		"total":           len(vulnerabilities),
		"severityCount":   severityCount,
		"vulnerabilities": vulnerabilities,
		"generatedAt":     time.Now(),
	}
}
