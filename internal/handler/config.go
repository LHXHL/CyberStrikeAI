package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ConfigHandler 配置处理器
type ConfigHandler struct {
	configPath string
	config     *config.Config
	mcpServer  *mcp.Server
	executor   *security.Executor
	agent      AgentUpdater // Agent接口，用于更新Agent配置
	logger     *zap.Logger
	mu         sync.RWMutex
}

// AgentUpdater Agent更新接口
type AgentUpdater interface {
	UpdateConfig(cfg *config.OpenAIConfig)
	UpdateMaxIterations(maxIterations int)
}

// NewConfigHandler 创建新的配置处理器
func NewConfigHandler(configPath string, cfg *config.Config, mcpServer *mcp.Server, executor *security.Executor, agent AgentUpdater, logger *zap.Logger) *ConfigHandler {
	return &ConfigHandler{
		configPath: configPath,
		config:     cfg,
		mcpServer:  mcpServer,
		executor:   executor,
		agent:      agent,
		logger:     logger,
	}
}

// GetConfigResponse 获取配置响应
type GetConfigResponse struct {
	OpenAI  config.OpenAIConfig   `json:"openai"`
	MCP     config.MCPConfig      `json:"mcp"`
	Tools   []ToolConfigInfo      `json:"tools"`
	Agent   config.AgentConfig    `json:"agent"`
}

// ToolConfigInfo 工具配置信息
type ToolConfigInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// GetConfig 获取当前配置
func (h *ConfigHandler) GetConfig(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// 获取工具列表
	tools := make([]ToolConfigInfo, 0, len(h.config.Security.Tools))
	for _, tool := range h.config.Security.Tools {
		tools = append(tools, ToolConfigInfo{
			Name:        tool.Name,
			Description: tool.ShortDescription,
			Enabled:     tool.Enabled,
		})
		// 如果没有简短描述，使用详细描述的前100个字符
		if tools[len(tools)-1].Description == "" {
			desc := tool.Description
			if len(desc) > 100 {
				desc = desc[:100] + "..."
			}
			tools[len(tools)-1].Description = desc
		}
	}

	c.JSON(http.StatusOK, GetConfigResponse{
		OpenAI: h.config.OpenAI,
		MCP:    h.config.MCP,
		Tools:  tools,
		Agent:  h.config.Agent,
	})
}

// UpdateConfigRequest 更新配置请求
type UpdateConfigRequest struct {
	OpenAI *config.OpenAIConfig `json:"openai,omitempty"`
	MCP    *config.MCPConfig    `json:"mcp,omitempty"`
	Tools  []ToolEnableStatus    `json:"tools,omitempty"`
	Agent  *config.AgentConfig  `json:"agent,omitempty"`
}

// ToolEnableStatus 工具启用状态
type ToolEnableStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// UpdateConfig 更新配置
func (h *ConfigHandler) UpdateConfig(c *gin.Context) {
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 更新OpenAI配置
	if req.OpenAI != nil {
		h.config.OpenAI = *req.OpenAI
		h.logger.Info("更新OpenAI配置",
			zap.String("base_url", h.config.OpenAI.BaseURL),
			zap.String("model", h.config.OpenAI.Model),
		)
	}

	// 更新MCP配置
	if req.MCP != nil {
		h.config.MCP = *req.MCP
		h.logger.Info("更新MCP配置",
			zap.Bool("enabled", h.config.MCP.Enabled),
			zap.String("host", h.config.MCP.Host),
			zap.Int("port", h.config.MCP.Port),
		)
	}

	// 更新Agent配置
	if req.Agent != nil {
		h.config.Agent = *req.Agent
		h.logger.Info("更新Agent配置",
			zap.Int("max_iterations", h.config.Agent.MaxIterations),
		)
	}

	// 更新工具启用状态
	if req.Tools != nil {
		toolMap := make(map[string]bool)
		for _, toolStatus := range req.Tools {
			toolMap[toolStatus.Name] = toolStatus.Enabled
		}

		// 更新配置中的工具状态
		for i := range h.config.Security.Tools {
			if enabled, ok := toolMap[h.config.Security.Tools[i].Name]; ok {
				h.config.Security.Tools[i].Enabled = enabled
				h.logger.Info("更新工具启用状态",
					zap.String("tool", h.config.Security.Tools[i].Name),
					zap.Bool("enabled", enabled),
				)
			}
		}
	}

	// 保存配置到文件
	if err := h.saveConfig(); err != nil {
		h.logger.Error("保存配置失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "配置已更新"})
}

// ApplyConfig 应用配置（重新加载并重启相关服务）
func (h *ConfigHandler) ApplyConfig(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 重新注册工具（根据新的启用状态）
	h.logger.Info("重新注册工具")
	
	// 清空MCP服务器中的工具
	h.mcpServer.ClearTools()
	
	// 重新注册工具
	h.executor.RegisterTools(h.mcpServer)

	// 更新Agent的OpenAI配置
	if h.agent != nil {
		h.agent.UpdateConfig(&h.config.OpenAI)
		h.agent.UpdateMaxIterations(h.config.Agent.MaxIterations)
		h.logger.Info("Agent配置已更新")
	}

	h.logger.Info("配置已应用",
		zap.Int("tools_count", len(h.config.Security.Tools)),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "配置已应用",
		"tools_count": len(h.config.Security.Tools),
	})
}

// saveConfig 保存配置到文件
func (h *ConfigHandler) saveConfig() error {
	// 读取现有配置文件
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析现有配置
	var existingConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &existingConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 更新配置值
	if existingConfig["openai"] == nil {
		existingConfig["openai"] = make(map[string]interface{})
	}
	openaiMap := existingConfig["openai"].(map[string]interface{})
	if h.config.OpenAI.APIKey != "" {
		openaiMap["api_key"] = h.config.OpenAI.APIKey
	}
	if h.config.OpenAI.BaseURL != "" {
		openaiMap["base_url"] = h.config.OpenAI.BaseURL
	}
	if h.config.OpenAI.Model != "" {
		openaiMap["model"] = h.config.OpenAI.Model
	}

	if existingConfig["mcp"] == nil {
		existingConfig["mcp"] = make(map[string]interface{})
	}
	mcpMap := existingConfig["mcp"].(map[string]interface{})
	mcpMap["enabled"] = h.config.MCP.Enabled
	if h.config.MCP.Host != "" {
		mcpMap["host"] = h.config.MCP.Host
	}
	if h.config.MCP.Port > 0 {
		mcpMap["port"] = h.config.MCP.Port
	}

	if h.config.Agent.MaxIterations > 0 {
		if existingConfig["agent"] == nil {
			existingConfig["agent"] = make(map[string]interface{})
		}
		agentMap := existingConfig["agent"].(map[string]interface{})
		agentMap["max_iterations"] = h.config.Agent.MaxIterations
	}

	// 更新工具配置文件中的enabled状态
	if h.config.Security.ToolsDir != "" {
		configDir := filepath.Dir(h.configPath)
		toolsDir := h.config.Security.ToolsDir
		if !filepath.IsAbs(toolsDir) {
			toolsDir = filepath.Join(configDir, toolsDir)
		}

		for _, tool := range h.config.Security.Tools {
			toolFile := filepath.Join(toolsDir, tool.Name+".yaml")
			// 检查文件是否存在
			if _, err := os.Stat(toolFile); os.IsNotExist(err) {
				// 尝试.yml扩展名
				toolFile = filepath.Join(toolsDir, tool.Name+".yml")
				if _, err := os.Stat(toolFile); os.IsNotExist(err) {
					h.logger.Warn("工具配置文件不存在", zap.String("tool", tool.Name))
					continue
				}
			}

			// 读取工具配置文件
			toolData, err := os.ReadFile(toolFile)
			if err != nil {
				h.logger.Warn("读取工具配置文件失败", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			// 解析工具配置
			var toolConfig map[string]interface{}
			if err := yaml.Unmarshal(toolData, &toolConfig); err != nil {
				h.logger.Warn("解析工具配置文件失败", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			// 更新enabled状态
			toolConfig["enabled"] = tool.Enabled

			// 保存工具配置文件
			updatedData, err := yaml.Marshal(toolConfig)
			if err != nil {
				h.logger.Warn("序列化工具配置失败", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			if err := os.WriteFile(toolFile, updatedData, 0644); err != nil {
				h.logger.Warn("保存工具配置文件失败", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			h.logger.Info("更新工具配置", zap.String("tool", tool.Name), zap.Bool("enabled", tool.Enabled))
		}
	}

	// 保存主配置文件
	updatedData, err := yaml.Marshal(existingConfig)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 创建备份
	backupPath := h.configPath + ".backup"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		h.logger.Warn("创建配置备份失败", zap.Error(err))
	}

	// 保存新配置
	if err := os.WriteFile(h.configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("保存配置文件失败: %w", err)
	}

	h.logger.Info("配置已保存", zap.String("path", h.configPath))
	return nil
}

