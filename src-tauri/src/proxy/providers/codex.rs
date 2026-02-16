//! Codex (OpenAI) Provider Adapter
//!
//! 仅透传模式，支持直连 OpenAI API
//!
//! ## 客户端检测
//! 支持检测官方 Codex 客户端 (codex_vscode, codex_cli_rs)

use super::{AuthInfo, AuthStrategy, ProviderAdapter};
use crate::provider::Provider;
use crate::proxy::error::ProxyError;
use regex::Regex;
use reqwest::RequestBuilder;
use serde_json::Value;
use std::sync::LazyLock;

/// 官方 Codex 客户端 User-Agent 正则
#[allow(dead_code)]
static CODEX_CLIENT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(codex_vscode|codex_cli_rs)/[\d.]+").unwrap());

const OPENAI_OFFICIAL_BASE_URL: &str = "https://api.openai.com";

/// Codex 适配器
pub struct CodexAdapter;

impl CodexAdapter {
    pub fn new() -> Self {
        Self
    }

    /// 检测是否为官方 Codex 客户端
    ///
    /// 匹配 User-Agent 模式: `^(codex_vscode|codex_cli_rs)/[\d.]+`
    #[allow(dead_code)]
    pub fn is_official_client(user_agent: &str) -> bool {
        CODEX_CLIENT_REGEX.is_match(user_agent)
    }

    /// 判断是否为 OpenAI 官方供应商
    fn is_official_provider(provider: &Provider) -> bool {
        provider
            .category
            .as_deref()
            .map(|c| c.eq_ignore_ascii_case("official"))
            .unwrap_or(false)
            || provider.name.eq_ignore_ascii_case("OpenAI Official")
    }

    /// 归一化字符串：去除首尾空白，空字符串视为 None
    fn normalize_non_empty(raw: Option<&str>) -> Option<String> {
        raw.map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
    }

    /// 从 auth JSON 值中提取 OpenAI Token（兼容多字段）
    fn extract_token_from_auth_value(auth: &Value) -> Option<String> {
        if let Some(s) = auth.as_str() {
            return Self::normalize_non_empty(Some(s));
        }

        // 优先级：API Key 字段 > access token 字段
        for field in [
            "OPENAI_API_KEY",
            "OPENAI_ACCESS_TOKEN",
            "api_key",
            "apiKey",
            "access_token",
            "accessToken",
        ] {
            if let Some(token) = Self::normalize_non_empty(auth.get(field).and_then(|v| v.as_str()))
            {
                return Some(token);
            }
        }

        None
    }

    /// 从本机 Codex live auth.json 中提取 Token（用于 official 供应商兜底）
    fn extract_live_key(&self) -> Option<String> {
        let auth_path = crate::codex_config::get_codex_auth_path();
        let content = std::fs::read_to_string(auth_path).ok()?;
        let auth_json: Value = serde_json::from_str(&content).ok()?;
        Self::extract_token_from_auth_value(&auth_json)
    }

    /// 从 TOML 文本中提取 base_url
    fn extract_base_url_from_toml(config_str: &str) -> Option<String> {
        if let Some(start) = config_str.find("base_url = \"") {
            let rest = &config_str[start + 12..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].trim_end_matches('/').to_string());
            }
        }
        if let Some(start) = config_str.find("base_url = '") {
            let rest = &config_str[start + 12..];
            if let Some(end) = rest.find('\'') {
                return Some(rest[..end].trim_end_matches('/').to_string());
            }
        }
        None
    }

    /// 从 Provider 配置中提取 API Key
    fn extract_key(&self, provider: &Provider) -> Option<String> {
        // 1. 尝试从 env 中获取
        if let Some(env) = provider.settings_config.get("env") {
            if let Some(key) =
                Self::normalize_non_empty(env.get("OPENAI_API_KEY").and_then(|v| v.as_str()))
            {
                return Some(key);
            }
            if let Some(token) =
                Self::normalize_non_empty(env.get("OPENAI_ACCESS_TOKEN").and_then(|v| v.as_str()))
            {
                return Some(token);
            }
        }

        // 2. 尝试从 auth 中获取 (Codex CLI 格式)
        if let Some(auth) = provider.settings_config.get("auth") {
            if let Some(token) = Self::extract_token_from_auth_value(auth) {
                return Some(token);
            }
        }

        // 3. 尝试直接获取
        if let Some(key) = Self::normalize_non_empty(
            provider
                .settings_config
                .get("apiKey")
                .or_else(|| provider.settings_config.get("api_key"))
                .and_then(|v| v.as_str()),
        ) {
            return Some(key);
        }

        // 4. 兼容 access_token 字段
        if let Some(token) = Self::normalize_non_empty(
            provider
                .settings_config
                .get("access_token")
                .or_else(|| provider.settings_config.get("accessToken"))
                .and_then(|v| v.as_str()),
        ) {
            return Some(token);
        }

        // 5. 尝试从 config 对象中获取
        if let Some(config) = provider.settings_config.get("config") {
            if let Some(key) = Self::normalize_non_empty(
                config
                    .get("api_key")
                    .or_else(|| config.get("apiKey"))
                    .or_else(|| config.get("OPENAI_API_KEY"))
                    .or_else(|| config.get("access_token"))
                    .or_else(|| config.get("accessToken"))
                    .and_then(|v| v.as_str()),
            ) {
                return Some(key);
            }
        }

        None
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderAdapter for CodexAdapter {
    fn name(&self) -> &'static str {
        "Codex"
    }

    fn extract_base_url(&self, provider: &Provider) -> Result<String, ProxyError> {
        // 1. 尝试直接获取 base_url 字段
        if let Some(url) = Self::normalize_non_empty(
            provider
                .settings_config
                .get("base_url")
                .and_then(|v| v.as_str()),
        ) {
            return Ok(url.trim_end_matches('/').to_string());
        }

        // 2. 尝试 baseURL
        if let Some(url) = Self::normalize_non_empty(
            provider
                .settings_config
                .get("baseURL")
                .and_then(|v| v.as_str()),
        ) {
            return Ok(url.trim_end_matches('/').to_string());
        }

        // 3. 尝试从 config 对象中获取
        if let Some(config) = provider.settings_config.get("config") {
            if let Some(url) =
                Self::normalize_non_empty(config.get("base_url").and_then(|v| v.as_str()))
            {
                return Ok(url.trim_end_matches('/').to_string());
            }

            // 尝试解析 TOML 字符串格式
            if let Some(config_str) = config.as_str() {
                if let Some(url) = Self::extract_base_url_from_toml(config_str) {
                    return Ok(url);
                }
            }
        }

        // OpenAI Official 允许省略 base_url（默认官方端点）
        if Self::is_official_provider(provider) {
            return Ok(OPENAI_OFFICIAL_BASE_URL.to_string());
        }

        Err(ProxyError::ConfigError(
            "Codex Provider 缺少 base_url 配置".to_string(),
        ))
    }

    fn extract_auth(&self, provider: &Provider) -> Option<AuthInfo> {
        if let Some(key) = self.extract_key(provider) {
            return Some(AuthInfo::new(key, AuthStrategy::Bearer));
        }

        // OpenAI Official 预设通常不在 provider 中保存 token，回退到 ~/.codex/auth.json
        if Self::is_official_provider(provider) {
            return self
                .extract_live_key()
                .map(|key| AuthInfo::new(key, AuthStrategy::Bearer));
        }

        None
    }

    fn build_url(&self, base_url: &str, endpoint: &str) -> String {
        let base_trimmed = base_url.trim_end_matches('/');
        let endpoint_trimmed = endpoint.trim_start_matches('/');

        // OpenAI/Codex 的 base_url 可能是：
        // - 纯 origin: https://api.openai.com  (需要自动补 /v1)
        // - 已含 /v1: https://api.openai.com/v1 (直接拼接)
        // - 自定义前缀: https://xxx/openai (不添加 /v1，直接拼接)

        // 检查 base_url 是否已经包含 /v1
        let already_has_v1 = base_trimmed.ends_with("/v1");

        // 检查是否是纯 origin（没有路径部分）
        let origin_only = match base_trimmed.split_once("://") {
            Some((_scheme, rest)) => !rest.contains('/'),
            None => !base_trimmed.contains('/'),
        };

        let mut url = if already_has_v1 {
            // 已经有 /v1，直接拼接
            format!("{base_trimmed}/{endpoint_trimmed}")
        } else if origin_only {
            // 纯 origin，添加 /v1
            format!("{base_trimmed}/v1/{endpoint_trimmed}")
        } else {
            // 自定义前缀，不添加 /v1，直接拼接
            format!("{base_trimmed}/{endpoint_trimmed}")
        };

        // 去除重复的 /v1/v1（可能由 base_url 与 endpoint 都带版本导致）
        while url.contains("/v1/v1") {
            url = url.replace("/v1/v1", "/v1");
        }

        url
    }

    fn add_auth_headers(&self, request: RequestBuilder, auth: &AuthInfo) -> RequestBuilder {
        request.header("Authorization", format!("Bearer {}", auth.api_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_provider(config: serde_json::Value) -> Provider {
        create_provider_with_category(config, Some("codex"))
    }

    fn create_provider_with_category(
        config: serde_json::Value,
        category: Option<&str>,
    ) -> Provider {
        Provider {
            id: "test".to_string(),
            name: "Test Codex".to_string(),
            settings_config: config,
            website_url: None,
            category: category.map(|c| c.to_string()),
            created_at: None,
            sort_index: None,
            notes: None,
            meta: None,
            icon: None,
            icon_color: None,
            in_failover_queue: false,
        }
    }

    #[test]
    fn test_extract_base_url_direct() {
        let adapter = CodexAdapter::new();
        let provider = create_provider(json!({
            "base_url": "https://api.openai.com/v1"
        }));

        let url = adapter.extract_base_url(&provider).unwrap();
        assert_eq!(url, "https://api.openai.com/v1");
    }

    #[test]
    fn test_extract_base_url_official_uses_default() {
        let adapter = CodexAdapter::new();
        let provider = create_provider_with_category(json!({}), Some("official"));

        let url = adapter.extract_base_url(&provider).unwrap();
        assert_eq!(url, "https://api.openai.com");
    }

    #[test]
    fn test_extract_base_url_missing_non_official_should_fail() {
        let adapter = CodexAdapter::new();
        let provider = create_provider_with_category(json!({}), Some("third_party"));

        let err = adapter.extract_base_url(&provider).unwrap_err();
        assert!(err.to_string().contains("缺少 base_url"));
    }

    #[test]
    fn test_extract_auth_from_auth_field() {
        let adapter = CodexAdapter::new();
        let provider = create_provider(json!({
            "auth": {
                "OPENAI_API_KEY": "sk-test-key-12345678"
            }
        }));

        let auth = adapter.extract_auth(&provider).unwrap();
        assert_eq!(auth.api_key, "sk-test-key-12345678");
        assert_eq!(auth.strategy, AuthStrategy::Bearer);
    }

    #[test]
    fn test_extract_auth_from_env() {
        let adapter = CodexAdapter::new();
        let provider = create_provider(json!({
            "env": {
                "OPENAI_API_KEY": "sk-env-key-12345678"
            }
        }));

        let auth = adapter.extract_auth(&provider).unwrap();
        assert_eq!(auth.api_key, "sk-env-key-12345678");
    }

    #[test]
    fn test_extract_auth_from_auth_access_token_field() {
        let adapter = CodexAdapter::new();
        let provider = create_provider(json!({
            "auth": {
                "access_token": "token-from-auth"
            }
        }));

        let auth = adapter.extract_auth(&provider).unwrap();
        assert_eq!(auth.api_key, "token-from-auth");
    }

    #[test]
    fn test_build_url() {
        let adapter = CodexAdapter::new();
        let url = adapter.build_url("https://api.openai.com/v1", "/responses");
        assert_eq!(url, "https://api.openai.com/v1/responses");
    }

    #[test]
    fn test_build_url_origin_adds_v1() {
        let adapter = CodexAdapter::new();
        let url = adapter.build_url("https://api.openai.com", "/responses");
        assert_eq!(url, "https://api.openai.com/v1/responses");
    }

    #[test]
    fn test_build_url_custom_prefix_no_v1() {
        let adapter = CodexAdapter::new();
        let url = adapter.build_url("https://example.com/openai", "/responses");
        assert_eq!(url, "https://example.com/openai/responses");
    }

    #[test]
    fn test_build_url_dedup_v1() {
        let adapter = CodexAdapter::new();
        // base_url 已包含 /v1，endpoint 也包含 /v1
        let url = adapter.build_url("https://www.packyapi.com/v1", "/v1/responses");
        assert_eq!(url, "https://www.packyapi.com/v1/responses");
    }

    // 官方客户端检测测试
    #[test]
    fn test_is_official_client_vscode() {
        assert!(CodexAdapter::is_official_client("codex_vscode/1.0.0"));
        assert!(CodexAdapter::is_official_client("codex_vscode/2.3.4"));
        assert!(CodexAdapter::is_official_client("codex_vscode/0.1"));
    }

    #[test]
    fn test_is_official_client_cli() {
        assert!(CodexAdapter::is_official_client("codex_cli_rs/1.0.0"));
        assert!(CodexAdapter::is_official_client("codex_cli_rs/0.5.2"));
    }

    #[test]
    fn test_is_not_official_client() {
        assert!(!CodexAdapter::is_official_client("Mozilla/5.0"));
        assert!(!CodexAdapter::is_official_client("curl/7.68.0"));
        assert!(!CodexAdapter::is_official_client("python-requests/2.25.1"));
        assert!(!CodexAdapter::is_official_client("codex_other/1.0.0"));
        assert!(!CodexAdapter::is_official_client(""));
    }

    #[test]
    fn test_is_official_client_partial_match() {
        // 必须从开头匹配
        assert!(!CodexAdapter::is_official_client("some codex_vscode/1.0.0"));
        assert!(!CodexAdapter::is_official_client(
            "prefix_codex_cli_rs/1.0.0"
        ));
    }
}
