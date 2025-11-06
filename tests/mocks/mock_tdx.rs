// Mock TDX client for testing
// TDX requires hardware, so we always mock it

use anyhow::Result;
use base64;

/// Mock TDX client for testing
pub struct MockTdxClient {
    pub should_succeed: bool,
    pub mock_quote: Option<Vec<u8>>,
    pub mock_event_log: Option<String>,
}

impl MockTdxClient {
    pub fn new() -> Self {
        Self {
            should_succeed: true,
            mock_quote: Some(vec![0u8; 1024]), // Minimum TDX quote size
            mock_event_log: Some(r#"{"environment_mode": "dev"}"#.to_string()),
        }
    }

    pub fn with_success(mut self, succeed: bool) -> Self {
        self.should_succeed = succeed;
        self
    }

    pub fn with_quote(mut self, quote: Vec<u8>) -> Self {
        self.mock_quote = Some(quote);
        self
    }

    pub fn with_event_log(mut self, event_log: String) -> Self {
        self.mock_event_log = Some(event_log);
        self
    }

    /// Mock getting TDX quote
    pub async fn get_quote(&self, _report_data: &[u8]) -> Result<MockQuoteResponse> {
        if !self.should_succeed {
            return Err(anyhow::anyhow!("Mock TDX: Failed to get quote"));
        }

        Ok(MockQuoteResponse {
            quote: self.mock_quote.clone().unwrap_or_else(|| vec![0u8; 1024]),
            event_log: self.mock_event_log.clone().unwrap_or_else(|| "{}".to_string()),
            rtmrs: vec![
                "0".repeat(96),
                "0".repeat(96),
                "0".repeat(96),
                "0".repeat(96),
            ],
        })
    }
}

pub struct MockQuoteResponse {
    pub quote: Vec<u8>,
    pub event_log: String,
    pub rtmrs: Vec<String>,
}

impl Default for MockTdxClient {
    fn default() -> Self {
        Self::new()
    }
}

