//! Component selector for choosing between standard and enhanced implementations
//! This provides the abstraction layer that hides the implementation details

use std::sync::Arc;
use anyhow::Result;
use crate::config::Config;
use crate::traits::{
    SecurityComponentFactory, SecurityEventProcessor, EnhancedScanner, 
    CorrelationEngine, RateLimiter
};
use crate::standard_impl::StandardComponentFactory;
use crate::enhanced_impl::EnhancedComponentFactory;

/// Selects appropriate component implementations based on configuration
pub struct ComponentSelector {
    factory: Box<dyn SecurityComponentFactory>,
}

impl ComponentSelector {
    /// Create a new component selector
    pub fn new(config: &Config) -> Self {
        // Choose factory based on event processor configuration
        let factory: Box<dyn SecurityComponentFactory> = if config.event_processor.enabled {
            tracing::info!("Performance mode: ENABLED");
            tracing::debug!("Advanced analytics active");
            Box::new(EnhancedComponentFactory)
        } else {
            tracing::info!("Performance mode: STANDARD");
            Box::new(StandardComponentFactory)
        };
        
        Self { factory }
    }
    
    /// Create event processor
    pub fn create_event_processor(&self, config: &Config) -> Result<Arc<dyn SecurityEventProcessor>> {
        self.factory.create_event_processor(config)
    }
    
    /// Create scanner
    pub fn create_scanner(&self, config: &Config) -> Result<Arc<dyn EnhancedScanner>> {
        self.factory.create_scanner(config)
    }
    
    /// Create correlation engine
    pub fn create_correlation_engine(&self, config: &Config) -> Result<Arc<dyn CorrelationEngine>> {
        self.factory.create_correlation_engine(config)
    }
    
    /// Create rate limiter
    pub fn create_rate_limiter(&self, config: &Config) -> Result<Arc<dyn RateLimiter>> {
        self.factory.create_rate_limiter(config)
    }
    
    /// Check if enhanced mode is active
    pub fn is_enhanced_mode(&self, config: &Config) -> bool {
        config.event_processor.enabled
    }
}

/// Global component manager for easy access
pub struct ComponentManager {
    event_processor: Arc<dyn SecurityEventProcessor>,
    scanner: Arc<dyn EnhancedScanner>,
    correlation_engine: Arc<dyn CorrelationEngine>,
    rate_limiter: Arc<dyn RateLimiter>,
    enhanced_mode: bool,
}

impl ComponentManager {
    /// Create a new component manager with all components
    pub fn new(config: &Config) -> Result<Self> {
        let selector = ComponentSelector::new(config);
        
        Ok(Self {
            event_processor: selector.create_event_processor(config)?,
            scanner: selector.create_scanner(config)?,
            correlation_engine: selector.create_correlation_engine(config)?,
            rate_limiter: selector.create_rate_limiter(config)?,
            enhanced_mode: selector.is_enhanced_mode(config),
        })
    }
    
    /// Get event processor
    pub fn event_processor(&self) -> &Arc<dyn SecurityEventProcessor> {
        &self.event_processor
    }
    
    /// Get scanner
    pub fn scanner(&self) -> &Arc<dyn EnhancedScanner> {
        &self.scanner
    }
    
    /// Get correlation engine
    pub fn correlation_engine(&self) -> &Arc<dyn CorrelationEngine> {
        &self.correlation_engine
    }
    
    /// Get rate limiter
    pub fn rate_limiter(&self) -> &Arc<dyn RateLimiter> {
        &self.rate_limiter
    }
    
    /// Check if running in enhanced mode
    pub fn is_enhanced_mode(&self) -> bool {
        self.enhanced_mode
    }
    
    /// Get performance description for logging
    pub fn performance_description(&self) -> &'static str {
        if self.enhanced_mode {
            "optimized performance mode"
        } else {
            "standard performance mode"
        }
    }
}