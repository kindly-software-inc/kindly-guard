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
#[cfg(feature = "enhanced")]
use crate::enhanced_impl::EnhancedComponentFactory;
use crate::permissions::{
    ToolPermissionManager, PermissionRules, ThreatLevel,
    StandardPermissionManager, default_tool_definitions, ClientPermissions,
};
#[cfg(feature = "enhanced")]
use crate::permissions::EnhancedPermissionManager;
use crate::telemetry::{TelemetryProvider, TelemetryProviderFactory, standard::StandardTelemetryFactory};
#[cfg(feature = "enhanced")]
use crate::telemetry::enhanced::EnhancedTelemetryFactory;
use crate::storage::{StorageProvider, StorageProviderFactory, DefaultStorageFactory};
use crate::plugins::{PluginManagerTrait, PluginManagerFactory, DefaultPluginManagerFactory};
use crate::audit::{AuditLogger, AuditLoggerFactory, DefaultAuditLoggerFactory};

/// Selects appropriate component implementations based on configuration
pub struct ComponentSelector {
    factory: Box<dyn SecurityComponentFactory>,
}

impl ComponentSelector {
    /// Create a new component selector
    pub fn new(config: &Config) -> Self {
        // Choose factory based on event processor configuration
        #[cfg(feature = "enhanced")]
        let factory: Box<dyn SecurityComponentFactory> = if config.is_event_processor_enabled() {
            tracing::info!("Performance mode: ENABLED");
            tracing::debug!("Advanced analytics active");
            Box::new(EnhancedComponentFactory)
        } else {
            tracing::info!("Performance mode: STANDARD");
            Box::new(StandardComponentFactory)
        };
        
        #[cfg(not(feature = "enhanced"))]
        let factory: Box<dyn SecurityComponentFactory> = {
            if config.is_event_processor_enabled() {
                tracing::warn!("Enhanced mode requested but not available - using standard mode");
            }
            tracing::info!("Performance mode: STANDARD");
            Box::new(StandardComponentFactory)
        };
        
        Self { factory }
    }
    
    /// Create event processor
    pub fn create_event_processor(&self, config: &Config, storage: Arc<dyn StorageProvider>) -> Result<Arc<dyn SecurityEventProcessor>> {
        self.factory.create_event_processor(config, storage)
    }
    
    /// Create scanner
    pub fn create_scanner(&self, config: &Config) -> Result<Arc<dyn EnhancedScanner>> {
        self.factory.create_scanner(config)
    }
    
    /// Create correlation engine
    pub fn create_correlation_engine(&self, config: &Config, storage: Arc<dyn StorageProvider>) -> Result<Arc<dyn CorrelationEngine>> {
        self.factory.create_correlation_engine(config, storage)
    }
    
    /// Create rate limiter
    pub fn create_rate_limiter(&self, config: &Config, storage: Arc<dyn StorageProvider>) -> Result<Arc<dyn RateLimiter>> {
        self.factory.create_rate_limiter(config, storage)
    }
    
    /// Check if enhanced mode is active
    pub fn is_enhanced_mode(&self, config: &Config) -> bool {
        config.is_event_processor_enabled()
    }
}

/// Global component manager for easy access
pub struct ComponentManager {
    event_processor: Arc<dyn SecurityEventProcessor>,
    scanner: Arc<dyn EnhancedScanner>,
    correlation_engine: Arc<dyn CorrelationEngine>,
    rate_limiter: Arc<dyn RateLimiter>,
    permission_manager: Arc<dyn ToolPermissionManager>,
    telemetry_provider: Arc<dyn TelemetryProvider>,
    storage_provider: Arc<dyn StorageProvider>,
    plugin_manager: Arc<dyn PluginManagerTrait>,
    audit_logger: Arc<dyn AuditLogger>,
    enhanced_mode: bool,
}

impl ComponentManager {
    /// Create a new component manager with all components
    pub fn new(config: &Config) -> Result<Self> {
        let selector = ComponentSelector::new(config);
        
        // Create permission rules
        let permission_rules = PermissionRules {
            default_permissions: ClientPermissions {
                max_threat_level: ThreatLevel::Medium,
                ..Default::default()
            },
            tools: default_tool_definitions(),
            category_rules: Default::default(),
            global_deny_list: Default::default(),
        };
        
        // Create permission manager based on mode
        #[cfg(feature = "enhanced")]
        let permission_manager: Arc<dyn ToolPermissionManager> = if config.is_event_processor_enabled() {
            Arc::new(EnhancedPermissionManager::new(permission_rules))
        } else {
            Arc::new(StandardPermissionManager::new(permission_rules))
        };
        
        #[cfg(not(feature = "enhanced"))]
        let permission_manager: Arc<dyn ToolPermissionManager> = 
            Arc::new(StandardPermissionManager::new(permission_rules));
        
        // Create storage provider first
        let storage_factory = DefaultStorageFactory;
        let storage_provider = storage_factory.create(&config.storage)?;
        
        // Create event processor with storage
        let event_processor = selector.create_event_processor(config, storage_provider.clone())?;
        
        // Create telemetry provider
        #[cfg(feature = "enhanced")]
        let telemetry_factory: Box<dyn TelemetryProviderFactory> = if config.is_event_processor_enabled() {
            Box::new(EnhancedTelemetryFactory::new(event_processor.clone()))
        } else {
            Box::new(StandardTelemetryFactory)
        };
        
        #[cfg(not(feature = "enhanced"))]
        let telemetry_factory: Box<dyn TelemetryProviderFactory> = Box::new(StandardTelemetryFactory);
        
        let telemetry_provider = telemetry_factory.create(&config.telemetry)?;
        
        // Create plugin manager
        let plugin_factory = DefaultPluginManagerFactory;
        let plugin_manager = plugin_factory.create(&config.plugins)?;
        
        // Create audit logger
        let audit_factory = DefaultAuditLoggerFactory;
        let audit_logger = audit_factory.create(&config.audit)?;
        
        Ok(Self {
            event_processor,
            scanner: selector.create_scanner(config)?,
            correlation_engine: selector.create_correlation_engine(config, storage_provider.clone())?,
            rate_limiter: selector.create_rate_limiter(config, storage_provider.clone())?,
            permission_manager,
            telemetry_provider,
            storage_provider,
            plugin_manager,
            audit_logger,
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
    
    /// Get permission manager
    pub fn permission_manager(&self) -> &Arc<dyn ToolPermissionManager> {
        &self.permission_manager
    }
    
    /// Get telemetry provider
    pub fn telemetry_provider(&self) -> &Arc<dyn TelemetryProvider> {
        &self.telemetry_provider
    }
    
    /// Get storage provider
    pub fn storage_provider(&self) -> &Arc<dyn StorageProvider> {
        &self.storage_provider
    }
    
    /// Get plugin manager
    pub fn plugin_manager(&self) -> &Arc<dyn PluginManagerTrait> {
        &self.plugin_manager
    }
    
    /// Get audit logger
    pub fn audit_logger(&self) -> &Arc<dyn AuditLogger> {
        &self.audit_logger
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