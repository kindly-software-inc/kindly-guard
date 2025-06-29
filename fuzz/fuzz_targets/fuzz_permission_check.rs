#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{permissions::*, ThreatLevel};
use arbitrary::{Arbitrary, Unstructured};
use serde_json::json;

// Arbitrary permission scenarios
#[derive(Debug, Clone)]
struct PermissionScenario {
    client_id: String,
    tool_name: String,
    threat_level: ThreatLevel,
    authenticated: bool,
    custom_rules: Vec<CustomRule>,
}

#[derive(Debug, Clone)]
struct CustomRule {
    pattern: String,
    permission: Permission,
}

impl<'a> Arbitrary<'a> for ThreatLevel {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(ThreatLevel::None),
            1 => Ok(ThreatLevel::Low),
            2 => Ok(ThreatLevel::Medium),
            _ => Ok(ThreatLevel::High),
        }
    }
}

impl<'a> Arbitrary<'a> for Permission {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            Ok(Permission::Allow)
        } else {
            Ok(Permission::Deny(u.arbitrary::<String>()?))
        }
    }
}

impl<'a> Arbitrary<'a> for CustomRule {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(CustomRule {
            pattern: u.arbitrary::<String>()?,
            permission: u.arbitrary::<Permission>()?,
        })
    }
}

impl<'a> Arbitrary<'a> for PermissionScenario {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_rules = u.int_in_range(0..=10)?;
        let mut custom_rules = Vec::new();
        for _ in 0..num_rules {
            custom_rules.push(u.arbitrary::<CustomRule>()?);
        }
        
        Ok(PermissionScenario {
            client_id: u.arbitrary::<String>()?,
            tool_name: u.arbitrary::<String>()?,
            threat_level: u.arbitrary::<ThreatLevel>()?,
            authenticated: u.arbitrary::<bool>()?,
            custom_rules,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    // Test with raw string inputs
    let input = String::from_utf8_lossy(data);
    
    // Create permission manager with default config
    let config = PermissionConfig {
        require_auth: true,
        default_permission: Permission::Deny("Not authorized".to_string()),
        role_permissions: Default::default(),
        custom_rules: vec![],
    };
    
    if let Ok(manager) = ToolPermissionManager::new(config) {
        // Test basic permission check
        let context = PermissionContext {
            authenticated: false,
            threat_level: ThreatLevel::None,
            request_metadata: Default::default(),
        };
        
        let _ = manager.check_permission(&input, "scan_text", &context);
        
        // Test with various threat levels
        for threat_level in [ThreatLevel::None, ThreatLevel::Low, ThreatLevel::Medium, ThreatLevel::High] {
            let context = PermissionContext {
                authenticated: true,
                threat_level,
                request_metadata: Default::default(),
            };
            let _ = manager.check_permission(&input, &input, &context);
        }
    }
    
    // Test with generated scenarios
    let mut u = Unstructured::new(data);
    if let Ok(scenario) = PermissionScenario::arbitrary(&mut u) {
        // Create config with custom rules
        let mut config = PermissionConfig {
            require_auth: scenario.authenticated,
            default_permission: Permission::Deny("Default deny".to_string()),
            role_permissions: Default::default(),
            custom_rules: vec![],
        };
        
        // Add custom rules
        for rule in scenario.custom_rules {
            config.custom_rules.push(PermissionRule {
                client_pattern: Some(rule.pattern.clone()),
                tool_pattern: Some(rule.pattern),
                permission: rule.permission,
                conditions: vec![],
            });
        }
        
        if let Ok(manager) = ToolPermissionManager::new(config) {
            let context = PermissionContext {
                authenticated: scenario.authenticated,
                threat_level: scenario.threat_level,
                request_metadata: json!({
                    "user_agent": String::from_utf8_lossy(data),
                    "random_data": data.to_vec(),
                }),
            };
            
            // Should not panic
            let _ = manager.check_permission(&scenario.client_id, &scenario.tool_name, &context);
            
            // Test with empty strings
            let _ = manager.check_permission("", "", &context);
            
            // Test with very long strings
            let long_client = scenario.client_id.repeat(100);
            let long_tool = scenario.tool_name.repeat(100);
            let _ = manager.check_permission(&long_client, &long_tool, &context);
            
            // Test with special characters
            let special_client = format!("{}\n\r\t\0{}", scenario.client_id, scenario.client_id);
            let _ = manager.check_permission(&special_client, &scenario.tool_name, &context);
        }
    }
    
    // Test permission rule parsing
    if data.len() > 0 {
        // Test regex patterns
        let pattern = String::from_utf8_lossy(data);
        let rule = PermissionRule {
            client_pattern: Some(pattern.to_string()),
            tool_pattern: Some(format!(".*{}.*", pattern)),
            permission: Permission::Allow,
            conditions: vec![],
        };
        
        let config = PermissionConfig {
            require_auth: false,
            default_permission: Permission::Deny("Default".to_string()),
            role_permissions: Default::default(),
            custom_rules: vec![rule],
        };
        
        // Should handle invalid regex gracefully
        let _ = ToolPermissionManager::new(config);
    }
});