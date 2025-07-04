#!/usr/bin/env python3
import os
import subprocess
import json
from collections import defaultdict
from pathlib import Path

def count_lines(file_path):
    """Count total lines, code lines, and comment lines in a file."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    total_lines = len(lines)
    code_lines = 0
    comment_lines = 0
    in_block_comment = False
    
    for line in lines:
        stripped = line.strip()
        
        # Handle block comments
        if stripped.startswith('/*'):
            in_block_comment = True
        if in_block_comment:
            comment_lines += 1
            if stripped.endswith('*/'):
                in_block_comment = False
            continue
            
        # Skip empty lines
        if not stripped:
            continue
            
        # Count single-line comments
        if stripped.startswith('//'):
            comment_lines += 1
        else:
            code_lines += 1
    
    return total_lines, code_lines, comment_lines

def analyze_rust_file(file_path):
    """Analyze a Rust file for traits, implementations, and functions."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Count various constructs
    trait_count = content.count('trait ') + content.count('trait\n')
    impl_count = content.count('impl ') + content.count('impl<')
    fn_count = content.count('fn ') + content.count('pub fn ') + content.count('async fn ')
    struct_count = content.count('struct ') + content.count('pub struct ')
    enum_count = content.count('enum ') + content.count('pub enum ')
    
    # Count trait implementations
    trait_impl_count = len([line for line in content.split('\n') if 'impl' in line and 'for' in line])
    
    return {
        'traits': trait_count,
        'impls': impl_count,
        'trait_impls': trait_impl_count,
        'functions': fn_count,
        'structs': struct_count,
        'enums': enum_count
    }

def analyze_module(module_path):
    """Analyze a module directory."""
    stats = {
        'total_lines': 0,
        'code_lines': 0,
        'comment_lines': 0,
        'files': 0,
        'traits': 0,
        'impls': 0,
        'trait_impls': 0,
        'functions': 0,
        'structs': 0,
        'enums': 0,
        'submodules': []
    }
    
    for root, dirs, files in os.walk(module_path):
        # Skip target and other build directories
        dirs[:] = [d for d in dirs if d not in ['target', 'node_modules', '.git']]
        
        for file in files:
            if file.endswith('.rs'):
                file_path = os.path.join(root, file)
                total, code, comments = count_lines(file_path)
                constructs = analyze_rust_file(file_path)
                
                stats['total_lines'] += total
                stats['code_lines'] += code
                stats['comment_lines'] += comments
                stats['files'] += 1
                
                for key, value in constructs.items():
                    stats[key] += value
    
    return stats

def main():
    base_path = '/home/samuel/kindly-guard/kindly-guard-server/src'
    
    # Define key modules to analyze
    modules = {
        'scanner': os.path.join(base_path, 'scanner'),
        'neutralizer': os.path.join(base_path, 'neutralizer'),
        'transport': os.path.join(base_path, 'transport'),
        'resilience': os.path.join(base_path, 'resilience'),
        'storage': os.path.join(base_path, 'storage'),
        'telemetry': os.path.join(base_path, 'telemetry'),
        'permissions': os.path.join(base_path, 'permissions'),
        'audit': os.path.join(base_path, 'audit'),
        'plugins': os.path.join(base_path, 'plugins'),
        'shield': os.path.join(base_path, 'shield'),
        'web': os.path.join(base_path, 'web'),
        'protocol': os.path.join(base_path, 'protocol'),
        'security': os.path.join(base_path, 'security'),
        'metrics': os.path.join(base_path, 'metrics'),
        'cli': os.path.join(base_path, 'cli'),
        'error': os.path.join(base_path, 'error'),
        'enhanced_impl': os.path.join(base_path, 'enhanced_impl')
    }
    
    # Analyze core files
    core_files = {
        'traits.rs': os.path.join(base_path, 'traits.rs'),
        'lib.rs': os.path.join(base_path, 'lib.rs'),
        'main.rs': os.path.join(base_path, 'main.rs'),
        'server.rs': os.path.join(base_path, 'server.rs'),
        'config.rs': os.path.join(base_path, 'config.rs'),
        'component_selector.rs': os.path.join(base_path, 'component_selector.rs'),
        'standard_impl.rs': os.path.join(base_path, 'standard_impl.rs'),
        'event_processor.rs': os.path.join(base_path, 'event_processor.rs'),
        'rate_limit.rs': os.path.join(base_path, 'rate_limit.rs'),
        'signing.rs': os.path.join(base_path, 'signing.rs'),
        'logging.rs': os.path.join(base_path, 'logging.rs'),
        'daemon.rs': os.path.join(base_path, 'daemon.rs'),
        'auth.rs': os.path.join(base_path, 'auth.rs'),
        'versioning.rs': os.path.join(base_path, 'versioning.rs')
    }
    
    print("# KindlyGuard Code Structure Analysis\n")
    print("## Core Files Analysis\n")
    
    total_stats = defaultdict(int)
    
    for name, path in core_files.items():
        if os.path.exists(path):
            total, code, comments = count_lines(path)
            constructs = analyze_rust_file(path)
            
            print(f"### {name}")
            print(f"- Total lines: {total}")
            print(f"- Code lines: {code}")
            print(f"- Comment lines: {comments}")
            print(f"- Traits: {constructs['traits']}")
            print(f"- Implementations: {constructs['impls']}")
            print(f"- Functions: {constructs['functions']}")
            print()
            
            total_stats['total_lines'] += total
            total_stats['code_lines'] += code
            total_stats['comment_lines'] += comments
            total_stats['files'] += 1
    
    print("\n## Module Analysis\n")
    
    module_stats = {}
    for module_name, module_path in modules.items():
        if os.path.exists(module_path):
            stats = analyze_module(module_path)
            module_stats[module_name] = stats
            
            print(f"### {module_name.upper()} Module")
            print(f"- Files: {stats['files']}")
            print(f"- Total lines: {stats['total_lines']}")
            print(f"- Code lines: {stats['code_lines']}")
            print(f"- Comment lines: {stats['comment_lines']}")
            print(f"- Traits defined: {stats['traits']}")
            print(f"- Trait implementations: {stats['trait_impls']}")
            print(f"- Structs: {stats['structs']}")
            print(f"- Enums: {stats['enums']}")
            print(f"- Functions: {stats['functions']}")
            print()
            
            # Add to totals
            for key, value in stats.items():
                if isinstance(value, int):
                    total_stats[key] += value
    
    print("\n## Overall Statistics\n")
    print(f"- Total files analyzed: {total_stats['files']}")
    print(f"- Total lines: {total_stats['total_lines']}")
    print(f"- Code lines: {total_stats['code_lines']}")
    print(f"- Comment lines: {total_stats['comment_lines']}")
    print(f"- Comment ratio: {total_stats['comment_lines'] / total_stats['total_lines'] * 100:.1f}%")
    print(f"- Total traits defined: {total_stats['traits']}")
    print(f"- Total trait implementations: {total_stats['trait_impls']}")
    print(f"- Total structs: {total_stats['structs']}")
    print(f"- Total enums: {total_stats['enums']}")
    print(f"- Total functions: {total_stats['functions']}")
    
    # Analyze trait usage patterns
    print("\n## Trait-based Architecture Analysis\n")
    
    # Count factory methods
    factory_count = 0
    for name, path in {**core_files, **{m: os.path.join(base_path, m, 'mod.rs') for m in modules}}.items():
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                factory_count += content.count('fn create_')
                factory_count += content.count('Factory')
    
    print(f"- Factory methods/types found: {factory_count}")
    print(f"- Standard vs Enhanced pattern used: {'enhanced_impl' in module_stats}")
    
    # Save detailed report as JSON
    report = {
        'core_files': {name: analyze_rust_file(path) if os.path.exists(path) else {} 
                      for name, path in core_files.items()},
        'modules': module_stats,
        'totals': dict(total_stats),
        'factory_count': factory_count
    }
    
    with open('/home/samuel/kindly-guard/code_structure_metrics.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nDetailed metrics saved to code_structure_metrics.json")

if __name__ == '__main__':
    main()