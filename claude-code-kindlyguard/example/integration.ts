/**
 * Example of how Claude Code would integrate with the KindlyGuard extension
 */

import { activate, deactivate } from '../src/extension';

// Mock Claude Code API for demonstration
const mockClaudeCodeAPI = {
  createFloatingWidget: (options: any) => ({
    update: (content: string) => console.log('Widget updated:', content.substring(0, 50) + '...'),
    show: () => console.log('Widget shown'),
    hide: () => console.log('Widget hidden'),
    dispose: () => console.log('Widget disposed')
  }),
  
  showNotification: (message: string, options?: any) => {
    console.log(`[${options?.type || 'info'}] ${message}`);
  },
  
  registerCommand: (command: string, callback: () => void) => {
    console.log(`Command registered: ${command}`);
    // In real Claude Code, this would register with the command palette
  }
};

// Example usage
async function demo() {
  console.log('=== KindlyGuard Extension Demo ===\n');
  
  // Activate the extension
  const extension = activate(mockClaudeCodeAPI);
  
  // Simulate some time passing
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Simulate receiving a threat via WebSocket
  console.log('\nSimulating threat detection...');
  
  // Simulate keyboard shortcut press
  console.log('\nSimulating Ctrl+Shift+S press...');
  
  // Deactivate
  console.log('\nDeactivating extension...');
  deactivate(extension);
}

// Run the demo
demo().catch(console.error);