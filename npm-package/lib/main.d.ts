/**
 * KindlyGuard TypeScript Definitions
 */

import { ChildProcess } from 'child_process';

export interface KindlyGuardOptions {
  /** Enable stdio mode for MCP communication (default: true) */
  stdio?: boolean;
  /** Path to configuration file */
  config?: string | null;
  /** Enable shield UI (default: false) */
  shield?: boolean;
  /** Log level: 'debug' | 'info' | 'warn' | 'error' (default: 'info') */
  logLevel?: string;
  /** Command timeout in milliseconds (default: 30000) */
  timeout?: number;
}

export interface ScanOptions {
  /** Treat input as file path instead of text */
  file?: boolean;
  /** Output format: 'json' | 'text' (default: 'text') */
  format?: 'json' | 'text';
  /** Include detailed threat information */
  detailed?: boolean;
}

export interface ScanResult {
  exitCode: number;
  threatsFound: boolean;
  stdout: string;
  stderr: string;
}

export interface JsonScanResult {
  threats: Threat[];
  summary: {
    total_threats: number;
    high_severity: number;
    medium_severity: number;
    low_severity: number;
  };
}

export interface Threat {
  type: string;
  severity: 'high' | 'medium' | 'low';
  position?: number;
  message: string;
  details?: any;
}

export interface StatusResult {
  running: boolean;
  version: string;
  uptime?: number;
  stats?: {
    requests_processed: number;
    threats_blocked: number;
    errors: number;
  };
}

export declare class KindlyGuard {
  constructor(options?: KindlyGuardOptions);
  
  /** Start the KindlyGuard MCP server */
  start(): ChildProcess;
  
  /** Stop the server gracefully */
  stop(timeout?: number): Promise<void>;
  
  /** Get server status and statistics */
  status(): Promise<StatusResult>;
  
  /** Scan text or file for threats */
  scan(input: string, options?: ScanOptions): Promise<ScanResult | JsonScanResult>;
  
  /** Get binary version information */
  version(): Promise<string>;
}

/** Create a new KindlyGuard instance */
export declare function createKindlyGuard(options?: KindlyGuardOptions): KindlyGuard;

/** Quick scan helper */
export declare function scan(input: string, options?: ScanOptions): Promise<ScanResult | JsonScanResult>;

/** Start server helper */
export declare function startServer(options?: KindlyGuardOptions): ChildProcess;

/** Platform detection utilities */
export declare namespace platform {
  function getPlatform(): string;
  function getArchitecture(): string;
  function getPlatformKey(): string;
  function getPackageName(): string;
  function getBinaryName(name: string): string;
  function getBinaryPath(name: string, baseDir?: string): string;
  function isMusl(): boolean;
  function validateBinary(binaryPath: string): { valid: boolean; error?: string };
  function downloadUrl(version?: string): string;
  const SUPPORTED_PLATFORMS: string[];
}

export default createKindlyGuard;