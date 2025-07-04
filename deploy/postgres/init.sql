-- KindlyGuard PostgreSQL initialization script

-- Create database if not exists (handled by POSTGRES_DB env var)
-- CREATE DATABASE kindlyguard;

-- Connect to the database
\c kindlyguard;

-- Create schema
CREATE SCHEMA IF NOT EXISTS kindly_guard;

-- Set search path
SET search_path TO kindly_guard, public;

-- Create tables for threat data
CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    threat_id UUID NOT NULL UNIQUE,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source VARCHAR(255),
    description TEXT,
    raw_data JSONB,
    neutralized BOOLEAN DEFAULT FALSE,
    neutralized_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    CONSTRAINT valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Create indexes
CREATE INDEX idx_threats_detected_at ON threats(detected_at DESC);
CREATE INDEX idx_threats_threat_type ON threats(threat_type);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_threats_source ON threats(source);
CREATE INDEX idx_threats_neutralized ON threats(neutralized);
CREATE INDEX idx_threats_metadata ON threats USING gin(metadata);

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    ip_address INET,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    result VARCHAR(20) NOT NULL,
    details JSONB,
    CONSTRAINT valid_result CHECK (result IN ('success', 'failure', 'error'))
);

-- Create indexes for audit log
CREATE INDEX idx_audit_log_event_time ON audit_log(event_time DESC);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_result ON audit_log(result);

-- Create statistics table
CREATE TABLE IF NOT EXISTS statistics (
    id BIGSERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_type VARCHAR(50) NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    dimensions JSONB DEFAULT '{}'::jsonb,
    UNIQUE(metric_name, recorded_at, dimensions)
);

-- Create indexes for statistics
CREATE INDEX idx_statistics_metric_name ON statistics(metric_name);
CREATE INDEX idx_statistics_recorded_at ON statistics(recorded_at DESC);
CREATE INDEX idx_statistics_dimensions ON statistics USING gin(dimensions);

-- Create function for cleaning old data
CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    -- Delete threats older than 90 days
    DELETE FROM threats WHERE detected_at < NOW() - INTERVAL '90 days';
    
    -- Delete audit logs older than 180 days
    DELETE FROM audit_log WHERE event_time < NOW() - INTERVAL '180 days';
    
    -- Delete statistics older than 30 days
    DELETE FROM statistics WHERE recorded_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Create periodic cleanup job (requires pg_cron extension)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('cleanup-old-data', '0 2 * * *', 'SELECT cleanup_old_data();');

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA kindly_guard TO kindlyguard;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA kindly_guard TO kindlyguard;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA kindly_guard TO kindlyguard;