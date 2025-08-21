-- Emulation Sessions Table
CREATE TABLE emulation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    emulating_user_id UUID NOT NULL REFERENCES auth_users(id),
    target_user_id UUID NOT NULL REFERENCES auth_users(id),
    session_token VARCHAR(500) NOT NULL,
    start_time TIMESTAMP NOT NULL DEFAULT NOW(),
    end_time TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    reason TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Emulation Audit Logs Table
CREATE TABLE emulation_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    emulation_session_id UUID REFERENCES emulation_sessions(id),
    emulating_user_id UUID NOT NULL REFERENCES auth_users(id),
    target_user_id UUID NOT NULL REFERENCES auth_users(id),
    action_type VARCHAR(100) NOT NULL,
    action_details JSONB,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT NOW(),
    success BOOLEAN DEFAULT true,
    error_message TEXT
);

-- Indexes for better performance
CREATE INDEX idx_emulation_sessions_emulating_user_id ON emulation_sessions(emulating_user_id);
CREATE INDEX idx_emulation_sessions_target_user_id ON emulation_sessions(target_user_id);
CREATE INDEX idx_emulation_sessions_status ON emulation_sessions(status);
CREATE INDEX idx_emulation_sessions_session_token ON emulation_sessions(session_token);
CREATE INDEX idx_emulation_audit_logs_session_id ON emulation_audit_logs(emulation_session_id);
CREATE INDEX idx_emulation_audit_logs_emulating_user_id ON emulation_audit_logs(emulating_user_id);
CREATE INDEX idx_emulation_audit_logs_timestamp ON emulation_audit_logs(timestamp); 