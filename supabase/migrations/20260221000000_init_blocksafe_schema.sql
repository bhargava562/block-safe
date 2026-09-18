-- ============================================================
-- BlockSafe Database Schema Migration
-- Defines scam_sessions and session_messages tables,
-- indexes, Row Level Security (RLS), and Realtime publication.
-- ============================================================

-- 1. Create scam_sessions table
CREATE TABLE IF NOT EXISTS public.scam_sessions (
    id TEXT PRIMARY KEY,
    campaign_id TEXT,
    scam_type TEXT NOT NULL DEFAULT 'phishing',
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'active',
    turns_completed INTEGER NOT NULL DEFAULT 0,
    initial_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Create session_messages table
CREATE TABLE IF NOT EXISTS public.session_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id TEXT NOT NULL REFERENCES public.scam_sessions(id) ON DELETE CASCADE,
    sender_role TEXT NOT NULL,
    message_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Performance Indexes
CREATE INDEX IF NOT EXISTS idx_scam_sessions_status ON public.scam_sessions(status);
CREATE INDEX IF NOT EXISTS idx_scam_sessions_created_at ON public.scam_sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_messages_session_id ON public.session_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_session_messages_created_at ON public.session_messages(created_at ASC);

-- 4. Enable Row Level Security (RLS)
ALTER TABLE public.scam_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.session_messages ENABLE ROW LEVEL SECURITY;

-- 5. RLS Policies: Allow anon read-only (used by React Dashboard via anon key)
DROP POLICY IF EXISTS "Anon Read scam_sessions" ON public.scam_sessions;
CREATE POLICY "Anon Read scam_sessions" 
    ON public.scam_sessions 
    FOR SELECT 
    TO anon 
    USING (true);

DROP POLICY IF EXISTS "Anon Read session_messages" ON public.session_messages;
CREATE POLICY "Anon Read session_messages" 
    ON public.session_messages 
    FOR SELECT 
    TO anon 
    USING (true);

-- 6. RLS Policies: Full access for service_role and authenticated users
DROP POLICY IF EXISTS "Service Role Full Access scam_sessions" ON public.scam_sessions;
CREATE POLICY "Service Role Full Access scam_sessions" 
    ON public.scam_sessions 
    FOR ALL 
    TO service_role 
    USING (true) 
    WITH CHECK (true);

DROP POLICY IF EXISTS "Service Role Full Access session_messages" ON public.session_messages;
CREATE POLICY "Service Role Full Access session_messages" 
    ON public.session_messages 
    FOR ALL 
    TO service_role 
    USING (true) 
    WITH CHECK (true);

-- 7. Realtime Replication for Dashboard Feed
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND tablename = 'scam_sessions'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.scam_sessions;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime' AND tablename = 'session_messages'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.session_messages;
    END IF;
END $$;
