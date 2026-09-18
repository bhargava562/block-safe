#!/usr/bin/env node
/**
 * BlockSafe Supabase Migration Runner
 * 
 * Reads credentials from root .env (VIEW ONLY - does not edit .env)
 * Applies SQL migration files to Supabase and verifies table connectivity.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const ENV_PATH = path.join(ROOT_DIR, '.env');
const MIGRATION_PATH = path.join(__dirname, 'migrations', '01_init_blocksafe_schema.sql');

function loadEnv() {
    if (!fs.existsSync(ENV_PATH)) {
        console.error(`[ERROR] .env file not found at ${ENV_PATH}`);
        process.exit(1);
    }
    const envContent = fs.readFileSync(ENV_PATH, 'utf-8');
    const env = {};
    for (const line of envContent.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx !== -1) {
            const key = trimmed.slice(0, eqIdx).trim();
            let val = trimmed.slice(eqIdx + 1).trim();
            if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
            }
            env[key] = val;
        }
    }
    return env;
}

async function run() {
    console.log('========================================================');
    console.log('  BlockSafe Supabase Database Migration Runner');
    console.log('========================================================\n');

    const env = loadEnv();
    const supabaseUrl = env['SUPABASE_URL'];
    const serviceKey = env['SUPABASE_SERVICE_KEY'];
    const anonKey = env['SUPABASE_ANON_KEY'];
    const dbPassword = env['SUPABASE_DB_PASSWORD'];
    const dbUrl = env['DATABASE_URL'];
    const mgmtToken = env['SUPABASE_ACCESS_TOKEN'];

    if (!supabaseUrl || !serviceKey) {
        console.error('[ERROR] SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env');
        process.exit(1);
    }

    // Extract project ref
    const match = supabaseUrl.match(/https:\/\/([a-z0-9]+)\.supabase\.co/i);
    const projectRef = match ? match[1] : null;

    console.log(`[INFO] Target Project: ${projectRef || 'unknown'} (${supabaseUrl})`);

    if (!fs.existsSync(MIGRATION_PATH)) {
        console.error(`[ERROR] Migration file not found: ${MIGRATION_PATH}`);
        process.exit(1);
    }

    const sqlContent = fs.readFileSync(MIGRATION_PATH, 'utf-8');
    console.log(`[INFO] Loaded migration script: ${path.basename(MIGRATION_PATH)} (${sqlContent.length} bytes)`);

    let migrationExecuted = false;

    // Strategy 1: Supabase Management API with token
    if (mgmtToken && projectRef) {
        console.log('[STEP 1] Attempting execution via Supabase Management API...');
        try {
            const resp = await fetch(`https://api.supabase.com/v1/projects/${projectRef}/database/query`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${mgmtToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ query: sqlContent })
            });
            if (resp.ok) {
                console.log('[SUCCESS] Migration executed successfully via Management API!');
                migrationExecuted = true;
            } else {
                console.warn(`[WARN] Management API returned ${resp.status}: ${await resp.text()}`);
            }
        } catch (err) {
            console.warn(`[WARN] Management API attempt failed: ${err.message}`);
        }
    }

    // Strategy 2: Direct PostgreSQL Connection if pg driver available and credentials present
    if (!migrationExecuted && (dbUrl || dbPassword)) {
        console.log('[STEP 2] Attempting execution via direct PostgreSQL connection...');
        try {
            const pg = await import('pg');
            const Client = pg.default ? pg.default.Client : pg.Client;
            const client = new Client({
                connectionString: dbUrl || `postgresql://postgres.${projectRef}:${dbPassword}@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres`,
                ssl: { rejectUnauthorized: false }
            });
            await client.connect();
            await client.query(sqlContent);
            console.log('[SUCCESS] Migration executed successfully via PostgreSQL pooler connection!');
            await client.end();
            migrationExecuted = true;
        } catch (err) {
            console.warn(`[WARN] PostgreSQL connection attempt failed: ${err.message}`);
        }
    }

    // Strategy 3: Verify Supabase Client Connection & Table status
    console.log('\n[STEP 3] Verifying database schema accessibility via Supabase Data API...');
    try {
        // Dynamically import @supabase/supabase-js from dashboard
        let createClient;
        try {
            const mod = await import('@supabase/supabase-js');
            createClient = mod.createClient;
        } catch {
            const indexPath = path.join(ROOT_DIR, 'dashboard', 'node_modules', '@supabase', 'supabase-js', 'dist', 'index.mjs');
            const mod = await import(pathToFileURL(indexPath).href);
            createClient = mod.createClient;
        }

        const supabase = createClient(supabaseUrl, serviceKey, {
            auth: { persistSession: false }
        });

        // Test scam_sessions
        const { data: sessionData, error: sessionErr } = await supabase
            .from('scam_sessions')
            .select('id, status, confidence_score')
            .limit(1);

        // Test session_messages
        const { data: messageData, error: messageErr } = await supabase
            .from('session_messages')
            .select('id, sender_role')
            .limit(1);

        if (!sessionErr && !messageErr) {
            console.log('[SUCCESS] Both tables (scam_sessions, session_messages) are online and verified!');
            console.log(`[INFO] Current scam_sessions records queryable: OK`);
            console.log(`[INFO] Current session_messages records queryable: OK`);
        } else {
            if (sessionErr) {
                console.log(`[STATUS] scam_sessions check: ${sessionErr.message}`);
            }
            if (messageErr) {
                console.log(`[STATUS] session_messages check: ${messageErr.message}`);
            }
            console.log('\n--------------------------------------------------------');
            console.log('NOTE: To complete the one-time table creation in Supabase:');
            console.log('1. Open your Supabase Dashboard: https://supabase.com/dashboard/project/' + (projectRef || ''));
            console.log('2. Navigate to SQL Editor.');
            console.log(`3. Paste the contents of: ${MIGRATION_PATH}`);
            console.log('4. Click RUN.');
            console.log('--------------------------------------------------------\n');
        }
    } catch (err) {
        console.error(`[ERROR] Supabase client check failed: ${err.message}`);
    }

    console.log('\n========================================================');
    console.log('  Migration Script Complete');
    console.log('========================================================');
}

run().catch(err => {
    console.error('Fatal migration error:', err);
    process.exit(1);
});
