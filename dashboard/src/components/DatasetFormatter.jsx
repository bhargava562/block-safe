import React, { useState } from 'react';
import { supabase } from '../lib/supabaseClient';
import { Database, FileJson, Download, Terminal } from 'lucide-react';

export default function DatasetFormatter() {
    const [isExporting, setIsExporting] = useState(false);
    const [logs, setLogs] = useState([]);

    const addLog = (msg) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev].slice(0, 5));

    const generateDataset = async (formatType) => {
        setIsExporting(true);
        addLog(`Initializing ${formatType} export...`);

        try {
            // 1. Fetch all completed/terminated scam sessions
            const { data: sessions, error: sessionErr } = await supabase
                .from('scam_sessions')
                .select('*')
                .not('status', 'eq', 'active');

            if (sessionErr) throw sessionErr;
            addLog(`Found ${sessions.length} archived sessions.`);

            let formattedData = [];

            // 2. Iterate and fetch transcripts for each session
            for (const session of sessions) {
                const { data: messages } = await supabase
                    .from('session_messages')
                    .select('sender_role, message_text')
                    .eq('session_id', session.id)
                    .order('created_at', { ascending: true });

                if (formatType === 'fine_tune') {
                    // Format for OpenAI Fine-Tuning (JSONL)
                    const convo = messages.map(m => ({
                        role: m.sender_role === 'scammer' ? 'user' : 'assistant',
                        content: m.message_text
                    }));
                    formattedData.push(JSON.stringify({ messages: convo }));
                } else {
                    // Format for Threat Intelligence (Rich JSON)
                    formattedData.push({
                        session_id: session.id,
                        threat_type: session.scam_type,
                        risk_score: session.confidence_score,
                        turns: session.turns_completed,
                        captured_at: session.created_at,
                        transcript: messages
                    });
                }
            }

            // 3. Trigger Download
            const blobType = formatType === 'fine_tune' ? 'text/plain' : 'application/json';
            const fileData = formatType === 'fine_tune' ? formattedData.join('\n') : JSON.stringify(formattedData, null, 2);

            const blob = new Blob([fileData], { type: blobType });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `blocksafe_${formatType}_${new Date().toISOString().split('T')[0]}.${formatType === 'fine_tune' ? 'jsonl' : 'json'}`;
            link.click();

            addLog("Export successful. Data forged.");

        } catch (err) {
            addLog(`Error: ${err.message}`);
            console.error("Export failed", err);
        } finally {
            setIsExporting(false);
        }
    };

    return (
        <div className="glass p-6 rounded-xl mt-8">
            <div className="flex items-center gap-3 mb-6">
                <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Database className="w-5 h-5 text-purple-500" />
                </div>
                <div>
                    <h2 className="text-xl font-bold">Autonomous Dataset Forge</h2>
                    <p className="text-zinc-500 text-sm">Convert neutralized threats into machine-learning training data.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="space-y-4">
                    <button
                        onClick={() => generateDataset('threat_intel')}
                        disabled={isExporting}
                        className="w-full flex items-center justify-between p-4 glass hover:bg-zinc-800 transition rounded-xl group"
                    >
                        <div className="flex items-center gap-3">
                            <FileJson className="w-5 h-5 text-blue-500" />
                            <div className="text-left">
                                <p className="font-bold">Threat Intelligence JSON</p>
                                <p className="text-[10px] text-zinc-500">Rich relational data for security analysis.</p>
                            </div>
                        </div>
                        <Download className="w-4 h-4 opacity-0 group-hover:opacity-100 transition" />
                    </button>

                    <button
                        onClick={() => generateDataset('fine_tune')}
                        disabled={isExporting}
                        className="w-full flex items-center justify-between p-4 glass hover:bg-zinc-800 transition rounded-xl group"
                    >
                        <div className="flex items-center gap-3">
                            <Terminal className="w-5 h-5 text-purple-500" />
                            <div className="text-left">
                                <p className="font-bold">LLM Fine-Tuning JSONL</p>
                                <p className="text-[10px] text-zinc-500">Optimized for OpenAI & HuggingFace training.</p>
                            </div>
                        </div>
                        <Download className="w-4 h-4 opacity-0 group-hover:opacity-100 transition" />
                    </button>
                </div>

                <div className="bg-black/40 rounded-xl border border-zinc-800 p-4 font-mono text-[11px] h-[140px] overflow-hidden">
                    <p className="text-zinc-500 mb-2 border-b border-zinc-800 pb-1 flex justify-between">
                        <span>Forge Console</span>
                        <span className="animate-pulse">●</span>
                    </p>
                    <div className="space-y-1">
                        {logs.length > 0 ? logs.map((log, i) => (
                            <p key={i} className={log.includes('Error') ? 'text-scam' : 'text-zinc-400'}>{log}</p>
                        )) : <p className="text-zinc-700 italic">Ready for extraction...</p>}
                    </div>
                </div>
            </div>
        </div>
    );
}
