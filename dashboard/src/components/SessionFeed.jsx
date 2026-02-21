import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabaseClient';
import { MessageSquare, ExternalLink, Clock } from 'lucide-react';

export default function SessionFeed() {
    const [sessions, setSessions] = useState([]);
    const [selectedSession, setSelectedSession] = useState(null);
    const [messages, setMessages] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSessions();

        // Subscribe to new sessions
        const subscription = supabase
            .channel('public:scam_sessions')
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'scam_sessions' }, payload => {
                setSessions(prev => [payload.new, ...prev]);
            })
            .subscribe();

        return () => {
            supabase.removeChannel(subscription);
        };
    }, []);

    const fetchSessions = async () => {
        const { data, error } = await supabase
            .from('scam_sessions')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(50);

        if (!error) setSessions(data);
        setLoading(false);
    };

    const fetchMessages = async (sessionId) => {
        const { data, error } = await supabase
            .from('session_messages')
            .select('*')
            .eq('session_id', sessionId)
            .order('created_at', { ascending: true });

        if (!error) setMessages(data);
    };

    const handleSessionClick = (session) => {
        setSelectedSession(session);
        setMessages([]);
        fetchMessages(session.id);
    };

    return (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 glass rounded-xl overflow-hidden">
                <div className="p-4 border-b border-zinc-800 bg-zinc-900/50 flex justify-between items-center">
                    <h3 className="font-bold flex items-center gap-2">
                        <MessageSquare className="w-4 h-4 text-primary" />
                        Live Threat Stream
                    </h3>
                    <span className="text-xs text-zinc-500">Auto-refreshing</span>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="text-xs uppercase text-zinc-500 bg-zinc-900/30">
                            <tr>
                                <th className="p-4 font-medium">Session ID</th>
                                <th className="p-4 font-medium">Type</th>
                                <th className="p-4 font-medium">Risk</th>
                                <th className="p-4 font-medium">Turns</th>
                                <th className="p-4 font-medium">Status</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800">
                            {sessions.map(session => (
                                <tr
                                    key={session.id}
                                    onClick={() => handleSessionClick(session)}
                                    className={`hover:bg-zinc-800/50 cursor-pointer transition-colors ${selectedSession?.id === session.id ? 'bg-zinc-800/30' : ''}`}
                                >
                                    <td className="p-4 font-mono text-xs">{session.id.slice(0, 8)}...</td>
                                    <td className="p-4 text-sm">{session.scam_type || 'Unknown'}</td>
                                    <td className="p-4">
                                        <span className={`text-xs px-2 py-0.5 rounded-full ${session.confidence_score > 0.7 ? 'bg-scam/20 text-scam' : 'bg-yellow-500/20 text-yellow-500'}`}>
                                            {Math.round(session.confidence_score * 100)}%
                                        </span>
                                    </td>
                                    <td className="p-4 text-sm">{session.turns_completed}</td>
                                    <td className="p-4">
                                        <span className={`text-[10px] uppercase font-bold ${session.status === 'active' ? 'text-primary' : 'text-zinc-500'}`}>
                                            {session.status}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="glass rounded-xl overflow-hidden flex flex-col h-[600px]">
                <div className="p-4 border-b border-zinc-800 bg-zinc-900/50">
                    <h3 className="font-bold">Intelligence Matrix</h3>
                </div>

                {selectedSession ? (
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        <div className="bg-zinc-900/80 p-3 rounded-lg border border-zinc-800">
                            <p className="text-[10px] text-zinc-500 uppercase mb-1">Original Scam Message</p>
                            <p className="text-xs line-clamp-3">{selectedSession.initial_message}</p>
                        </div>

                        <div className="space-y-3">
                            {messages.map((msg, idx) => (
                                <div key={idx} className={`flex flex-col ${msg.sender_role === 'scammer' ? 'items-start' : 'items-end'}`}>
                                    <span className="text-[9px] uppercase text-zinc-600 mb-1">
                                        {msg.sender_role === 'scammer' ? 'Scammer' : 'BlockSafe Agent'}
                                    </span>
                                    <div className={`text-xs p-3 rounded-xl max-w-[85%] ${msg.sender_role === 'scammer'
                                            ? 'bg-zinc-800 rounded-tl-none'
                                            : 'bg-primary/20 text-primary border border-primary/30 rounded-tr-none'
                                        }`}>
                                        {msg.message_text}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 p-8 text-center">
                        <Fingerprint className="w-12 h-12 mb-4 opacity-20" />
                        <p className="text-sm">Select a live threat to view the intelligence transcript</p>
                    </div>
                )}
            </div>
        </div>
    );
}
