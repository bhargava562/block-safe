import React, { useState, useEffect } from 'react'
import { supabase } from './lib/supabaseClient'
import StatsGrid from './components/StatsGrid'
import ThreatChart from './components/ThreatChart'
import SessionFeed from './components/SessionFeed'
import DatasetFormatter from './components/DatasetFormatter'
import { Shield, LayoutDashboard, Database, Info, LogOut } from 'lucide-react'

function App() {
    const [stats, setStats] = useState({ total: 0, active: 0, avgRisk: 0, dataPoints: 0 })
    const [chartData, setChartData] = useState([])

    useEffect(() => {
        fetchGlobalStats()

        const channel = supabase
            .channel('schema-db-changes')
            .on('postgres_changes', { event: '*', schema: 'public', table: 'scam_sessions' }, () => {
                fetchGlobalStats()
            })
            .subscribe()

        return () => {
            supabase.removeChannel(channel)
        }
    }, [])

    const fetchGlobalStats = async () => {
        const { data: sessions, error } = await supabase
            .from('scam_sessions')
            .select('status, confidence_score, turns_completed, scam_type')

        if (!error && sessions) {
            const active = sessions.filter(s => s.status === 'active').length
            const avgRisk = sessions.reduce((acc, s) => acc + s.confidence_score, 0) / sessions.length
            const dataPoints = sessions.reduce((acc, s) => acc + s.turns_completed, 0)

            setStats({
                total: sessions.length,
                active,
                avgRisk: avgRisk || 0,
                dataPoints
            })

            // Group by scam_type for charts
            const distribution = sessions.reduce((acc, s) => {
                const type = s.scam_type || 'Unknown'
                acc[type] = (acc[type] || 0) + 1
                return acc
            }, {})

            setChartData(Object.entries(distribution).map(([name, value]) => ({ name, value })))
        }
    }

    return (
        <div className="flex min-h-screen bg-background font-sans antialiased">
            {/* Sidebar */}
            <aside className="w-64 border-r border-zinc-800 bg-card/50 hidden lg:flex flex-col">
                <div className="p-6 border-b border-zinc-800">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center shadow-lg shadow-primary/20">
                            <Shield className="w-5 h-5 text-white" />
                        </div>
                        <span className="font-bold text-xl tracking-tight">BlockSafe</span>
                    </div>
                    <p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-widest font-bold">Command Center</p>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <div className="px-3 py-2 bg-primary/10 text-primary rounded-lg flex items-center gap-3 cursor-pointer">
                        <LayoutDashboard className="w-4 h-4" />
                        <span className="text-sm font-bold">Threat Matrix</span>
                    </div>
                    <div className="px-3 py-2 text-zinc-400 hover:bg-zinc-800/50 rounded-lg flex items-center gap-3 cursor-pointer transition-colors">
                        <Database className="w-4 h-4" />
                        <span className="text-sm font-medium">Intel Datasets</span>
                    </div>
                </nav>

                <div className="p-4 border-t border-zinc-800">
                    <div className="flex items-center gap-3 p-3 text-zinc-500 hover:text-white cursor-pointer transition-colors">
                        <LogOut className="w-4 h-4" />
                        <span className="text-sm font-medium">Terminal Exit</span>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 p-8 max-w-7xl mx-auto w-full">
                <header className="mb-8 flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-extrabold flex items-center gap-3">
                            Network Threat Overview
                            <span className="inline-block w-2 h-2 rounded-full bg-safe animate-pulse"></span>
                        </h1>
                        <p className="text-zinc-500 mt-1">Real-time intelligence from active agent swarm.</p>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="glass px-4 py-2 rounded-full text-xs font-mono text-zinc-400 flex items-center gap-2">
                            <Info className="w-3 h-3" />
                            Honeypots Scale: 12ms/turn
                        </div>
                    </div>
                </header>

                <StatsGrid stats={stats} />
                <ThreatChart data={chartData} />
                <SessionFeed />
                <DatasetFormatter />

                <footer className="mt-12 pt-8 border-t border-zinc-800 text-center text-zinc-600">
                    <p className="text-[10px] uppercase font-bold tracking-[0.2em]">BlockSafe Agentic Intelligence Layer &copy; 2026</p>
                </footer>
            </main>
        </div>
    )
}

export default App
