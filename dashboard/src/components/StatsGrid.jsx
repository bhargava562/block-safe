import React from 'react';
import { Shield, Activity, BarChart3, Fingerprint } from 'lucide-react';

const StatCard = ({ title, value, icon: Icon, color }) => (
    <div className="glass p-5 rounded-xl shadow-lg flex items-center gap-4">
        <div className={`p-3 rounded-lg ${color}`}>
            <Icon className="w-6 h-6 text-white" />
        </div>
        <div>
            <p className="text-zinc-400 text-sm font-medium">{title}</p>
            <h3 className="text-2xl font-bold">{value}</h3>
        </div>
    </div>
);

export default function StatsGrid({ stats }) {
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard
                title="Total Threats Detected"
                value={stats.total || 0}
                icon={Shield}
                color="bg-scam"
            />
            <StatCard
                title="Active Engagements"
                value={stats.active || 0}
                icon={Activity}
                color="bg-primary"
            />
            <StatCard
                title="Avg Risk Score"
                value={`${Math.round((stats.avgRisk || 0) * 100)}%`}
                icon={BarChart3}
                color="bg-zinc-700"
            />
            <StatCard
                title="AI Intelligence Captured"
                value={stats.dataPoints || 0}
                icon={Fingerprint}
                color="bg-safe"
            />
        </div>
    );
}
