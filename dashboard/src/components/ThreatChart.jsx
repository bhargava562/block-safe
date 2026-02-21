import React from 'react';
import {
    PieChart,
    Pie,
    Cell,
    ResponsiveContainer,
    Tooltip,
    Legend,
    BarChart,
    Bar,
    XAxis,
    YAxis
} from 'recharts';

const COLORS = ['#ef4444', '#3b82f6', '#f59e0b', '#8b5cf6', '#10b981'];

export default function ThreatChart({ data }) {
    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="glass p-6 rounded-xl">
                <h3 className="text-lg font-bold mb-4">Scam Distribution</h3>
                <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={data}
                                innerRadius={60}
                                outerRadius={80}
                                paddingAngle={5}
                                dataKey="value"
                            >
                                {data.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a' }}
                                itemStyle={{ color: '#fff' }}
                            />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="glass p-6 rounded-xl">
                <h3 className="text-lg font-bold mb-4">Risk Volume by Type</h3>
                <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={data}>
                            <XAxis dataKey="name" stroke="#71717a" fontSize={12} tickLine={false} axisLine={false} />
                            <YAxis stroke="#71717a" fontSize={12} tickLine={false} axisLine={false} />
                            <Tooltip
                                cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                                contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a' }}
                                itemStyle={{ color: '#fff' }}
                            />
                            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                                {data.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        </div>
    );
}
