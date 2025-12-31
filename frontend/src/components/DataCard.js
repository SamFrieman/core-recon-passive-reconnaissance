import { ShieldAlert } from 'lucide-react';

const renderValue = (val) => {
  if (typeof val === 'object' && val !== null) {
    return <pre className="text-[10px] text-blue-300 leading-tight">{JSON.stringify(val, null, 2)}</pre>;
  }
  return <span className="text-gray-300">{val}</span>;
};

const DataCard = ({ title, icon: Icon, data, loading }) => {
  return (
    <div className="bg-[#0f0f0f] border border-gray-800 rounded-xl p-6 hover:border-[#007fff]/50 transition-all duration-300 group">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          {Icon && <Icon className="w-5 h-5 text-[#007fff] group-hover:scale-110 transition-transform" />}
          <h3 className="text-sm font-bold tracking-widest text-gray-400 uppercase">{title}</h3>
        </div>
        {loading && <div className="w-2 h-2 bg-[#007fff] rounded-full animate-ping" />}
      </div>

      <div className="bg-black/40 rounded-lg p-4 font-mono text-xs border border-gray-900 overflow-auto max-h-64 custom-scrollbar">
        {data ? (
          <pre className="text-gray-300">
            {typeof data === 'object' ? JSON.stringify(data, null, 2) : data}
          </pre>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-gray-600 italic">
            <ShieldAlert className="w-8 h-8 mb-2 opacity-20" />
            <p>NO_DATA_EXTRACTED</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DataCard;