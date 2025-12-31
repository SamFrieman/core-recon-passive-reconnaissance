import React, { useState } from 'react';
import axios from 'axios';
import { 
  Search, Shield, Globe, Terminal, Activity, ShieldAlert, 
  Cpu, Lock, Download, History, Fingerprint, Database,
  AlertTriangle, CheckCircle, XCircle, Clock, Server,
  Zap, Eye, MapPin, ChevronDown, ChevronUp, ExternalLink,
  Info, TrendingUp, Layers, Code
} from 'lucide-react';

const RiskGauge = ({ score, level }) => {
  const getColor = (s) => {
    if (s < 30) return 'bg-emerald-500';
    if (s < 60) return 'bg-amber-500';
    return 'bg-rose-500';
  };

  const getLevelColor = (l) => {
    if (l === 'MINIMAL' || l === 'LOW') return 'text-emerald-400';
    if (l === 'MEDIUM') return 'text-amber-400';
    return 'text-rose-400';
  };

  const getRingColor = (l) => {
    if (l === 'MINIMAL' || l === 'LOW') return 'stroke-emerald-500';
    if (l === 'MEDIUM') return 'stroke-amber-500';
    return 'stroke-rose-500';
  };

  // Calculate circumference for the circular progress
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex items-center gap-6">
      {/* Circular gauge */}
      <div className="relative w-32 h-32">
        <svg className="transform -rotate-90 w-32 h-32">
          {/* Background circle */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            stroke="currentColor"
            strokeWidth="8"
            fill="none"
            className="text-gray-800"
          />
          {/* Progress circle */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            stroke="currentColor"
            strokeWidth="8"
            fill="none"
            className={getRingColor(level)}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease-in-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center flex-col">
          <span className={`text-3xl font-black ${getLevelColor(level)}`}>{score}</span>
          <span className="text-xs text-gray-500">/ 100</span>
        </div>
      </div>

      {/* Risk details */}
      <div className="flex-1">
        <div className="text-sm text-gray-500 uppercase tracking-wider mb-1">Threat Level</div>
        <div className={`text-2xl font-black ${getLevelColor(level)} mb-2`}>{level}</div>
        <div className="h-2 w-full bg-gray-800/50 rounded-full overflow-hidden">
          <div 
            className={`h-full transition-all duration-1000 ${getColor(score)}`} 
            style={{ width: `${score}%` }}
          />
        </div>
      </div>
    </div>
  );
};

const ExpandableCard = ({ title, icon: Icon, data, loading, defaultExpanded = false, renderContent }) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  
  // Determine if card has valid data
  const hasData = data && (!data.error || Object.keys(data).length > 1);
  const hasError = data?.error;

  return (
    <div className={`bg-gradient-to-br from-gray-900/50 to-gray-900/30 border rounded-xl transition-all duration-300 overflow-hidden ${
      isExpanded ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' : 'border-gray-800/50 hover:border-gray-700/50'
    }`}>
      {/* Card Header - Always visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-5 flex items-center justify-between group hover:bg-gray-800/20 transition-colors"
      >
        <div className="flex items-center gap-3">
          {Icon && (
            <div className={`p-2 rounded-lg transition-all ${
              isExpanded 
                ? 'bg-cyan-500/20 text-cyan-400' 
                : 'bg-gray-800/50 text-gray-500 group-hover:bg-gray-800 group-hover:text-cyan-500'
            }`}>
              <Icon className="w-5 h-5" />
            </div>
          )}
          <div className="text-left">
            <h3 className="text-sm font-bold tracking-wider text-gray-300 uppercase">{title}</h3>
            {!isExpanded && hasData && (
              <p className="text-xs text-gray-600 mt-0.5">Click to expand</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Status indicator */}
          {loading ? (
            <div className="w-2 h-2 bg-cyan-500 rounded-full animate-ping" />
          ) : hasError ? (
            <div className="flex items-center gap-2 text-rose-500 text-xs">
              <XCircle className="w-4 h-4" />
            </div>
          ) : hasData ? (
            <div className="flex items-center gap-2 text-emerald-500 text-xs">
              <CheckCircle className="w-4 h-4" />
            </div>
          ) : (
            <Info className="w-4 h-4 text-gray-600" />
          )}
          
          {/* Expand/collapse icon - separated for better visibility */}
          <div className={`p-1 rounded transition-colors ${
            isExpanded ? 'bg-cyan-500/20' : 'group-hover:bg-gray-800/50'
          }`}>
            {isExpanded ? (
              <ChevronUp className="w-5 h-5 text-cyan-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500 group-hover:text-cyan-500 transition-colors" />
            )}
          </div>
        </div>
      </button>

      {/* Card Content - Expandable */}
      {isExpanded && (
        <div className="px-5 pb-5 animate-in slide-in-from-top duration-300 border-t border-gray-800/30">
          <div className="bg-black/40 rounded-lg p-4 border border-gray-800/50 mt-4">
            {loading ? (
              <div className="flex items-center justify-center py-8 text-gray-600">
                <Activity className="w-6 h-6 animate-spin mr-2" />
                <span className="text-sm">Gathering intelligence...</span>
              </div>
            ) : (
              <div className="text-gray-300 text-sm">
                {renderContent ? renderContent(data) : <pre className="text-xs overflow-auto">{JSON.stringify(data, null, 2)}</pre>}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default function App() {
  const [domain, setDomain] = useState('');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [inputWarning, setInputWarning] = useState(null);

  // Client-side input validation
  const validateInput = (input) => {
    if (!input || input.trim().length === 0) {
      return { valid: false, error: 'Input cannot be empty' };
    }

    const trimmed = input.trim();

    // Check length
    if (trimmed.length > 255) {
      return { valid: false, error: 'Input too long (max 255 characters)' };
    }

    // Check for dangerous patterns (XSS prevention)
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i,
    ];

    for (const pattern of xssPatterns) {
      if (pattern.test(trimmed)) {
        return { valid: false, error: 'Invalid characters detected' };
      }
    }

    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(--|;)/,
      /(\bOR\b\s+\w+\s*=)/i,
      /(\bAND\b\s+\w+\s*=)/i,
    ];

    for (const pattern of sqlPatterns) {
      if (pattern.test(trimmed)) {
        return { valid: false, error: 'Invalid input format' };
      }
    }

    // Check if it's a hash (show warning)
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) {
      return { valid: false, error: 'MD5 hash detected. Please enter a domain, IP, or URL instead.' };
    }
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) {
      return { valid: false, error: 'SHA1 hash detected. Please enter a domain, IP, or URL instead.' };
    }
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
      return { valid: false, error: 'SHA256 hash detected. Please enter a domain, IP, or URL instead.' };
    }

    // Basic format validation
    const validFormatRegex = /^[a-zA-Z0-9\.\-\:\/]+$/;
    if (!validFormatRegex.test(trimmed)) {
      return { valid: false, error: 'Invalid characters. Use only letters, numbers, dots, hyphens, colons, and slashes.' };
    }

    return { valid: true, sanitized: trimmed };
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    setDomain(value);
    
    // Real-time validation feedback
    if (value.trim().length > 0) {
      const validation = validateInput(value);
      if (!validation.valid) {
        setInputWarning(validation.error);
      } else {
        setInputWarning(null);
      }
    } else {
      setInputWarning(null);
    }
  };

  const executeRecon = async () => {
    // Validate input before sending
    const validation = validateInput(domain);
    
    if (!validation.valid) {
      setError(validation.error);
      return;
    }
    
    setLoading(true);
    setError(null);
    setData(null);
    setInputWarning(null);

    try {
      // Use the sanitized input
      const API_BASE = import.meta.env.VITE_API_URL || '/api';
      const response = await axios.get(`${API_BASE}/v1/recon/${encodeURIComponent(validation.sanitized)}`);
      setData(response.data);
    } catch (err) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to connect to reconnaissance service';
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading) {
      executeRecon();
    }
  };

  // Render functions for different card types
  const renderInfrastructure = (infra) => {
    if (!infra || infra.error) {
      return (
        <div className="flex items-center gap-2 text-rose-400">
          <AlertTriangle className="w-4 h-4" />
          <span>{infra?.error || 'Unable to retrieve infrastructure data'}</span>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        {/* Status badge */}
        <div className="flex items-center gap-3 pb-3 border-b border-gray-800/50">
          <div className={`w-3 h-3 rounded-full ${infra.status === 'ONLINE' ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
          <span className="text-sm font-bold text-gray-300">{infra.status}</span>
          {infra.status === 'ONLINE' && (
            <span className="text-xs text-emerald-500 ml-auto">● Live</span>
          )}
        </div>

        {/* Network details */}
        <div className="grid gap-3">
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-xs">IP Address</span>
            <code className="text-cyan-400 font-mono text-sm bg-gray-900/50 px-2 py-1 rounded">{infra.ip}</code>
          </div>

          {infra.reverse_dns && infra.reverse_dns !== 'No PTR record' && (
            <div className="flex justify-between items-start">
              <span className="text-gray-500 text-xs">Reverse DNS</span>
              <code className="text-cyan-400 font-mono text-xs text-right max-w-[60%] break-all">{infra.reverse_dns}</code>
            </div>
          )}

          {infra.asn && (
            <>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 text-xs">ASN</span>
                <code className="text-cyan-400 font-mono text-sm">{infra.asn.number}</code>
              </div>
              <div className="flex justify-between items-start">
                <span className="text-gray-500 text-xs">Organization</span>
                <span className="text-gray-300 text-xs text-right max-w-[60%]">{infra.asn.organization}</span>
              </div>
            </>
          )}

          <div className="flex justify-between items-start">
            <span className="text-gray-500 text-xs">ISP Provider</span>
            <span className="text-gray-300 text-xs text-right max-w-[60%]">{infra.provider}</span>
          </div>

          {infra.location && typeof infra.location === 'object' && (
            <div className="mt-2 pt-3 border-t border-gray-800/50">
              <div className="flex items-start gap-2 mb-2">
                <MapPin className="w-4 h-4 text-cyan-500 mt-0.5" />
                <div className="flex-1">
                  <div className="text-gray-300 text-sm font-medium">
                    {infra.location.city}, {infra.location.region}
                  </div>
                  <div className="text-gray-500 text-xs">{infra.location.country}</div>
                  {infra.location.coordinates && (
                    <code className="text-gray-600 text-xs mt-1 block">{infra.location.coordinates}</code>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderFingerprint = (fing) => {
    if (!fing || fing.error) {
      return (
        <div className="flex items-center gap-2 text-rose-400">
          <AlertTriangle className="w-4 h-4" />
          <span>{fing?.error || 'Unable to fingerprint system'}</span>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        {/* Basic info */}
        <div className="grid gap-3 pb-3 border-b border-gray-800/50">
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-xs">Server</span>
            <code className="text-cyan-400 text-xs">{fing.server || 'Hidden'}</code>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-xs">Protocol</span>
            <span className={`text-xs font-bold px-2 py-1 rounded ${
              fing.protocol === 'HTTPS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
            }`}>
              {fing.protocol}
            </span>
          </div>
          {fing.status_code && (
            <div className="flex justify-between items-center">
              <span className="text-gray-500 text-xs">Status Code</span>
              <code className="text-cyan-400 text-sm">{fing.status_code}</code>
            </div>
          )}
        </div>

        {/* Security headers */}
        {fing.security && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-3">Security Headers</div>
            <div className="space-y-2">
              {Object.entries(fing.security).map(([header, value]) => {
                const isSet = value !== 'MISSING' && value !== false;
                return (
                  <div key={header} className="flex items-center justify-between text-xs group">
                    <span className="text-gray-400 flex-1">{header.replace(/-/g, ' ').toUpperCase()}</span>
                    <div className={`flex items-center gap-2 ${isSet ? 'text-emerald-500' : 'text-rose-500'}`}>
                      {isSet ? (
                        <>
                          <CheckCircle className="w-3 h-3" />
                          <span className="font-medium">SET</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3 h-3" />
                          <span className="font-medium">MISSING</span>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderSSL = (ssl) => {
    if (!ssl || ssl.error) {
      return (
        <div className="flex items-center gap-2 text-rose-400">
          <AlertTriangle className="w-4 h-4" />
          <span>{ssl?.error || 'No SSL certificate found'}</span>
        </div>
      );
    }

    const daysRemaining = ssl.days_remaining;
    const isExpiringSoon = daysRemaining < 30;
    const isExpired = daysRemaining < 0;

    return (
      <div className="space-y-4">
        {/* Validity status */}
        <div className="flex items-center justify-between pb-3 border-b border-gray-800/50">
          <span className="text-gray-500 text-xs">Certificate Validity</span>
          <div className={`flex items-center gap-2 ${
            isExpired ? 'text-rose-500' : isExpiringSoon ? 'text-amber-500' : 'text-emerald-500'
          }`}>
            <Lock className="w-4 h-4" />
            <span className="text-sm font-bold">
              {isExpired ? 'EXPIRED' : `${daysRemaining} days`}
            </span>
          </div>
        </div>

        {/* Certificate details */}
        <div className="space-y-3">
          <div>
            <div className="text-gray-500 text-xs mb-1">Issuer</div>
            <code className="text-cyan-400 text-xs block break-all">{ssl.issuer}</code>
          </div>

          <div>
            <div className="text-gray-500 text-xs mb-1">Subject</div>
            <code className="text-cyan-400 text-xs block break-all">{ssl.subject}</code>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-gray-500 text-xs mb-1">Valid From</div>
              <div className="text-gray-300 text-xs">{new Date(ssl.valid_from).toLocaleDateString()}</div>
            </div>
            <div>
              <div className="text-gray-500 text-xs mb-1">Valid Until</div>
              <div className="text-gray-300 text-xs">{new Date(ssl.valid_until).toLocaleDateString()}</div>
            </div>
          </div>

          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-xs">TLS Version</span>
            <code className="text-cyan-400 text-xs">{ssl.tls_version}</code>
          </div>

          {ssl.subject_alternative_names && ssl.subject_alternative_names.length > 0 && (
            <div className="mt-3 pt-3 border-t border-gray-800/50">
              <div className="text-gray-500 text-xs mb-2">
                Subject Alternative Names ({ssl.subject_alternative_names.length})
              </div>
              <div className="space-y-1 max-h-32 overflow-auto">
                {ssl.subject_alternative_names.map((san, i) => (
                  <div key={i} className="text-cyan-400 text-xs font-mono flex items-center gap-2">
                    <span className="text-gray-700">→</span>
                    {san}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderDNS = (dns) => {
    if (!dns || Object.keys(dns).length === 0) {
      return <div className="text-gray-500 text-sm">No DNS records retrieved</div>;
    }

    const recordTypes = Object.entries(dns).filter(([_, records]) => 
      records && Array.isArray(records) && records.length > 0 && 
      !records[0].includes('Query failed') && !records[0].includes('timeout')
    );

    if (recordTypes.length === 0) {
      return <div className="text-gray-500 text-sm">No valid DNS records found</div>;
    }

    return (
      <div className="space-y-4">
        {recordTypes.map(([recordType, records]) => (
          <div key={recordType} className="pb-3 border-b border-gray-800/50 last:border-0">
            <div className="text-cyan-500 text-xs uppercase font-bold mb-2 flex items-center gap-2">
              <Layers className="w-3 h-3" />
              {recordType} Records
            </div>
            <div className="space-y-1 ml-4">
              {records.slice(0, 10).map((record, i) => (
                <div key={i} className="text-gray-400 text-xs font-mono flex items-start gap-2">
                  <span className="text-gray-700 mt-0.5">→</span>
                  <span className="break-all">{record}</span>
                </div>
              ))}
              {records.length > 10 && (
                <div className="text-gray-600 text-xs italic mt-2">
                  + {records.length - 10} more records
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderSubdomains = (subs) => {
    console.log("Subdomain data received:", subs); // Debug log
    
    if (!subs) {
      return <div className="text-gray-500 text-sm">No subdomain data received</div>;
    }
    
    if (subs.error) {
      return (
        <div className="flex items-center gap-2 text-amber-400">
          <AlertTriangle className="w-4 h-4" />
          <span className="text-sm">{subs.error}</span>
        </div>
      );
    }
    
    if (!subs.subdomains || subs.subdomains.length === 0) {
      return (
        <div className="text-center py-6">
          <Terminal className="w-8 h-8 mx-auto mb-2 opacity-20 text-gray-600" />
          <div className="text-gray-500 text-sm">No subdomains discovered</div>
          <div className="text-gray-600 text-xs mt-2">
            This could mean the domain has no public subdomains or they are not indexed in certificate transparency logs
          </div>
        </div>
      );
    }

    return (
      <SubdomainList subdomains={subs.subdomains} count={subs.count} sources={subs.sources} />
    );
  };

  // Separate component for subdomain list to avoid state issues
  const SubdomainList = ({ subdomains, count, sources }) => {
    const [showAll, setShowAll] = useState(false);
    const displayLimit = 15;
    const displaySubdomains = showAll ? subdomains : subdomains.slice(0, displayLimit);

    return (
      <div className="space-y-4">
        {/* Summary */}
        <div className="flex items-center justify-between pb-3 border-b border-gray-800/50">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-500" />
            <span className="text-sm text-gray-400">Total Discovered</span>
          </div>
          <span className="text-xl font-bold text-cyan-400">{count || 0}</span>
        </div>

        {sources && (
          <div className="text-xs text-gray-600">
            <span className="text-gray-500">Sources:</span> {sources.join(', ')}
          </div>
        )}

        {/* Subdomain list */}
        <div className="space-y-1 max-h-96 overflow-auto">
          {displaySubdomains.map((sub, i) => (
            <div key={i} className="group flex items-center gap-2 text-xs font-mono hover:bg-gray-800/30 p-2 rounded transition-colors">
              <span className="text-gray-700">{(showAll ? i : i) + 1}.</span>
              <span className="text-cyan-400 group-hover:text-cyan-300 break-all">{sub}</span>
              <a 
                href={`https://${sub}`} 
                target="_blank" 
                rel="noopener noreferrer"
                className="ml-auto"
                onClick={(e) => e.stopPropagation()}
              >
                <ExternalLink className="w-3 h-3 text-gray-700 group-hover:text-cyan-500 opacity-0 group-hover:opacity-100 transition-opacity" />
              </a>
            </div>
          ))}
        </div>

        {/* Show more button */}
        {subdomains.length > displayLimit && (
          <button
            onClick={() => setShowAll(!showAll)}
            className="w-full py-2 mt-3 text-xs text-cyan-500 hover:text-cyan-400 border border-gray-800 hover:border-cyan-500/50 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            {showAll ? (
              <>
                <ChevronUp className="w-4 h-4" />
                Show Less
              </>
            ) : (
              <>
                <ChevronDown className="w-4 h-4" />
                Show All ({subdomains.length - displayLimit} more)
              </>
            )}
          </button>
        )}
      </div>
    );
  };

  const renderWHOIS = (whois) => {
    if (!whois || whois.error) {
      return (
        <div className="flex items-center gap-2 text-amber-400">
          <Info className="w-4 h-4" />
          <span className="text-sm">{whois?.note || 'WHOIS data unavailable (likely privacy protected)'}</span>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        <div className="flex justify-between items-start">
          <span className="text-gray-500 text-xs">Registrar</span>
          <span className="text-gray-300 text-xs text-right max-w-[60%]">{whois.registrar}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-500 text-xs">Organization</span>
          <span className="text-gray-300 text-xs">{whois.organization}</span>
        </div>
        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-gray-800/50">
          <div>
            <div className="text-gray-500 text-xs mb-1">Created</div>
            <div className="text-gray-300 text-xs">
              {whois.creation_date !== 'Unknown' ? new Date(whois.creation_date).toLocaleDateString() : 'Unknown'}
            </div>
          </div>
          <div>
            <div className="text-gray-500 text-xs mb-1">Expires</div>
            <div className="text-gray-300 text-xs">
              {whois.expiration_date !== 'Unknown' ? new Date(whois.expiration_date).toLocaleDateString() : 'Unknown'}
            </div>
          </div>
        </div>
        {whois.name_servers && whois.name_servers.length > 0 && (
          <div className="pt-2 border-t border-gray-800/50">
            <div className="text-gray-500 text-xs mb-2">Name Servers</div>
            <div className="space-y-1">
              {whois.name_servers.slice(0, 4).map((ns, i) => (
                <div key={i} className="text-cyan-400 font-mono text-xs flex items-center gap-2">
                  <span className="text-gray-700">→</span>
                  {ns}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderTechnology = (tech) => {
    if (!tech || tech.error || tech.message) {
      return (
        <div className="text-center py-8 text-gray-600">
          <Code className="w-8 h-8 mx-auto mb-2 opacity-20" />
          <div className="text-sm">{tech?.message || tech?.error || 'No technologies detected'}</div>
        </div>
      );
    }

    return <TechnologyStack technologies={tech} />;
  };

  // Separate component for technology stack
  const TechnologyStack = ({ technologies }) => {
    const [expandedCategories, setExpandedCategories] = useState({});

    return (
      <div className="space-y-3">
        {Object.entries(technologies).map(([category, items]) => {
          const isExpanded = expandedCategories[category];
          const displayItems = isExpanded ? items : items.slice(0, 3);

          return (
            <div key={category} className="border border-gray-800/50 rounded-lg overflow-hidden hover:border-gray-700/50 transition-colors">
              <div className="bg-gray-900/30 px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Cpu className="w-4 h-4 text-cyan-500" />
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                    {category}
                  </span>
                  <span className="text-xs text-gray-600 bg-gray-800/50 px-2 py-0.5 rounded">
                    {items.length}
                  </span>
                </div>
                {items.length > 3 && (
                  <button
                    onClick={() => setExpandedCategories(prev => ({
                      ...prev,
                      [category]: !prev[category]
                    }))}
                    className="text-xs text-gray-500 hover:text-cyan-400 transition-colors flex items-center gap-1 px-3 py-1 rounded hover:bg-gray-800/50"
                  >
                    {isExpanded ? (
                      <>
                        <ChevronUp className="w-3 h-3" />
                        <span>Show Less</span>
                      </>
                    ) : (
                      <>
                        <ChevronDown className="w-3 h-3" />
                        <span>+{items.length - 3} more</span>
                      </>
                    )}
                  </button>
                )}
              </div>
              <div className="p-4 space-y-2 bg-black/20">
                {displayItems.map((item, idx) => (
                  <div key={idx} className="flex items-center justify-between group hover:bg-gray-900/30 p-2 rounded transition-colors">
                    <div className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 bg-cyan-500/50 rounded-full group-hover:bg-cyan-500 transition-colors" />
                      <span className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors">
                        {item.name}
                      </span>
                    </div>
                    <span className={`text-xs font-mono px-2.5 py-1 rounded ${
                      item.version === 'Undetected' 
                        ? 'text-gray-600 bg-gray-900/50 border border-gray-800' 
                        : 'text-cyan-400 bg-cyan-500/10 border border-cyan-500/20'
                    }`}>
                      {item.version}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  const renderWayback = (wb) => {
    console.log("Wayback data received:", wb); // Debug log
    
    if (!wb) {
      return <div className="text-gray-500 text-sm">No archive data received</div>;
    }
    
    if (wb.error) {
      return (
        <div className="flex items-center gap-2 text-amber-400">
          <AlertTriangle className="w-4 h-4" />
          <span className="text-sm">{wb.error}</span>
        </div>
      );
    }
    
    if (!wb.available) {
      return (
        <div className="text-center py-6">
          <History className="w-8 h-8 mx-auto mb-2 opacity-20 text-gray-600" />
          <div className="flex items-center justify-center gap-2 text-gray-500 text-sm">
            <XCircle className="w-4 h-4" />
            <span>{wb.message || 'No archives found in Wayback Machine'}</span>
          </div>
          <div className="text-gray-600 text-xs mt-2">
            This domain may be new or hasn't been archived yet
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-emerald-500 pb-3 border-b border-gray-800/50">
          <CheckCircle className="w-5 h-5" />
          <span className="text-sm font-bold">Archives Available</span>
        </div>

        <div className="space-y-3">
          {wb.total_snapshots && (
            <div className="flex justify-between items-center">
              <span className="text-gray-500 text-xs">Total Snapshots</span>
              <span className="text-cyan-400 text-xl font-bold">{wb.total_snapshots}</span>
            </div>
          )}

          {wb.last_snapshot_formatted && (
            <div className="flex justify-between items-center">
              <span className="text-gray-500 text-xs">Last Capture</span>
              <code className="text-gray-400 text-xs">{wb.last_snapshot_formatted}</code>
            </div>
          )}
          
          {!wb.last_snapshot_formatted && wb.last_snapshot && (
            <div className="flex justify-between items-center">
              <span className="text-gray-500 text-xs">Last Snapshot</span>
              <code className="text-gray-400 text-xs">{wb.last_snapshot}</code>
            </div>
          )}

          {wb.status_code && (
            <div className="flex justify-between items-center">
              <span className="text-gray-500 text-xs">Status Code</span>
              <code className="text-cyan-400 text-xs">{wb.status_code}</code>
            </div>
          )}

          {wb.archive_url && (
            <a
              href={wb.archive_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center gap-2 w-full py-3 mt-4 text-sm text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 rounded-lg transition-all"
            >
              <ExternalLink className="w-4 h-4" />
              <span>View Latest Archive</span>
            </a>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 text-gray-100 p-4 md:p-12 font-sans">
      {/* Animated background grid */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#1f1f1f_1px,transparent_1px),linear-gradient(to_bottom,#1f1f1f_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-20" />
      <div className="fixed inset-0 bg-gradient-to-t from-cyan-500/5 via-transparent to-transparent" />
      
      <div className="relative z-10">
        {/* Header */}
        <div className="max-w-7xl mx-auto mb-12">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-6 bg-gradient-to-r from-gray-900/80 to-gray-900/40 backdrop-blur-sm border border-gray-800/50 rounded-2xl">
            <div className="flex items-center gap-4">
              <div className="p-4 bg-gradient-to-br from-cyan-500/20 to-cyan-600/10 rounded-xl border border-cyan-500/30 shadow-lg shadow-cyan-500/20">
                <Shield className="text-cyan-400 w-10 h-10" />
              </div>
              <div>
                <h1 className="text-4xl font-black tracking-tight">
                  CORE<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">RECON</span>
                </h1>
                <p className="text-xs text-gray-500 tracking-[0.3em] uppercase mt-1">
                  Advanced Passive Intelligence Platform
                </p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-gray-500 uppercase mb-1">System Status</div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                </span>
                <span className="text-sm font-bold text-emerald-400">OPERATIONAL</span>
              </div>
            </div>
          </div>
        </div>

        {/* Search Input */}
        <div className="max-w-4xl mx-auto mb-16">
          <div className="relative flex gap-3 bg-gray-900/50 backdrop-blur-sm border border-gray-800/50 p-3 rounded-2xl focus-within:border-cyan-500/50 focus-within:shadow-lg focus-within:shadow-cyan-500/10 transition-all">
            <div className="flex items-center justify-center pl-3">
              <Search className="w-6 h-6 text-gray-600" />
            </div>
            <input 
              type="text"
              value={domain}
              onChange={handleInputChange}
              onKeyPress={handleKeyPress}
              placeholder="Enter domain, URL, or IP address (e.g., example.com, https://example.com, 8.8.8.8)"
              className="flex-1 bg-transparent py-4 px-2 focus:outline-none text-cyan-400 placeholder:text-gray-700 text-lg"
              disabled={loading}
            />
            <button 
              onClick={executeRecon}
              disabled={loading || !domain.trim() || inputWarning}
              className="bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white px-8 py-3 rounded-xl font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-3 shadow-lg shadow-cyan-500/20 min-w-[180px] justify-center"
            >
              {loading ? (
                <>
                  <Activity className="animate-spin w-5 h-5" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" />
                  <span>Begin Scan</span>
                </>
              )}
            </button>
          </div>
          
          {/* Input Warning */}
          {inputWarning && !error && (
            <div className="mt-4 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl backdrop-blur-sm">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <div>
                  <div className="text-sm font-bold text-amber-400">Input Validation Warning</div>
                  <div className="text-xs text-amber-300/80 mt-1">{inputWarning}</div>
                </div>
              </div>
            </div>
          )}
          
          {/* Error Display */}
          {error && (
            <div className="mt-4 p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl backdrop-blur-sm">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-rose-400" />
                <div>
                  <div className="text-sm font-bold text-rose-400">Reconnaissance Error</div>
                  <div className="text-xs text-rose-300/80 mt-1">{error}</div>
                </div>
              </div>
            </div>
          )}
          
          {/* Input Format Help */}
          {!data && !loading && !error && (
            <div className="mt-4 p-4 bg-gray-900/50 border border-gray-800/50 rounded-xl backdrop-blur-sm">
              <div className="text-xs text-gray-500">
                <div className="font-bold text-gray-400 mb-2">Supported Input Formats:</div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="flex items-start gap-2">
                    <Globe className="w-4 h-4 text-cyan-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <div className="text-gray-400 font-medium">Domain Names</div>
                      <code className="text-gray-600 text-xs">example.com</code>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Server className="w-4 h-4 text-cyan-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <div className="text-gray-400 font-medium">IP Addresses</div>
                      <code className="text-gray-600 text-xs">8.8.8.8, 2001:4860:4860::8888</code>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <ExternalLink className="w-4 h-4 text-cyan-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <div className="text-gray-400 font-medium">URLs</div>
                      <code className="text-gray-600 text-xs">https://example.com</code>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Loading State */}
        {loading && (
          <div className="max-w-7xl mx-auto">
            <div className="text-center py-20">
              <div className="inline-flex items-center gap-4 text-cyan-400 mb-8">
                <Activity className="w-12 h-12 animate-spin" />
                <span className="text-2xl font-bold tracking-wider">Reconnaissance in Progress</span>
              </div>
              <p className="text-gray-500 text-sm mb-8">Gathering intelligence from multiple passive sources...</p>
              
              {/* Enhanced loading progress */}
              <div className="max-w-2xl mx-auto space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                  {['DNS Analysis', 'Subdomain Discovery', 'Security Scan', 'Certificate Check'].map((task, i) => (
                    <div key={i} className="p-3 bg-gray-900/50 border border-gray-800/50 rounded-lg">
                      <div className="flex items-center gap-2 justify-center">
                        <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse" style={{ animationDelay: `${i * 200}ms` }} />
                        <span className="text-gray-400">{task}</span>
                      </div>
                    </div>
                  ))}
                </div>
                
                <div className="h-2 bg-gray-800/50 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-cyan-600 to-blue-500 animate-pulse" style={{ width: '70%' }} />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Empty State */}
        {!data && !loading && !error && (
          <div className="max-w-7xl mx-auto">
            <div className="border border-dashed border-gray-800/50 rounded-2xl py-24 text-center backdrop-blur-sm bg-gray-900/20">
              <div className="inline-flex p-6 bg-gray-900/50 rounded-2xl border border-gray-800/50 mb-6">
                <Cpu className="w-16 h-16 text-gray-700" />
              </div>
              <h2 className="text-2xl font-bold text-gray-400 mb-3">Awaiting Target Input</h2>
              <p className="text-sm text-gray-600 mb-12">Enter a domain above to begin comprehensive passive reconnaissance</p>
              
              <div className="flex items-center justify-center gap-12 text-sm">
                {[
                  { icon: Shield, label: 'Security Analysis' },
                  { icon: Globe, label: 'Infrastructure Intel' },
                  { icon: Terminal, label: 'Subdomain Discovery' },
                  { icon: Lock, label: 'Certificate Validation' }
                ].map(({ icon: Icon, label }, i) => (
                  <div key={i} className="flex flex-col items-center gap-3">
                    <div className="p-3 bg-gray-900/50 rounded-lg border border-gray-800/30">
                      <Icon className="w-6 h-6 text-gray-700" />
                    </div>
                    <span className="text-gray-600">{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {data && (
          <div className="max-w-7xl mx-auto">
            {/* Action Bar */}
            <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-8 p-5 bg-gray-900/50 backdrop-blur-sm border border-gray-800/50 rounded-xl">
              <div className="flex flex-wrap items-center gap-4 text-sm">
                <div className="flex items-center gap-2 text-gray-500">
                  <Clock className="w-4 h-4" />
                  <span>Scanned: {data.timestamp}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-500">
                  <Eye className="w-4 h-4" />
                  <span>Target: <span className="text-cyan-400 font-mono">{data.target}</span></span>
                </div>
                {data.input_type && (
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-3 py-1 rounded-full font-bold ${
                      data.input_type === 'domain' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' :
                      data.input_type === 'ipv4' || data.input_type === 'ipv6' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' :
                      data.input_type === 'url' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                      'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                    }`}>
                      {data.input_type.toUpperCase()}
                    </span>
                  </div>
                )}
                {data.original_input && data.original_input !== data.target && (
                  <div className="text-xs text-gray-600">
                    (from: {data.original_input})
                  </div>
                )}
              </div>
              <button 
                onClick={() => {
                  const API_BASE = import.meta.env.VITE_API_URL || '/api';
                  window.open(`${API_BASE}/v1/report/${domain}`, '_blank');
                }}
                className="bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white px-6 py-3 rounded-xl font-bold flex items-center gap-2 transition-all shadow-lg shadow-cyan-500/20"
              >
                <Download className="w-5 h-5" />
                <span>Download Report</span>
              </button>
            </div>

            {/* Risk Assessment - Always Expanded */}
            <div className="mb-6 bg-gradient-to-br from-gray-900/80 to-gray-900/40 backdrop-blur-sm border border-gray-800/50 rounded-xl p-6 shadow-xl">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 bg-gradient-to-br from-rose-500/20 to-rose-600/10 rounded-xl border border-rose-500/30">
                  <ShieldAlert className="w-6 h-6 text-rose-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-300">Threat Assessment & Risk Analysis</h2>
                  <p className="text-xs text-gray-600 mt-1">Comprehensive security evaluation based on passive reconnaissance</p>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-8">
                {/* Risk Score */}
                <div className="space-y-6">
                  <div>
                    <RiskGauge score={data.risk_score || 0} level={data.risk_level || 'UNKNOWN'} />
                    <p className="text-sm text-gray-400 italic leading-relaxed mt-4">{data.risk_status}</p>
                    
                    {/* Risk calculation note */}
                    <div className="mt-3 p-3 bg-gray-900/50 border border-gray-800/50 rounded-lg">
                      <div className="flex items-start gap-2">
                        <Info className="w-4 h-4 text-cyan-500 flex-shrink-0 mt-0.5" />
                        <div className="text-xs text-gray-500">
                          <span className="text-gray-400 font-medium">Risk calculated based on:</span>
                          <div className="mt-1 space-y-0.5 text-gray-600">
                            • Security headers presence
                            • SSL/TLS configuration
                            • Server information disclosure
                            • Protocol security (HTTP vs HTTPS)
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Scan History */}
                  <div className="pt-4 border-t border-gray-800/50">
                    <div className="text-xs text-gray-500 uppercase tracking-wider mb-3">Scan History</div>
                    {data.history_correlation?.status === 'REPEAT_TARGET' ? (
                      <div className="flex items-start gap-3 p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg">
                        <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-amber-400 text-sm">Repeat Target</div>
                          <div className="text-xs text-gray-500 mt-1">
                            This domain has been scanned {data.history_correlation.previous_scans} time(s) before
                          </div>
                          {data.history_correlation.last_scan && (
                            <div className="text-xs text-gray-600 mt-1">
                              Last scan: {data.history_correlation.last_scan}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-start gap-3 p-3 bg-emerald-500/5 border border-emerald-500/20 rounded-lg">
                        <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-emerald-400 text-sm">First Reconnaissance</div>
                          <div className="text-xs text-gray-500 mt-1">Initial intelligence gathering for this target</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Critical Issues & Recommendations */}
                <div className="md:col-span-2 space-y-6">
                  {/* Critical Alerts */}
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="text-sm font-bold text-gray-400 uppercase tracking-wider">
                        Critical Security Findings
                      </div>
                      <span className="px-3 py-1 bg-rose-500/10 border border-rose-500/30 rounded-full text-rose-400 text-xs font-bold">
                        {data.risk_issues?.length || 0} Issues
                      </span>
                    </div>
                    
                    <div className="bg-black/40 rounded-xl p-4 border border-gray-800/50 min-h-[200px]">
                      {data.risk_issues?.length > 0 ? (
                        <div className="grid md:grid-cols-2 gap-3">
                          {data.risk_issues.map((issue, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 bg-rose-500/5 border border-rose-500/20 rounded-lg group hover:border-rose-500/40 transition-colors">
                              <XCircle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                              <span className="text-rose-300 text-sm leading-relaxed">{issue}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex flex-col items-center justify-center h-full py-8">
                          <CheckCircle className="w-12 h-12 text-emerald-500 mb-3" />
                          <div className="text-emerald-400 font-bold text-lg">No Critical Vulnerabilities</div>
                          <div className="text-gray-500 text-sm mt-2">Security posture appears strong</div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Recommendations */}
                  {data.recommendations && data.recommendations.length > 0 && (
                    <div>
                      <div className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3">
                        Security Recommendations
                      </div>
                      <div className="space-y-2">
                        {data.recommendations.slice(0, 4).map((rec, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 bg-cyan-500/5 border border-cyan-500/20 rounded-lg group hover:border-cyan-500/40 transition-colors">
                            <Zap className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                            <span className="text-cyan-300 text-sm leading-relaxed">{rec}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Intelligence Cards Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ExpandableCard 
                title="Infrastructure Intelligence" 
                icon={Globe} 
                data={data.infrastructure}
                renderContent={renderInfrastructure}
              />
              
              <ExpandableCard 
                title="System Fingerprint" 
                icon={Fingerprint} 
                data={data.fingerprint}
                renderContent={renderFingerprint}
              />
              
              <ExpandableCard 
                title="SSL/TLS Certificate" 
                icon={Lock} 
                data={data.ssl_certificate}
                renderContent={renderSSL}
              />
              
              <ExpandableCard 
                title="DNS Records" 
                icon={Activity} 
                data={data.dns}
                renderContent={renderDNS}
              />
              
              <ExpandableCard 
                title="Subdomain Discovery" 
                icon={Terminal} 
                data={data.subdomains}
                renderContent={renderSubdomains}
              />
              
              <ExpandableCard 
                title="WHOIS Information" 
                icon={Database} 
                data={data.whois}
                renderContent={renderWHOIS}
              />
              
              <ExpandableCard 
                title="Technology Stack" 
                icon={Cpu} 
                data={data.technology}
                renderContent={renderTechnology}
              />
              
              <ExpandableCard 
                title="Web Archives" 
                icon={History} 
                data={data.wayback}
                renderContent={renderWayback}
              />
            </div>

            {/* Footer */}
            <div className="mt-12 pt-8 border-t border-gray-800/50 text-center">
              <p className="text-sm text-gray-600">CoreRecon Intelligence Platform v1.0</p>
              <p className="text-xs text-gray-700 mt-2">For authorized security testing and research purposes only</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}