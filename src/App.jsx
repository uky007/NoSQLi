import { useState, useEffect, useRef } from "react";

const SQLI_PATTERNS = [
  { pattern: /union\s+select/i, name: "UNION-based Injection", severity: "CRITICAL", desc: "UNION SELECT detected. Data exfiltration attempt blocked." },
  { pattern: /union\s+all\s+select/i, name: "UNION ALL Injection", severity: "CRITICAL", desc: "UNION ALL SELECT detected. Mass data exfiltration attempt blocked." },
  { pattern: /'\s*or\s+['"]?[0-9]/i, name: "Tautology Attack", severity: "CRITICAL", desc: "Classic OR-based authentication bypass detected." },
  { pattern: /'\s*or\s+['"]/i, name: "String Tautology", severity: "CRITICAL", desc: "String-based tautology injection detected." },
  { pattern: /or\s+1\s*=\s*1/i, name: "Boolean Tautology", severity: "CRITICAL", desc: "OR 1=1 boolean bypass detected." },
  { pattern: /or\s+true/i, name: "Boolean Bypass", severity: "CRITICAL", desc: "OR TRUE authentication bypass detected." },
  { pattern: /'\s*;\s*drop\s/i, name: "DROP Statement Injection", severity: "CRITICAL", desc: "Attempted table/database destruction detected." },
  { pattern: /drop\s+table/i, name: "DROP TABLE", severity: "CRITICAL", desc: "DROP TABLE statement detected. Destruction attempt blocked." },
  { pattern: /drop\s+database/i, name: "DROP DATABASE", severity: "CRITICAL", desc: "DROP DATABASE detected. Total annihilation attempt blocked." },
  { pattern: /;\s*delete\s/i, name: "DELETE Injection", severity: "CRITICAL", desc: "Chained DELETE statement detected." },
  { pattern: /;\s*update\s/i, name: "UPDATE Injection", severity: "HIGH", desc: "Chained UPDATE statement detected." },
  { pattern: /;\s*insert\s/i, name: "INSERT Injection", severity: "HIGH", desc: "Chained INSERT statement detected." },
  { pattern: /information_schema/i, name: "Schema Reconnaissance", severity: "CRITICAL", desc: "information_schema access attempt. Database structure leak blocked." },
  { pattern: /sys\.tables/i, name: "System Table Access", severity: "CRITICAL", desc: "System table reconnaissance detected." },
  { pattern: /pg_catalog/i, name: "PostgreSQL Catalog Access", severity: "CRITICAL", desc: "PostgreSQL system catalog probing detected." },
  { pattern: /sqlite_master/i, name: "SQLite Master Access", severity: "CRITICAL", desc: "SQLite master table access attempt detected." },
  { pattern: /sleep\s*\(/i, name: "Time-based Blind SQLi", severity: "HIGH", desc: "SLEEP() function detected. Time-based blind injection blocked." },
  { pattern: /benchmark\s*\(/i, name: "Benchmark Timing Attack", severity: "HIGH", desc: "BENCHMARK() timing attack detected." },
  { pattern: /waitfor\s+delay/i, name: "WAITFOR Attack", severity: "HIGH", desc: "WAITFOR DELAY timing attack detected." },
  { pattern: /load_file\s*\(/i, name: "File Read Attack", severity: "CRITICAL", desc: "LOAD_FILE() detected. File system access attempt blocked." },
  { pattern: /into\s+(out|dump)file/i, name: "File Write Attack", severity: "CRITICAL", desc: "INTO OUTFILE/DUMPFILE detected. File write attempt blocked." },
  { pattern: /exec\s*\(/i, name: "Command Execution", severity: "CRITICAL", desc: "EXEC() detected. OS command execution attempt blocked." },
  { pattern: /xp_cmdshell/i, name: "xp_cmdshell Attack", severity: "CRITICAL", desc: "xp_cmdshell detected. Windows command shell access blocked." },
  { pattern: /concat\s*\(/i, name: "String Concatenation", severity: "MEDIUM", desc: "CONCAT() detected. Potential payload construction." },
  { pattern: /group_concat\s*\(/i, name: "Data Aggregation Attack", severity: "HIGH", desc: "GROUP_CONCAT() detected. Mass data extraction attempt." },
  { pattern: /char\s*\(/i, name: "Character Encoding Bypass", severity: "MEDIUM", desc: "CHAR() detected. Encoding-based filter evasion attempt." },
  { pattern: /0x[0-9a-f]{4,}/i, name: "Hex Encoding", severity: "MEDIUM", desc: "Hex-encoded payload detected." },
  { pattern: /\/\*.*\*\//i, name: "Comment Obfuscation", severity: "MEDIUM", desc: "Inline comment detected. Query obfuscation attempt." },
  { pattern: /--\s/i, name: "Line Comment Injection", severity: "HIGH", desc: "SQL line comment (--) detected. Query truncation attempt." },
  { pattern: /#\s*$/m, name: "MySQL Comment", severity: "HIGH", desc: "MySQL-style comment (#) detected." },
  { pattern: /'\s*$/m, name: "Unterminated String", severity: "MEDIUM", desc: "Unterminated string literal. Possible injection probe." },
  { pattern: /;\s*$/m, name: "Statement Terminator", severity: "LOW", desc: "Trailing semicolon detected. Multi-statement attempt." },
  { pattern: /select\s+/i, name: "SELECT Statement", severity: "MEDIUM", desc: "SELECT keyword detected in input. Suspicious." },
  { pattern: /where\s+/i, name: "WHERE Clause", severity: "LOW", desc: "WHERE keyword detected. Potential clause manipulation." },
  { pattern: /having\s+/i, name: "HAVING Clause Injection", severity: "MEDIUM", desc: "HAVING clause detected. Aggregate-based injection attempt." },
  { pattern: /order\s+by\s+\d/i, name: "ORDER BY Enumeration", severity: "MEDIUM", desc: "Numeric ORDER BY detected. Column count enumeration attempt." },
  { pattern: /'\s*and\s+/i, name: "AND-based Injection", severity: "HIGH", desc: "AND clause after string delimiter. Blind injection attempt." },
  { pattern: /extractvalue\s*\(/i, name: "ExtractValue Attack", severity: "HIGH", desc: "EXTRACTVALUE() error-based injection detected." },
  { pattern: /updatexml\s*\(/i, name: "UpdateXML Attack", severity: "HIGH", desc: "UPDATEXML() error-based injection detected." },
  { pattern: /substr\s*\(/i, name: "Substring Extraction", severity: "MEDIUM", desc: "SUBSTR() detected. Character-by-character extraction attempt." },
  { pattern: /ascii\s*\(/i, name: "ASCII Conversion", severity: "MEDIUM", desc: "ASCII() detected. Character code probing." },
  { pattern: /hex\s*\(/i, name: "Hex Conversion", severity: "MEDIUM", desc: "HEX() detected. Data encoding attempt." },
  { pattern: /version\s*\(/i, name: "Version Fingerprinting", severity: "HIGH", desc: "VERSION() detected. Database fingerprinting attempt." },
  { pattern: /@@version/i, name: "Version Variable", severity: "HIGH", desc: "@@version access. Database identification attempt." },
  { pattern: /user\s*\(\s*\)/i, name: "User Enumeration", severity: "HIGH", desc: "USER() detected. Privilege reconnaissance." },
  { pattern: /database\s*\(\s*\)/i, name: "Database Name Leak", severity: "HIGH", desc: "DATABASE() detected. Schema reconnaissance." },
  { pattern: /current_user/i, name: "Current User Probe", severity: "HIGH", desc: "CURRENT_USER detected. User context probing." },
  { pattern: /'\s*\|\|\s*'/i, name: "String Concatenation (Oracle)", severity: "MEDIUM", desc: "Oracle-style string concatenation detected." },
  { pattern: /like\s+'/i, name: "LIKE Injection", severity: "LOW", desc: "LIKE clause with string. Pattern matching manipulation." },
  { pattern: /'\)/i, name: "Parenthesis After Quote", severity: "LOW", desc: "Closing parenthesis after string delimiter. Syntax manipulation." },
  { pattern: /'\s*,/i, name: "Comma After Quote", severity: "LOW", desc: "Comma after string delimiter. Parameter injection attempt." },
];

const EXAMPLE_QUERIES = [
  { label: "Normal: User lookup", query: "SELECT * FROM users WHERE id = 42" },
  { label: "Normal: Search by name", query: "SELECT name FROM employees WHERE name = 'O\\'Brien'" },
  { label: "Normal: Join query", query: "SELECT o.id, u.name FROM orders o JOIN users u ON o.user_id = u.id" },
  { label: "Attack: Auth bypass", query: "' OR '1'='1' --" },
  { label: "Attack: UNION extract", query: "' UNION SELECT username, password FROM users --" },
  { label: "Attack: DROP TABLE", query: "'; DROP TABLE users; --" },
  { label: "Attack: Time-based blind", query: "' AND SLEEP(5) --" },
  { label: "Attack: Schema recon", query: "' UNION SELECT table_name, NULL FROM information_schema.tables --" },
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff1744", bg: "rgba(255,23,68,0.08)", border: "rgba(255,23,68,0.3)", icon: "☠" },
  HIGH: { color: "#ff6d00", bg: "rgba(255,109,0,0.08)", border: "rgba(255,109,0,0.3)", icon: "⚠" },
  MEDIUM: { color: "#ffd600", bg: "rgba(255,214,0,0.08)", border: "rgba(255,214,0,0.3)", icon: "◆" },
  LOW: { color: "#69f0ae", bg: "rgba(105,240,174,0.08)", border: "rgba(105,240,174,0.3)", icon: "●" },
};

function analyzeQuery(query) {
  if (!query.trim()) return [];
  const matches = [];
  for (const rule of SQLI_PATTERNS) {
    if (rule.pattern.test(query)) {
      matches.push(rule);
    }
  }
  return matches;
}

function getThreatLevel(matches) {
  if (matches.length === 0) return 0;
  const severityScores = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 5 };
  const total = matches.reduce((sum, m) => sum + severityScores[m.severity], 0);
  return Math.min(total, 100);
}

function ThreatMeter({ level }) {
  const getColor = (l) => {
    if (l === 0) return "#2e7d32";
    if (l < 20) return "#69f0ae";
    if (l < 40) return "#ffd600";
    if (l < 60) return "#ff9100";
    if (l < 80) return "#ff6d00";
    return "#ff1744";
  };

  const getLabel = (l) => {
    if (l === 0) return "SAFE";
    if (l < 20) return "SUSPICIOUS";
    if (l < 40) return "ELEVATED";
    if (l < 60) return "HIGH";
    if (l < 80) return "SEVERE";
    return "MAXIMUM";
  };

  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
        <span style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 11, color: "#8a8a8a", letterSpacing: 2, textTransform: "uppercase" }}>Threat Level</span>
        <span style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 13,
          fontWeight: 700,
          color: getColor(level),
          letterSpacing: 1,
          transition: "color 0.3s ease",
        }}>
          {getLabel(level)} ({level}%)
        </span>
      </div>
      <div style={{
        height: 6,
        background: "rgba(255,255,255,0.05)",
        borderRadius: 3,
        overflow: "hidden",
        border: "1px solid rgba(255,255,255,0.06)",
      }}>
        <div style={{
          height: "100%",
          width: `${level}%`,
          background: `linear-gradient(90deg, ${getColor(Math.max(0, level - 20))}, ${getColor(level)})`,
          borderRadius: 3,
          transition: "width 0.5s cubic-bezier(0.4,0,0.2,1), background 0.5s ease",
          boxShadow: level > 50 ? `0 0 12px ${getColor(level)}40` : "none",
        }} />
      </div>
    </div>
  );
}

function DetectionCard({ match, index }) {
  const config = SEVERITY_CONFIG[match.severity];
  return (
    <div style={{
      padding: "12px 16px",
      background: config.bg,
      border: `1px solid ${config.border}`,
      borderRadius: 6,
      marginBottom: 8,
      animation: `slideIn 0.3s ease ${index * 0.05}s both`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 12,
          fontWeight: 700,
          color: config.color,
        }}>
          {config.icon} {match.name}
        </span>
        <span style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 9,
          color: config.color,
          background: `${config.color}18`,
          padding: "2px 8px",
          borderRadius: 3,
          letterSpacing: 1,
          fontWeight: 700,
        }}>
          {match.severity}
        </span>
      </div>
      <div style={{
        fontFamily: "'IBM Plex Sans', 'Noto Sans JP', sans-serif",
        fontSize: 12,
        color: "#9e9e9e",
        lineHeight: 1.5,
      }}>
        {match.desc}
      </div>
    </div>
  );
}

function StatusBanner({ matches, query }) {
  if (!query.trim()) return null;
  const blocked = matches.length > 0;
  return (
    <div style={{
      padding: "14px 20px",
      borderRadius: 8,
      marginBottom: 16,
      background: blocked ? "rgba(255,23,68,0.06)" : "rgba(46,125,50,0.06)",
      border: `1px solid ${blocked ? "rgba(255,23,68,0.25)" : "rgba(46,125,50,0.25)"}`,
      display: "flex",
      alignItems: "center",
      gap: 12,
    }}>
      <span style={{ fontSize: 22 }}>{blocked ? "🛑" : "✅"}</span>
      <div>
        <div style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 13,
          fontWeight: 700,
          color: blocked ? "#ff1744" : "#2e7d32",
          marginBottom: 2,
        }}>
          {blocked ? "QUERY BLOCKED — SQLi DETECTED" : "QUERY ALLOWED"}
        </div>
        <div style={{
          fontFamily: "'IBM Plex Sans', 'Noto Sans JP', sans-serif",
          fontSize: 11,
          color: "#757575",
        }}>
          {blocked
            ? `${matches.length} pattern${matches.length > 1 ? "s" : ""} matched. This query will NOT be forwarded to the database.`
            : "No injection patterns detected. Query forwarded to database."
          }
        </div>
      </div>
    </div>
  );
}

export default function NoSQLi() {
  const [query, setQuery] = useState("");
  const [matches, setMatches] = useState([]);
  const [threatLevel, setThreatLevel] = useState(0);
  const [totalBlocked, setTotalBlocked] = useState(0);
  const [totalAllowed, setTotalAllowed] = useState(0);
  const [history, setHistory] = useState([]);
  const textareaRef = useRef(null);

  useEffect(() => {
    const m = analyzeQuery(query);
    setMatches(m);
    setThreatLevel(getThreatLevel(m));
  }, [query]);

  const handleSubmit = () => {
    if (!query.trim()) return;
    const m = analyzeQuery(query);
    const blocked = m.length > 0;
    if (blocked) setTotalBlocked(prev => prev + 1);
    else setTotalAllowed(prev => prev + 1);
    setHistory(prev => [{ query, blocked, count: m.length, time: new Date().toLocaleTimeString() }, ...prev].slice(0, 20));
  };

  const handleExample = (q) => {
    setQuery(q);
    if (textareaRef.current) textareaRef.current.focus();
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0a0a",
      color: "#e0e0e0",
      fontFamily: "'IBM Plex Sans', 'Noto Sans JP', sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;500;700&family=Noto+Sans+JP:wght@400;700&display=swap');
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        textarea:focus { outline: none; border-color: rgba(255,255,255,0.15) !important; }
        textarea::placeholder { color: #4a4a4a; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
      `}</style>

      <div style={{ maxWidth: 880, margin: "0 auto", padding: "40px 24px" }}>
        {/* Header */}
        <div style={{ marginBottom: 40, borderBottom: "1px solid rgba(255,255,255,0.06)", paddingBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            <span style={{ fontSize: 20 }}>🛡️</span>
            <h1 style={{
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              fontSize: 22,
              fontWeight: 700,
              color: "#ffffff",
              margin: 0,
              letterSpacing: -0.5,
            }}>
              NoSQLi
            </h1>
            <span style={{
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              fontSize: 9,
              color: "#ff1744",
              background: "rgba(255,23,68,0.1)",
              padding: "2px 8px",
              borderRadius: 3,
              letterSpacing: 1,
              fontWeight: 700,
              animation: "pulse 2s ease infinite",
            }}>
              PARANOID MODE
            </span>
          </div>
          <p style={{ fontSize: 13, color: "#666", margin: 0, lineHeight: 1.6 }}>
            Database proxy that pre-screens ALL queries against {SQLI_PATTERNS.length} known SQLi patterns.
            Zero false negatives guaranteed. Usability not guaranteed.
          </p>

          {/* Stats */}
          <div style={{ display: "flex", gap: 24, marginTop: 16 }}>
            {[
              { label: "PATTERNS", value: SQLI_PATTERNS.length, color: "#64b5f6" },
              { label: "BLOCKED", value: totalBlocked, color: "#ff1744" },
              { label: "ALLOWED", value: totalAllowed, color: "#2e7d32" },
              { label: "BLOCK RATE", value: totalBlocked + totalAllowed > 0 ? Math.round((totalBlocked / (totalBlocked + totalAllowed)) * 100) + "%" : "—", color: "#ffd600" },
            ].map((s, i) => (
              <div key={i}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#555", letterSpacing: 2, marginBottom: 2 }}>{s.label}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 18, fontWeight: 700, color: s.color }}>{s.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Main layout */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 32 }}>
          {/* Left column */}
          <div>
            {/* Input */}
            <div style={{ marginBottom: 20 }}>
              <label style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                color: "#555",
                letterSpacing: 2,
                textTransform: "uppercase",
                display: "block",
                marginBottom: 8,
              }}>
                SQL Query Input
              </label>
              <textarea
                ref={textareaRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter SQL query to analyze..."
                rows={4}
                style={{
                  width: "100%",
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 8,
                  padding: "14px 16px",
                  color: "#e0e0e0",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 13,
                  lineHeight: 1.6,
                  resize: "vertical",
                  boxSizing: "border-box",
                }}
              />
              <button
                onClick={handleSubmit}
                style={{
                  marginTop: 10,
                  padding: "10px 24px",
                  background: threatLevel > 0 ? "rgba(255,23,68,0.12)" : "rgba(46,125,50,0.12)",
                  border: `1px solid ${threatLevel > 0 ? "rgba(255,23,68,0.3)" : "rgba(46,125,50,0.3)"}`,
                  borderRadius: 6,
                  color: threatLevel > 0 ? "#ff1744" : "#69f0ae",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: "pointer",
                  letterSpacing: 1,
                  transition: "all 0.2s ease",
                }}
              >
                {threatLevel > 0 ? "🛑 EXECUTE (WILL BE BLOCKED)" : "✓ EXECUTE QUERY"}
              </button>
            </div>

            {/* Threat meter */}
            <ThreatMeter level={threatLevel} />

            {/* Status */}
            <StatusBanner matches={matches} query={query} />

            {/* Detections */}
            {matches.length > 0 && (
              <div>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  color: "#555",
                  letterSpacing: 2,
                  marginBottom: 12,
                }}>
                  DETECTIONS ({matches.length})
                </div>
                {matches.map((m, i) => (
                  <DetectionCard key={i} match={m} index={i} />
                ))}
              </div>
            )}

            {/* History */}
            {history.length > 0 && (
              <div style={{ marginTop: 32 }}>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  color: "#555",
                  letterSpacing: 2,
                  marginBottom: 12,
                }}>
                  QUERY LOG
                </div>
                {history.map((h, i) => (
                  <div key={i} style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 12px",
                    borderBottom: "1px solid rgba(255,255,255,0.03)",
                    fontSize: 11,
                  }}>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 9,
                      color: "#444",
                      minWidth: 64,
                    }}>{h.time}</span>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 9,
                      fontWeight: 700,
                      color: h.blocked ? "#ff1744" : "#2e7d32",
                      minWidth: 60,
                    }}>
                      {h.blocked ? `BLOCKED (${h.count})` : "ALLOWED"}
                    </span>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11,
                      color: "#666",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {h.query}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Right column: examples */}
          <div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: "#555",
              letterSpacing: 2,
              marginBottom: 12,
            }}>
              SAMPLE QUERIES
            </div>
            {EXAMPLE_QUERIES.map((ex, i) => (
              <button
                key={i}
                onClick={() => handleExample(ex.query)}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "10px 12px",
                  marginBottom: 6,
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderRadius: 6,
                  cursor: "pointer",
                  transition: "all 0.15s ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(255,255,255,0.05)";
                  e.currentTarget.style.borderColor = "rgba(255,255,255,0.12)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(255,255,255,0.02)";
                  e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)";
                }}
              >
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  color: ex.label.startsWith("Attack") ? "#ff6d00" : "#4caf50",
                  letterSpacing: 0.5,
                  marginBottom: 4,
                }}>
                  {ex.label}
                </div>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  color: "#888",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}>
                  {ex.query}
                </div>
              </button>
            ))}

            {/* Disclaimer */}
            <div style={{
              marginTop: 24,
              padding: "14px 16px",
              background: "rgba(255,214,0,0.04)",
              border: "1px solid rgba(255,214,0,0.12)",
              borderRadius: 8,
            }}>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: "#ffd600",
                letterSpacing: 2,
                marginBottom: 6,
              }}>
                ⚠ DISCLAIMER
              </div>
              <div style={{
                fontSize: 11,
                color: "#777",
                lineHeight: 1.6,
              }}>
                This tool achieves maximum SQLi protection by blocking everything that looks remotely suspicious. 
                Side effects may include: inability to query users named O'Brien, 
                SELECT committees, or anything containing the word "drop". 
                We consider this an acceptable trade-off.
              </div>
            </div>

            {/* Pattern count by severity */}
            <div style={{ marginTop: 20 }}>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                color: "#555",
                letterSpacing: 2,
                marginBottom: 10,
              }}>
                PATTERN COVERAGE
              </div>
              {Object.entries(SEVERITY_CONFIG).map(([sev, config]) => {
                const count = SQLI_PATTERNS.filter(p => p.severity === sev).length;
                return (
                  <div key={sev} style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "6px 0",
                    borderBottom: "1px solid rgba(255,255,255,0.03)",
                  }}>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 11,
                      color: config.color,
                    }}>
                      {config.icon} {sev}
                    </span>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      color: "#888",
                    }}>
                      {count}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
