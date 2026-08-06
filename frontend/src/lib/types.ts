export type ToolName = "lynis" | "nmap" | "rkhunter" | "zap-docker" | "trivy" | "jq";

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  server_count: number;
}

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_type: "password" | "private_key";
  has_sudo_password: boolean;
  web_targets: string[];
  installed_tools: Record<string, boolean>;
  last_run_id: string | null;
  created_at: string;
}

export interface KernelVulnerability {
  id?: string;
  package?: string;
  installed?: string;
  fixed?: string;
  severity?: string;
  title?: string;
}

export interface AuditRunSummary {
  current_phase?: string;
  lynis_score?: number;
  lynis_grade?: string;
  lynis_warnings?: number;
  lynis_suggestions?: number;
  open_ports?: number;
  zap_high?: number;
  zap_medium?: number;
  zap_low?: number;
  health_failed?: number;
  health_total?: number;
  suid_sgid_count?: number;
  audit_timestamp?: string;
  kernel_vulns_count?: number;
  kernel_critical_count?: number;
  kernel_high_count?: number;
  kernel_vulnerabilities?: KernelVulnerability[];
  kernel_scan_skipped?: boolean;
  kernel_scan_skip_reason?: string;
}

export interface AuditRun {
  id: string;
  server_id: string;
  run_type: "install_tools" | "audit" | "test_connection";
  status: "queued" | "running" | "completed" | "failed";
  requested_tools: ToolName[];
  flags: string[];
  started_at: string;
  finished_at: string | null;
  log_tail: string;
  report_path: string | null;
  summary: AuditRunSummary | null;
}
