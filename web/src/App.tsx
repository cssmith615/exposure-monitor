import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bell,
  Building2,
  CheckCircle2,
  Fingerprint,
  Globe2,
  LockKeyhole,
  LogOut,
  Plus,
  Radar,
  RefreshCw,
  ShieldCheck,
  Slack,
  TerminalSquare,
  UserPlus,
} from 'lucide-react'
import './App.css'

const apiBaseUrl = import.meta.env.VITE_CEEM_API_URL ?? 'http://127.0.0.1:8080'
const sessionStorageKey = 'ceem.session'

type SessionState = {
  user: UserAccount
  session: SessionToken
}

type SessionToken = {
  access_token: string
  token_type: string
  expires_in_seconds: number
}

type UserAccount = {
  id: string
  email: string
  display_name: string
  created_at: string
}

type Organization = {
  id: string
  name: string
  slug: string
  created_at: string
}

type OrganizationSummary = {
  organization: Organization
  role: MemberRole
}

type MemberRole = 'owner' | 'admin' | 'member' | 'viewer'

type OrganizationMember = {
  user: UserAccount
  role: MemberRole
  created_at: string
}

type DomainAsset = {
  id: string
  organization_id: string
  domain: string
  authorization_attested_by: string
  authorization_attested_at: string
  created_at: string
}

type ScanJob = {
  id: string
  organization_id: string
  asset_id: string
  requested_by: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'canceled'
  reason: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

type ScanEvidence =
  | { kind: 'dns_baseline'; data: { domain: string; addresses: { record_type: string; value: string }[] } }
  | {
      kind: 'http_probe'
      data: {
        domain: string
        scheme: string
        status_code: number | null
        final_url: string | null
        redirect_chain: string[]
        error: string | null
      }
    }
  | { kind: 'dns_policy'; data: { domain: string; spf_record: string | null; dmarc_record: string | null } }

type ScanResult = {
  id: string
  organization_id: string
  asset_id: string
  scan_job_id: string
  source: string
  observed_at: string
  evidence: ScanEvidence
}

type Finding = {
  id: string
  organization_id: string
  asset_id: string
  rule_id: string
  title: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  status: 'open' | 'accepted_risk' | 'false_positive' | 'in_progress' | 'remediated' | 'reopened'
  confidence: 'low' | 'medium' | 'high'
  evidence: string
  remediation: string
  first_seen_at: string
  last_seen_at: string
}

type FindingEvent = {
  id: string
  organization_id: string
  finding_id: string
  actor_user_id: string
  event_type: string
  note: string | null
  created_at: string
}

type Alert = {
  id: string
  organization_id: string
  finding_id: string
  notification_channel_id: string
  status: 'queued' | 'sent' | 'failed' | 'suppressed'
  payload: string
  created_at: string
  sent_at: string | null
}

type RemediationTask = {
  id: string
  organization_id: string
  finding_id: string
  title: string
  status: 'open' | 'in_progress' | 'blocked' | 'remediated' | 'accepted_risk' | 'false_positive'
  assignee: string | null
  created_at: string
  updated_at: string
}

type AuditLog = {
  id: string
  organization_id: string | null
  actor_user_id: string | null
  action: string
  target_type: string
  target_id: string | null
  metadata: Record<string, unknown>
  created_at: string
}

type WorkspaceData = {
  assets: DomainAsset[]
  scanJobs: ScanJob[]
  scanResults: ScanResult[]
  findings: Finding[]
  alerts: Alert[]
  remediationTasks: RemediationTask[]
  auditLogs: AuditLog[]
  members: OrganizationMember[]
}

const emptyWorkspace: WorkspaceData = {
  assets: [],
  scanJobs: [],
  scanResults: [],
  findings: [],
  alerts: [],
  remediationTasks: [],
  auditLogs: [],
  members: [],
}

function App() {
  const [session, setSession] = useState<SessionState | null>(() => loadStoredSession())
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [authEmail, setAuthEmail] = useState('chris@example.com')
  const [authName, setAuthName] = useState('Chris Smith')
  const [authPassword, setAuthPassword] = useState('correct-horse-7!')
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([])
  const [activeOrganizationId, setActiveOrganizationId] = useState<string>('')
  const [workspace, setWorkspace] = useState<WorkspaceData>(emptyWorkspace)
  const [domainInput, setDomainInput] = useState('billing.example.com')
  const [attested, setAttested] = useState(true)
  const [orgName, setOrgName] = useState('Acme Startup')
  const [orgSlug, setOrgSlug] = useState('acme-startup')
  const [inviteEmail, setInviteEmail] = useState('')
  const [slackName, setSlackName] = useState('#security-alerts')
  const [slackWebhookUrl, setSlackWebhookUrl] = useState('')
  const [activeFindingId, setActiveFindingId] = useState<string>('')
  const [findingEvents, setFindingEvents] = useState<FindingEvent[]>([])
  const [noteDraft, setNoteDraft] = useState('Accepted through launch week; revisit after automation lands.')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const activeOrganization = organizations.find(
    (summary) => summary.organization.id === activeOrganizationId,
  )?.organization
  const activeFinding = workspace.findings.find((finding) => finding.id === activeFindingId)
  const activeAssetById = useMemo(
    () => new Map(workspace.assets.map((asset) => [asset.id, asset])),
    [workspace.assets],
  )
  const latestScanTarget = workspace.assets[0]
  const openFindings = workspace.findings.filter((finding) => finding.status !== 'remediated')
  const highFindings = workspace.findings.filter(
    (finding) => finding.severity === 'high' || finding.severity === 'critical',
  )

  const api = useCallback(
    async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
      const response = await fetch(`${apiBaseUrl}${path}`, {
        ...options,
        headers: {
          'content-type': 'application/json',
          ...(session ? { authorization: `Bearer ${session.session.access_token}` } : {}),
          ...options.headers,
        },
      })
      const body = await response.text()
      const parsed = body ? JSON.parse(body) : null
      if (!response.ok) {
        throw new Error(parsed?.error ?? `Request failed with ${response.status}`)
      }
      return parsed as T
    },
    [session],
  )

  const refreshOrganizations = useCallback(async () => {
    if (!session) {
      return
    }
    const nextOrganizations = await api<OrganizationSummary[]>('/v1/organizations')
    setOrganizations(nextOrganizations)
    setActiveOrganizationId((current) => current || nextOrganizations[0]?.organization.id || '')
  }, [api, session])

  const refreshWorkspace = useCallback(async () => {
    if (!activeOrganizationId || !session) {
      setWorkspace(emptyWorkspace)
      return
    }

    setIsLoading(true)
    setError(null)
    try {
      const [
        assets,
        scanJobs,
        scanResults,
        findings,
        alerts,
        remediationTasks,
        auditLogs,
        members,
      ] = await Promise.all([
        api<DomainAsset[]>(`/v1/organizations/${activeOrganizationId}/domain-assets`),
        api<ScanJob[]>(`/v1/organizations/${activeOrganizationId}/scan-jobs`),
        api<ScanResult[]>(`/v1/organizations/${activeOrganizationId}/scan-results`),
        api<Finding[]>(`/v1/organizations/${activeOrganizationId}/findings`),
        api<Alert[]>(`/v1/organizations/${activeOrganizationId}/alerts`),
        api<RemediationTask[]>(`/v1/organizations/${activeOrganizationId}/remediation-tasks`),
        api<AuditLog[]>(`/v1/organizations/${activeOrganizationId}/audit-logs`),
        api<OrganizationMember[]>(`/v1/organizations/${activeOrganizationId}/members`),
      ])
      setWorkspace({ assets, scanJobs, scanResults, findings, alerts, remediationTasks, auditLogs, members })
      setActiveFindingId((current) => current || findings[0]?.id || '')
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setIsLoading(false)
    }
  }, [activeOrganizationId, api, session])

  useEffect(() => {
    refreshOrganizations().catch((caught) => setError(errorMessage(caught)))
  }, [refreshOrganizations])

  useEffect(() => {
    refreshWorkspace()
  }, [refreshWorkspace])

  useEffect(() => {
    if (!activeOrganizationId || !activeFindingId || !session) {
      setFindingEvents([])
      return
    }
    api<FindingEvent[]>(`/v1/organizations/${activeOrganizationId}/findings/${activeFindingId}/notes`)
      .then(setFindingEvents)
      .catch((caught) => setError(errorMessage(caught)))
  }, [activeFindingId, activeOrganizationId, api, session])

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsLoading(true)
    setError(null)
    try {
      const nextSession =
        authMode === 'login'
          ? await api<SessionState>('/v1/auth/login', {
              method: 'POST',
              body: JSON.stringify({ email: authEmail, password: authPassword }),
            })
          : await api<SessionState>('/v1/auth/register', {
              method: 'POST',
              body: JSON.stringify({
                email: authEmail,
                display_name: authName,
                password: authPassword,
              }),
            })
      localStorage.setItem(sessionStorageKey, JSON.stringify(nextSession))
      setSession(nextSession)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setIsLoading(false)
    }
  }

  async function createOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await mutate(async () => {
      const response = await api<{ organization: Organization }>('/v1/organizations', {
        method: 'POST',
        body: JSON.stringify({ name: orgName, slug: orgSlug }),
      })
      await refreshOrganizations()
      setActiveOrganizationId(response.organization.id)
    })
  }

  async function queueDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!activeOrganizationId) {
      return
    }
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/domain-assets`, {
        method: 'POST',
        body: JSON.stringify({ domain: normalizedDomain, authorization_attested: attested }),
      })
      setDomainInput('')
      await refreshWorkspace()
    })
  }

  async function queueScan(assetId: string, reason = 'Manual authorized scan') {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/domain-assets/${assetId}/scan-jobs`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      })
      await refreshWorkspace()
    })
  }

  async function runScan(scanJobId: string, scanType: 'dns-baseline' | 'http-probe' | 'dns-policy') {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/scan-jobs/${scanJobId}/run-${scanType}`, {
        method: 'POST',
      })
      await refreshWorkspace()
    })
  }

  async function deriveLatestFindings(scanResultId: string) {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/scan-results/${scanResultId}/derive-findings`, {
        method: 'POST',
      })
      await refreshWorkspace()
    })
  }

  async function queueSlackAlert(findingId: string) {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/findings/${findingId}/slack-alerts`, {
        method: 'POST',
      })
      await refreshWorkspace()
    })
  }

  async function saveSlackChannel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/slack-channels`, {
        method: 'POST',
        body: JSON.stringify({ name: slackName, webhook_url: slackWebhookUrl }),
      })
      setSlackWebhookUrl('')
      await refreshWorkspace()
    })
  }

  async function createRemediationTask(findingId: string) {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/findings/${findingId}/remediation-tasks`, {
        method: 'POST',
        body: JSON.stringify({ title: null, assignee: null }),
      })
      await refreshWorkspace()
    })
  }

  async function updateFindingStatus(status: Finding['status']) {
    if (!activeFinding) {
      return
    }
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/findings/${activeFinding.id}/status`, {
        method: 'POST',
        body: JSON.stringify({ status, note: noteDraft }),
      })
      setNoteDraft('')
      await refreshWorkspace()
    })
  }

  async function addFindingNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!activeFinding) {
      return
    }
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/findings/${activeFinding.id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ note: noteDraft }),
      })
      setNoteDraft('')
      const events = await api<FindingEvent[]>(
        `/v1/organizations/${activeOrganizationId}/findings/${activeFinding.id}/notes`,
      )
      setFindingEvents(events)
    })
  }

  async function updateTaskStatus(taskId: string, status: RemediationTask['status']) {
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/remediation-tasks/${taskId}/status`, {
        method: 'POST',
        body: JSON.stringify({ status }),
      })
      await refreshWorkspace()
    })
  }

  async function inviteUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await mutate(async () => {
      await api(`/v1/organizations/${activeOrganizationId}/invites`, {
        method: 'POST',
        body: JSON.stringify({ email: inviteEmail, role: 'member' }),
      })
      setInviteEmail('')
      await refreshWorkspace()
    })
  }

  async function mutate(operation: () => Promise<void>) {
    setIsLoading(true)
    setError(null)
    try {
      await operation()
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setIsLoading(false)
    }
  }

  function logout() {
    localStorage.removeItem(sessionStorageKey)
    setSession(null)
    setOrganizations([])
    setWorkspace(emptyWorkspace)
    setActiveOrganizationId('')
  }

  const normalizedDomain = useMemo(
    () => domainInput.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase(),
    [domainInput],
  )
  const canQueueDomain =
    Boolean(activeOrganizationId) &&
    attested &&
    normalizedDomain.includes('.') &&
    !workspace.assets.some((asset) => asset.domain === normalizedDomain)

  if (!session) {
    return (
      <main className="auth-shell">
        <section className="auth-panel">
          <div className="brand large">
            <ShieldCheck size={28} aria-hidden="true" />
            <div>
              <strong>CEEM</strong>
              <span>Continuous external exposure monitor</span>
            </div>
          </div>
          <form className="auth-form" onSubmit={submitAuth}>
            <h1>{authMode === 'login' ? 'Sign in' : 'Create operator'}</h1>
            {error && <p className="error-banner">{error}</p>}
            {authMode === 'register' && (
              <label>
                Display name
                <input value={authName} onChange={(event) => setAuthName(event.target.value)} />
              </label>
            )}
            <label>
              Email
              <input value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} />
            </label>
            <label>
              Password
              <input
                type="password"
                value={authPassword}
                onChange={(event) => setAuthPassword(event.target.value)}
              />
            </label>
            <button disabled={isLoading} type="submit">
              <LockKeyhole size={18} aria-hidden="true" />
              {authMode === 'login' ? 'Login' : 'Register'}
            </button>
            <button
              className="secondary"
              type="button"
              onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
            >
              {authMode === 'login' ? 'Need an account?' : 'Already registered?'}
            </button>
          </form>
        </section>
      </main>
    )
  }

  if (!activeOrganization) {
    return (
      <main className="auth-shell">
        <section className="auth-panel">
          <div className="brand large">
            <Building2 size={28} aria-hidden="true" />
            <div>
              <strong>Launch workspace</strong>
              <span>{session.user.email}</span>
            </div>
          </div>
          {error && <p className="error-banner">{error}</p>}
          <form className="auth-form" onSubmit={createOrganization}>
            <label>
              Organization name
              <input value={orgName} onChange={(event) => setOrgName(event.target.value)} />
            </label>
            <label>
              Slug
              <input value={orgSlug} onChange={(event) => setOrgSlug(event.target.value)} />
            </label>
            <button disabled={isLoading} type="submit">
              <Plus size={18} aria-hidden="true" />
              Create organization
            </button>
            <button className="secondary" type="button" onClick={logout}>
              <LogOut size={18} aria-hidden="true" />
              Logout
            </button>
          </form>
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Primary">
        <div className="brand">
          <ShieldCheck size={24} aria-hidden="true" />
          <div>
            <strong>CEEM</strong>
            <span>Command surface</span>
          </div>
        </div>

        <nav>
          <a className="active" href="#overview"><Activity size={18} aria-hidden="true" />Overview</a>
          <a href="#assets"><Globe2 size={18} aria-hidden="true" />Domains</a>
          <a href="#findings"><AlertTriangle size={18} aria-hidden="true" />Findings</a>
          <a href="#alerts"><Slack size={18} aria-hidden="true" />Slack alerts</a>
          <a href="#team"><Building2 size={18} aria-hidden="true" />Team</a>
        </nav>

        <div className="authorization-note">
          <LockKeyhole size={18} aria-hidden="true" />
          <span>Authorization gate enabled</span>
        </div>
      </aside>

      <section className="workspace" id="overview">
        <header className="topbar">
          <div>
            <p className="eyebrow">{activeOrganization.name} / production perimeter</p>
            <h1>Exposure command</h1>
          </div>
          <div className="topbar-actions">
            <select
              aria-label="Organization"
              value={activeOrganizationId}
              onChange={(event) => setActiveOrganizationId(event.target.value)}
            >
              {organizations.map((summary) => (
                <option key={summary.organization.id} value={summary.organization.id}>
                  {summary.organization.name}
                </option>
              ))}
            </select>
            <button className="secondary" type="button" onClick={refreshWorkspace}>
              <RefreshCw size={18} aria-hidden="true" />
              Refresh
            </button>
            <button className="secondary" type="button" onClick={logout}>
              <LogOut size={18} aria-hidden="true" />
              Logout
            </button>
          </div>
        </header>

        {error && <p className="error-banner">{error}</p>}
        {isLoading && <p className="loading-banner">Syncing CEEM control plane...</p>}

        <section className="command-stage" aria-label="Exposure command view">
          <div className="stage-radar" aria-hidden="true">
            <div className="radar-grid">
              <span className="radar-ring ring-one" />
              <span className="radar-ring ring-two" />
              <span className="radar-ring ring-three" />
              <span className="radar-sweep" />
              <span className="radar-node clean" />
              <span className="radar-node warning" />
              <span className="radar-node queued" />
            </div>
            <div className="radar-caption">
              <strong>External perimeter</strong>
              <span>DNS, TLS, HTTP evidence lanes</span>
            </div>
          </div>
          <div className="stage-copy">
            <p className="eyebrow">Continuous external exposure monitor</p>
            <h2>
              {workspace.assets.length} domains watched. {highFindings.length} priority findings open.
            </h2>
            <div className="stage-actions">
              <button disabled={!latestScanTarget} type="button" onClick={() => latestScanTarget && queueScan(latestScanTarget.id)}>
                <Radar size={18} aria-hidden="true" />
                Queue worker scan
              </button>
              <button className="secondary" type="button" onClick={() => workspace.scanResults[0] && deriveLatestFindings(workspace.scanResults[0].id)}>
                <TerminalSquare size={18} aria-hidden="true" />
                Derive findings
              </button>
            </div>
          </div>
          <div className="stage-feed" aria-label="Audit event stream">
            {workspace.auditLogs.slice(0, 4).map((item) => (
              <div className="feed-item queued" key={item.id}>
                <span>{formatTime(item.created_at)}</span>
                <strong>{item.action.replaceAll('.', ' ')}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="metrics" aria-label="Exposure metrics">
          <article><span>Domains</span><strong>{workspace.assets.length}</strong><small>Authorized assets</small></article>
          <article><span>Open findings</span><strong>{openFindings.length}</strong><small>{highFindings.length} high or critical</small></article>
          <article><span>Last scan</span><strong>{workspace.scanResults[0] ? formatTime(workspace.scanResults[0].observed_at) : 'None'}</strong><small>Evidence capture</small></article>
          <article><span>Slack alerts</span><strong>{workspace.alerts.length}</strong><small>Queued, sent, failed, suppressed</small></article>
        </section>

        <section className="content-grid">
          <article className="panel intake-console" id="domain-intake">
            <div className="panel-header">
              <div><p className="eyebrow">Domain intake</p><h2>Authorization gate</h2></div>
              <Fingerprint size={22} aria-hidden="true" />
            </div>
            <form className="domain-form" onSubmit={queueDomain}>
              <label htmlFor="domain">Domain</label>
              <div className="domain-control">
                <Globe2 size={18} aria-hidden="true" />
                <input id="domain" value={domainInput} onChange={(event) => setDomainInput(event.target.value)} />
              </div>
              <label className="attestation-control">
                <input checked={attested} onChange={(event) => setAttested(event.target.checked)} type="checkbox" />
                <span>I am authorized to monitor this domain.</span>
              </label>
              <button disabled={!canQueueDomain} type="submit"><Plus size={18} aria-hidden="true" />Queue domain</button>
            </form>
          </article>

          <article className="panel exposure-map" id="assets">
            <div className="panel-header">
              <div><p className="eyebrow">Authorized domains</p><h2>Scan posture</h2></div>
            </div>
            {workspace.assets.map((asset) => (
              <div className="scan-row" key={asset.id}>
                <CheckCircle2 size={18} aria-hidden="true" />
                <span><strong>{asset.domain}</strong><small>Added {formatTime(asset.created_at)}</small></span>
                <button className="secondary" type="button" onClick={() => queueScan(asset.id)}>Scan</button>
              </div>
            ))}
            {workspace.assets.length === 0 && <p className="empty-state">No authorized domains yet.</p>}
          </article>

          <article className="panel" id="alerts">
            <div className="panel-header compact">
              <div><p className="eyebrow">Slack</p><h2>Alert policy</h2></div>
            </div>
            <form className="domain-form" onSubmit={saveSlackChannel}>
              <label>Channel</label>
              <input value={slackName} onChange={(event) => setSlackName(event.target.value)} />
              <label>Webhook URL</label>
              <input value={slackWebhookUrl} onChange={(event) => setSlackWebhookUrl(event.target.value)} />
              <button disabled={!slackWebhookUrl} type="submit"><Bell size={18} aria-hidden="true" />Save Slack</button>
            </form>
          </article>
        </section>

        <section className="panel scan-queue" aria-label="Scan queue">
          <div className="panel-header">
            <div><p className="eyebrow">Manual scan orchestration</p><h2>Scan jobs</h2></div>
          </div>
          <div className="job-list">
            {workspace.scanJobs.map((job) => (
              <div className={`job-row ${job.status}`} key={job.id}>
                <span className="job-id">{shortId(job.id)}</span>
                <span><strong>{activeAssetById.get(job.asset_id)?.domain ?? job.asset_id}</strong><small>{job.reason ?? 'Manual scan'}</small></span>
                <span>{formatTime(job.created_at)}</span>
                <span className="row-actions">
                  <mark className={job.status}>{job.status}</mark>
                  {job.status === 'queued' && (
                    <>
                      <button className="secondary" type="button" onClick={() => runScan(job.id, 'dns-baseline')}>DNS</button>
                      <button className="secondary" type="button" onClick={() => runScan(job.id, 'http-probe')}>HTTP</button>
                      <button className="secondary" type="button" onClick={() => runScan(job.id, 'dns-policy')}>TXT</button>
                    </>
                  )}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel evidence-vault" aria-label="Scan evidence">
          <div className="panel-header">
            <div><p className="eyebrow">Evidence vault</p><h2>Scan history</h2></div>
            <TerminalSquare size={22} aria-hidden="true" />
          </div>
          <div className="evidence-list">
            {workspace.scanResults.map((item) => (
              <div className="evidence-row" key={item.id}>
                <span className="job-id">{shortId(item.id)}</span>
                <span><strong>{activeAssetById.get(item.asset_id)?.domain ?? evidenceDomain(item.evidence)}</strong><small>{item.source}</small></span>
                <span className="address-stack">{evidenceSummary(item.evidence)}</span>
                <span>{formatTime(item.observed_at)}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel findings" id="findings">
          <div className="panel-header">
            <div><p className="eyebrow">Remediation workflow</p><h2>Current findings</h2></div>
          </div>
          <div className="finding-table">
            <div className="table-head"><span>Asset</span><span>Finding</span><span>Severity</span><span>Status</span><span>Confidence</span><span>Actions</span></div>
            {workspace.findings.map((finding) => (
              <div className="table-row" key={finding.id}>
                <span>{activeAssetById.get(finding.asset_id)?.domain ?? finding.asset_id}</span>
                <span>{finding.title}</span>
                <span><mark className={finding.severity}>{finding.severity}</mark></span>
                <span>{finding.status.replaceAll('_', ' ')}</span>
                <span>{finding.confidence}</span>
                <span className="row-actions">
                  <button type="button" onClick={() => queueSlackAlert(finding.id)}><Slack size={15} aria-hidden="true" />Queue</button>
                  <button className="secondary" type="button" onClick={() => createRemediationTask(finding.id)}><Plus size={15} aria-hidden="true" />Task</button>
                  <button className="secondary" type="button" onClick={() => setActiveFindingId(finding.id)}>Review</button>
                </span>
              </div>
            ))}
          </div>
        </section>

        {activeFinding && (
          <section className="panel finding-activity" aria-label="Finding activity">
            <div className="panel-header">
              <div><p className="eyebrow">Finding activity</p><h2>{activeFinding.title}</h2></div>
              <mark className={activeFinding.severity}>{activeFinding.severity}</mark>
            </div>
            <div className="activity-layout">
              <div className="activity-summary">
                <span>{activeAssetById.get(activeFinding.asset_id)?.domain}</span>
                <strong>{activeFinding.status.replaceAll('_', ' ')}</strong>
                <small>{activeFinding.remediation}</small>
                <div className="status-actions">
                  <button className="secondary" type="button" onClick={() => updateFindingStatus('in_progress')}>In progress</button>
                  <button className="secondary" type="button" onClick={() => updateFindingStatus('accepted_risk')}>Accepted risk</button>
                  <button className="secondary" type="button" onClick={() => updateFindingStatus('false_positive')}>False positive</button>
                </div>
              </div>
              <form className="note-form" onSubmit={addFindingNote}>
                <label htmlFor="finding-note">Activity note</label>
                <textarea id="finding-note" value={noteDraft} onChange={(event) => setNoteDraft(event.target.value)} />
                <button disabled={noteDraft.trim().length < 3} type="submit"><Plus size={18} aria-hidden="true" />Add note</button>
              </form>
              <div className="activity-feed">
                {findingEvents.map((event) => (
                  <div className="activity-event" key={event.id}>
                    <span className="job-id">{shortId(event.id)}</span>
                    <strong>{event.event_type.replaceAll('_', ' ')}</strong>
                    <p>{event.note}</p>
                    <small>{formatTime(event.created_at)}</small>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        <section className="ops-grid">
          <article className="panel alert-queue" aria-label="Alert queue">
            <div className="panel-header compact"><div><p className="eyebrow">Slack queue</p><h2>Alert dispatch</h2></div></div>
            <div className="compact-list">
              {workspace.alerts.map((alert) => (
                <div className="compact-row" key={alert.id}>
                  <span className="job-id">{shortId(alert.id)}</span>
                  <span><strong>{workspace.findings.find((finding) => finding.id === alert.finding_id)?.title ?? alert.finding_id}</strong><small>{alert.payload}</small></span>
                  <mark className={alert.status}>{alert.status}</mark>
                </div>
              ))}
            </div>
          </article>

          <article className="panel remediation-queue" aria-label="Remediation queue">
            <div className="panel-header compact"><div><p className="eyebrow">Remediation</p><h2>Workflow board</h2></div></div>
            <div className="compact-list">
              {workspace.remediationTasks.map((task) => (
                <div className="compact-row remediation-row" key={task.id}>
                  <span className="job-id">{shortId(task.id)}</span>
                  <span><strong>{task.title}</strong><small>{task.status.replaceAll('_', ' ')}</small></span>
                  <button className="secondary" type="button" onClick={() => updateTaskStatus(task.id, 'remediated')}>Close</button>
                </div>
              ))}
            </div>
          </article>
        </section>

        <section className="panel finding-activity" id="team">
          <div className="panel-header">
            <div><p className="eyebrow">Organization</p><h2>Team and audit trail</h2></div>
            <UserPlus size={22} aria-hidden="true" />
          </div>
          <div className="activity-layout">
            <form className="note-form" onSubmit={inviteUser}>
              <label>Invite email</label>
              <input value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} />
              <button disabled={!inviteEmail} type="submit"><UserPlus size={18} aria-hidden="true" />Invite member</button>
            </form>
            <div className="activity-feed">
              {workspace.members.map((member) => (
                <div className="activity-event" key={member.user.id}>
                  <strong>{member.user.display_name}</strong>
                  <p>{member.user.email}</p>
                  <small>{member.role}</small>
                </div>
              ))}
            </div>
            <div className="activity-feed">
              {workspace.auditLogs.slice(0, 6).map((log) => (
                <div className="activity-event" key={log.id}>
                  <strong>{log.action.replaceAll('.', ' ')}</strong>
                  <p>{log.target_type}</p>
                  <small>{formatTime(log.created_at)}</small>
                </div>
              ))}
            </div>
          </div>
        </section>
      </section>
    </main>
  )
}

function loadStoredSession(): SessionState | null {
  const stored = localStorage.getItem(sessionStorageKey)
  if (!stored) {
    return null
  }
  try {
    return JSON.parse(stored) as SessionState
  } catch {
    localStorage.removeItem(sessionStorageKey)
    return null
  }
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong'
}

function formatTime(value: string) {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function shortId(value: string) {
  return value.slice(0, 8)
}

function evidenceDomain(evidence: ScanEvidence) {
  return evidence.data.domain
}

function evidenceSummary(evidence: ScanEvidence) {
  if (evidence.kind === 'dns_baseline') {
    return evidence.data.addresses.map((address) => <code key={address.value}>{address.value}</code>)
  }
  if (evidence.kind === 'dns_policy') {
    return (
      <>
        <code>SPF {evidence.data.spf_record ? 'present' : 'missing'}</code>
        <code>DMARC {evidence.data.dmarc_record ? 'present' : 'missing'}</code>
      </>
    )
  }
  return (
    <>
      <code>{evidence.data.status_code ?? 'error'}</code>
      <code>{evidence.data.final_url ?? evidence.data.error ?? 'no final URL'}</code>
    </>
  )
}

export default App
