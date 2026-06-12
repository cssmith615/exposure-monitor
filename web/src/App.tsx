import { type FormEvent, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bell,
  Building2,
  ChevronRight,
  CheckCircle2,
  Clock3,
  Fingerprint,
  Globe2,
  Plus,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Slack,
  Sparkles,
  TerminalSquare,
} from 'lucide-react'
import './App.css'

type FindingStatus = 'Open' | 'In progress' | 'Accepted risk' | 'False positive' | 'Remediated'

type DemoFinding = {
  asset: string
  title: string
  severity: string
  status: FindingStatus
  owner: string
}

type FindingEvent = {
  id: string
  finding: string
  eventType: string
  note: string
  actor: string
  time: string
}

const initialFindings: DemoFinding[] = [
  {
    asset: 'api.example.com',
    title: 'TLS certificate expires soon',
    severity: 'High',
    status: 'Open',
    owner: 'Platform',
  },
  {
    asset: 'example.com',
    title: 'DMARC policy is not published',
    severity: 'Medium',
    status: 'In progress',
    owner: 'IT',
  },
  {
    asset: 'app.example.com',
    title: 'HSTS header is missing',
    severity: 'Low',
    status: 'Accepted risk',
    owner: 'Security',
  },
] 

const initialFindingEvents: FindingEvent[] = [
  {
    id: 'event-5001',
    finding: 'TLS certificate expires soon',
    eventType: 'status_changed_to_in_progress',
    note: 'Platform owns the certificate rotation before the next production deploy.',
    actor: 'Maya Chen',
    time: '09:52',
  },
  {
    id: 'event-5000',
    finding: 'DMARC policy is not published',
    eventType: 'note_added',
    note: 'Waiting on IT to confirm DNS provider ownership before publishing enforcement.',
    actor: 'Chris Smith',
    time: '09:46',
  },
]

const initialAlerts = [
  {
    id: 'alert-3001',
    channel: '#security-alerts',
    finding: 'TLS certificate expires soon',
    status: 'queued',
  },
]

const initialRemediationTasks = [
  {
    id: 'task-4001',
    finding: 'TLS certificate expires soon',
    title: 'Renew api.example.com TLS certificate',
    owner: 'Platform',
    status: 'in progress',
  },
]

const scanEvents = [
  { time: '09:42', event: 'DNS baseline refreshed', state: 'stable' },
  { time: '09:44', event: 'api.example.com certificate threshold crossed', state: 'alert' },
  { time: '09:51', event: 'Slack alert queued for Platform', state: 'queued' },
]

const initialScanJobs = [
  {
    id: 'scan-1007',
    target: 'api.example.com',
    status: 'queued',
    requested: '09:58',
    reason: 'Certificate renewal verification',
  },
  {
    id: 'scan-1006',
    target: 'example.com',
    status: 'completed',
    requested: '09:42',
    reason: 'Scheduled DNS and header baseline',
  },
]

const initialEvidence = [
  {
    id: 'dns-2004',
    target: 'example.com',
    source: 'dns_baseline',
    observed: '09:42',
    addresses: ['93.184.216.34'],
  },
  {
    id: 'dns-2003',
    target: 'api.example.com',
    source: 'dns_baseline',
    observed: '09:40',
    addresses: ['203.0.113.42', '2001:db8::42'],
  },
]

const demoAddressBook: Record<string, string[]> = {
  'example.com': ['93.184.216.34'],
  'api.example.com': ['203.0.113.42', '2001:db8::42'],
  'careers.example.com': ['198.51.100.12'],
}

function App() {
  const [domainInput, setDomainInput] = useState('billing.example.com')
  const [attested, setAttested] = useState(true)
  const [queuedDomains, setQueuedDomains] = useState([
    'example.com',
    'api.example.com',
    'careers.example.com',
  ])
  const [scanJobs, setScanJobs] = useState(initialScanJobs)
  const [evidenceItems, setEvidenceItems] = useState(initialEvidence)
  const [findings, setFindings] = useState(initialFindings)
  const [alerts, setAlerts] = useState(initialAlerts)
  const [remediationTasks, setRemediationTasks] = useState(initialRemediationTasks)
  const [activeFindingTitle, setActiveFindingTitle] = useState(initialFindings[0].title)
  const [findingEvents, setFindingEvents] = useState(initialFindingEvents)
  const [noteDraft, setNoteDraft] = useState(
    'Accepted through launch week; revisit after certificate automation lands.',
  )

  const normalizedDomain = useMemo(
    () => domainInput.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase(),
    [domainInput],
  )

  const canQueueDomain =
    attested &&
    normalizedDomain.includes('.') &&
    !queuedDomains.includes(normalizedDomain)

  const activeFinding = findings.find((finding) => finding.title === activeFindingTitle) ?? findings[0]
  const activeFindingEvents = findingEvents.filter(
    (event) => event.finding === activeFinding.title,
  )

  function queueDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!canQueueDomain) {
      return
    }

    setQueuedDomains((domains) => [...domains, normalizedDomain])
    setDomainInput('')
  }

  function queueAuthorizedScan(target = queuedDomains[0]) {
    const timestamp = new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    })

    setScanJobs((jobs) => [
      {
        id: `scan-${1008 + jobs.length}`,
        target,
        status: 'queued',
        requested: timestamp,
        reason: 'Manual authorized scan',
      },
      ...jobs,
    ])
    setEvidenceItems((items) => [
      {
        id: `dns-${2005 + items.length}`,
        target,
        source: 'dns_baseline',
        observed: timestamp,
        addresses: demoAddressBook[target] ?? ['Pending resolver capture'],
      },
      ...items,
    ])
  }

  function queueSlackAlert(finding: (typeof initialFindings)[number]) {
    setAlerts((currentAlerts) => [
      {
        id: `alert-${3002 + currentAlerts.length}`,
        channel: '#security-alerts',
        finding: finding.title,
        status: 'queued',
      },
      ...currentAlerts,
    ])
  }

  function createRemediationTask(finding: (typeof initialFindings)[number]) {
    setRemediationTasks((tasks) => [
      {
        id: `task-${4002 + tasks.length}`,
        finding: finding.title,
        title: `Remediate: ${finding.title}`,
        owner: finding.owner,
        status: 'open',
      },
      ...tasks,
    ])
    setFindings((currentFindings) =>
      currentFindings.map((currentFinding) =>
        currentFinding.title === finding.title
          ? { ...currentFinding, status: 'In progress' }
          : currentFinding,
      ),
    )
  }

  function markTaskRemediated(taskId: string) {
    const task = remediationTasks.find((candidate) => candidate.id === taskId)

    setRemediationTasks((tasks) =>
      tasks.map((candidate) =>
        candidate.id === taskId ? { ...candidate, status: 'remediated' } : candidate,
      ),
    )

    if (!task) {
      return
    }

    setFindings((currentFindings) =>
      currentFindings.map((finding) =>
        finding.title === task.finding ? { ...finding, status: 'Remediated' } : finding,
      ),
    )
  }

  function appendFindingEvent(finding: DemoFinding, eventType: string, note: string) {
    const timestamp = new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    })

    setFindingEvents((events) => [
      {
        id: `event-${5002 + events.length}`,
        finding: finding.title,
        eventType,
        note,
        actor: 'Chris Smith',
        time: timestamp,
      },
      ...events,
    ])
  }

  function updateFindingStatus(status: FindingStatus, note: string) {
    setFindings((currentFindings) =>
      currentFindings.map((finding) =>
        finding.title === activeFinding.title ? { ...finding, status } : finding,
      ),
    )
    appendFindingEvent(activeFinding, `status_changed_to_${status.toLowerCase().replaceAll(' ', '_')}`, note)
  }

  function addFindingNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const note = noteDraft.trim()

    if (note.length < 3) {
      return
    }

    appendFindingEvent(activeFinding, 'note_added', note)
    setNoteDraft('')
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
          <a className="active" href="#overview">
            <Activity size={18} aria-hidden="true" />
            Overview
          </a>
          <a href="#assets">
            <Globe2 size={18} aria-hidden="true" />
            Domains
          </a>
          <a href="#findings">
            <AlertTriangle size={18} aria-hidden="true" />
            Findings
          </a>
          <a href="#alerts">
            <Slack size={18} aria-hidden="true" />
            Slack alerts
          </a>
          <a href="#team">
            <Building2 size={18} aria-hidden="true" />
            Team
          </a>
        </nav>

        <div className="authorization-note">
          <LockKeyhole size={18} aria-hidden="true" />
          <span>Authorization gate enabled</span>
        </div>
      </aside>

      <section className="workspace" id="overview">
        <header className="topbar">
          <div>
            <p className="eyebrow">Acme Startup / production perimeter</p>
            <h1>Exposure command</h1>
          </div>
          <button type="button">
            <Bell size={18} aria-hidden="true" />
            Test Slack alert
          </button>
        </header>

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
            <h2>12 domains watched. 1 high-priority remediation open.</h2>
            <div className="stage-actions">
              <button type="button" onClick={() => queueAuthorizedScan(queuedDomains[0])}>
                <Radar size={18} aria-hidden="true" />
                Run authorized scan
              </button>
              <button className="secondary" type="button">
                <TerminalSquare size={18} aria-hidden="true" />
                Review evidence
              </button>
            </div>
          </div>
          <div className="stage-feed" aria-label="Scan event stream">
            {scanEvents.map((item) => (
              <div className={`feed-item ${item.state}`} key={`${item.time}-${item.event}`}>
                <span>{item.time}</span>
                <strong>{item.event}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="metrics" aria-label="Exposure metrics">
          <article>
            <span>Domains</span>
            <strong>12</strong>
            <small>10 monitored / 2 pending</small>
          </article>
          <article>
            <span>Open findings</span>
            <strong>7</strong>
            <small>1 high, 3 medium, 3 low</small>
          </article>
          <article>
            <span>Last scan</span>
            <strong>18m</strong>
            <small>DNS, TLS, HTTP checks</small>
          </article>
          <article>
            <span>Slack alerts</span>
            <strong>On</strong>
            <small>High and critical only</small>
          </article>
        </section>

        <section className="content-grid">
          <article className="panel intake-console" id="domain-intake">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Domain intake</p>
                <h2>Authorization gate</h2>
              </div>
              <Fingerprint size={22} aria-hidden="true" />
            </div>

            <form className="domain-form" onSubmit={queueDomain}>
              <label htmlFor="domain">Domain</label>
              <div className="domain-control">
                <Globe2 size={18} aria-hidden="true" />
                <input
                  id="domain"
                  name="domain"
                  onChange={(event) => setDomainInput(event.target.value)}
                  placeholder="security.example.com"
                  type="text"
                  value={domainInput}
                />
              </div>

              <label className="attestation-control">
                <input
                  checked={attested}
                  onChange={(event) => setAttested(event.target.checked)}
                  type="checkbox"
                />
                <span>I am authorized to monitor this domain.</span>
              </label>

              <button disabled={!canQueueDomain} type="submit">
                <Plus size={18} aria-hidden="true" />
                Queue domain
              </button>
            </form>
          </article>

          <article className="panel exposure-map" id="assets">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Authorized domains</p>
                <h2>Scan posture</h2>
              </div>
              <button type="button">
                <Globe2 size={18} aria-hidden="true" />
                Add domain
              </button>
            </div>
            <div className="scan-row">
              <CheckCircle2 size={18} aria-hidden="true" />
              <span>
                <strong>{queuedDomains[0]}</strong>
                <small>Headers and DNS aligned</small>
              </span>
              <strong>Clean</strong>
            </div>
            <div className="scan-row warning">
              <AlertTriangle size={18} aria-hidden="true" />
              <span>
                <strong>{queuedDomains[1]}</strong>
                <small>TLS renewal window breached</small>
              </span>
              <strong>1 high</strong>
            </div>
            <div className="scan-row">
              <Clock3 size={18} aria-hidden="true" />
              <span>
                <strong>{queuedDomains[2] ?? queuedDomains.at(-1)}</strong>
                <small>Queued for passive refresh</small>
              </span>
              <strong>Queued</strong>
            </div>
            {queuedDomains.slice(3).map((domain) => (
              <div className="scan-row queued" key={domain}>
                <Clock3 size={18} aria-hidden="true" />
                <span>
                  <strong>{domain}</strong>
                  <small>Awaiting first evidence capture</small>
                </span>
                <strong>New</strong>
              </div>
            ))}
          </article>

          <article className="panel" id="alerts">
            <div className="panel-header compact">
              <div>
                <p className="eyebrow">Slack</p>
                <h2>Alert policy</h2>
              </div>
            </div>
            <dl className="policy-list">
              <div>
                <dt>Channel</dt>
                <dd>#security-alerts</dd>
              </div>
              <div>
                <dt>Threshold</dt>
                <dd>High and critical</dd>
              </div>
              <div>
                <dt>Delivery</dt>
                <dd>Webhook secret reference</dd>
              </div>
              <div>
                <dt>Noise budget</dt>
                <dd>One alert per finding transition</dd>
              </div>
            </dl>
          </article>
        </section>

        <section className="panel scan-queue" aria-label="Scan queue">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Manual scan orchestration</p>
              <h2>Scan jobs</h2>
            </div>
            <button type="button" onClick={() => queueAuthorizedScan(queuedDomains[1])}>
              <Radar size={18} aria-hidden="true" />
              Trigger scan
            </button>
          </div>

          <div className="job-list">
            {scanJobs.map((job) => (
              <div className={`job-row ${job.status}`} key={job.id}>
                <span className="job-id">{job.id}</span>
                <span>
                  <strong>{job.target}</strong>
                  <small>{job.reason}</small>
                </span>
                <span>{job.requested}</span>
                <mark className={job.status}>{job.status}</mark>
              </div>
            ))}
          </div>
        </section>

        <section className="panel evidence-vault" aria-label="Scan evidence">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Evidence vault</p>
              <h2>DNS baselines</h2>
            </div>
            <TerminalSquare size={22} aria-hidden="true" />
          </div>

          <div className="evidence-list">
            {evidenceItems.map((item) => (
              <div className="evidence-row" key={item.id}>
                <span className="job-id">{item.id}</span>
                <span>
                  <strong>{item.target}</strong>
                  <small>{item.source}</small>
                </span>
                <span className="address-stack">
                  {item.addresses.map((address) => (
                    <code key={`${item.id}-${address}`}>{address}</code>
                  ))}
                </span>
                <span>{item.observed}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel findings" id="findings">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Remediation workflow</p>
              <h2>Current findings</h2>
            </div>
            <button type="button">
              <Sparkles size={18} aria-hidden="true" />
              Triage queue
            </button>
          </div>

          <div className="finding-table">
            <div className="table-head">
              <span>Asset</span>
              <span>Finding</span>
              <span>Severity</span>
              <span>Status</span>
              <span>Owner</span>
              <span>Actions</span>
            </div>
            {findings.map((finding) => (
              <div className="table-row" key={`${finding.asset}-${finding.title}`}>
                <span>{finding.asset}</span>
                <span>{finding.title}</span>
                <span>
                  <mark className={finding.severity.toLowerCase()}>
                    {finding.severity}
                  </mark>
                </span>
                <span>{finding.status}</span>
                <span className="owner-cell">
                  {finding.owner}
                  <ChevronRight size={16} aria-hidden="true" />
                </span>
                <span className="row-actions">
                  <button type="button" onClick={() => queueSlackAlert(finding)}>
                    <Slack size={15} aria-hidden="true" />
                    Queue
                  </button>
                  <button className="secondary" type="button" onClick={() => createRemediationTask(finding)}>
                    <Plus size={15} aria-hidden="true" />
                    Task
                  </button>
                  <button className="secondary" type="button" onClick={() => setActiveFindingTitle(finding.title)}>
                    <ChevronRight size={15} aria-hidden="true" />
                    Review
                  </button>
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel finding-activity" aria-label="Finding activity">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Finding activity</p>
              <h2>{activeFinding.title}</h2>
            </div>
            <mark className={activeFinding.severity.toLowerCase()}>{activeFinding.severity}</mark>
          </div>

          <div className="activity-layout">
            <div className="activity-summary">
              <span>{activeFinding.asset}</span>
              <strong>{activeFinding.status}</strong>
              <small>{activeFinding.owner} owner</small>
              <div className="status-actions">
                <button
                  className="secondary"
                  type="button"
                  onClick={() =>
                    updateFindingStatus(
                      'Accepted risk',
                      'Accepted as a time-boxed business risk with owner visibility.',
                    )
                  }
                >
                  Accepted risk
                </button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() =>
                    updateFindingStatus(
                      'False positive',
                      'Marked false positive after evidence review.',
                    )
                  }
                >
                  False positive
                </button>
              </div>
            </div>

            <form className="note-form" onSubmit={addFindingNote}>
              <label htmlFor="finding-note">Activity note</label>
              <textarea
                id="finding-note"
                onChange={(event) => setNoteDraft(event.target.value)}
                value={noteDraft}
              />
              <button disabled={noteDraft.trim().length < 3} type="submit">
                <Plus size={18} aria-hidden="true" />
                Add note
              </button>
            </form>

            <div className="activity-feed">
              {activeFindingEvents.map((event) => (
                <div className="activity-event" key={event.id}>
                  <span className="job-id">{event.id}</span>
                  <strong>{event.eventType.replaceAll('_', ' ')}</strong>
                  <p>{event.note}</p>
                  <small>
                    {event.actor} / {event.time}
                  </small>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="ops-grid">
          <article className="panel alert-queue" aria-label="Alert queue">
            <div className="panel-header compact">
              <div>
                <p className="eyebrow">Slack queue</p>
                <h2>Alert dispatch</h2>
              </div>
            </div>
            <div className="compact-list">
              {alerts.map((alert) => (
                <div className="compact-row" key={alert.id}>
                  <span className="job-id">{alert.id}</span>
                  <span>
                    <strong>{alert.finding}</strong>
                    <small>{alert.channel}</small>
                  </span>
                  <mark className={alert.status}>{alert.status}</mark>
                </div>
              ))}
            </div>
          </article>

          <article className="panel remediation-queue" aria-label="Remediation queue">
            <div className="panel-header compact">
              <div>
                <p className="eyebrow">Remediation</p>
                <h2>Workflow board</h2>
              </div>
            </div>
            <div className="compact-list">
              {remediationTasks.map((task) => (
                <div className="compact-row remediation-row" key={task.id}>
                  <span className="job-id">{task.id}</span>
                  <span>
                    <strong>{task.title}</strong>
                    <small>{task.owner}</small>
                  </span>
                  <button
                    className="secondary"
                    disabled={task.status === 'remediated'}
                    type="button"
                    onClick={() => markTaskRemediated(task.id)}
                  >
                    {task.status}
                  </button>
                </div>
              ))}
            </div>
          </article>
        </section>
      </section>
    </main>
  )
}

export default App
