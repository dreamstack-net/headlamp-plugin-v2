export interface Rules {
  apiVersion?: string;
  kind?: string;
  metadata?: {
    name?: string;
    namespace?: string;
  };
  spec: RulesSpec;
}

export interface RulesSpec {
  rules: Rule[];
}

export interface Rule {
  name: string;
  id: string;
  enabled: boolean;
  description: string;
  expressions: RuleExpressions;
  profileDependency: ProfileDependency;
  severity: number;
  supportPolicy: boolean;
  isTriggerAlert: boolean;
  mitreTactic: string;
  mitreTechnique: string;
  tags?: string[];
}

export interface RuleExpressions {
  message: string;
  uniqueId: string;
  ruleExpression: RuleExpression[];
}

export interface RuleExpression {
  eventType: EventType;
  expression: string;
}

// the event types of the node-agent, the alias dnsQuery under which it evaluates DNS queries and
// error responses, and k8s-admission, the requests of the admission webhook of the operator
export type EventType =
  | 'exec'
  | 'open'
  | 'syscall'
  | 'capabilities'
  | 'dns'
  | 'dnsQuery'
  | 'network'
  | 'bpf'
  | 'kmod'
  | 'ssh'
  | 'symlink'
  | 'hardlink'
  | 'ptrace'
  | 'randomx'
  | 'unshare'
  | 'iouring'
  | 'http'
  | 'fork'
  | 'exit'
  | 'procfs'
  | 'k8s-admission';

// 0 = Required (rule always needs a profile), 1 = Optional, 2 = NotRequired
export type ProfileDependency = 0 | 1 | 2;

// --- CEL evaluation result types (mirror go/rules/Evaluator.go) ---

export interface RuleExprResult {
  eventType: string;
  expression: string;
  result: boolean | null;
  error?: string;
  // the error is of the expression itself, which does not compile for any event, rather than
  // of evaluating it against this event
  compileError?: boolean;
}

export interface StringExprResult {
  result: string;
  error?: string;
  // as in RuleExprResult
  compileError?: boolean;
}

export interface RuleEvalResults {
  error?: string;
  eventTypeMismatch?: string;
  ruleExpression: RuleExprResult[];
  // whether the rule alerts: every expression of the event type is true; the message and the
  // unique id are only evaluated then
  fired?: boolean;
  // why the node-agent skips the event before evaluating the rule: the prefilter of the rule's
  // state excludes it, so the rule does not fire
  prefiltered?: string;
  message: StringExprResult;
  uniqueId: StringExprResult;
}

// --- Mock data types for the playground (mirror go/rules/Libraries.go) ---

export interface MockProfile {
  containers: Record<string, MockContainer>;
}

export interface MockContainer {
  execs?: Array<{ path: string; args?: string[] }>;
  opens?: Array<{ path: string; flags?: string[] }>;
  syscalls?: string[];
  capabilities?: string[];
  endpoints?: Array<{ endpoint: string; methods?: string[] }>;
}

export interface MockNetwork {
  containers: Record<string, MockNetworkContainer>;
}

// a network neighbor, with the fields of a profile's; dns may also be a list of names
export interface MockNetworkEntry {
  ipAddress?: string;
  ipAddresses?: string[];
  dns?: string | string[];
  dnsNames?: string[];
}

export interface MockNetworkContainer {
  egress?: MockNetworkEntry[];
  ingress?: MockNetworkEntry[];
}

// the Kubernetes mock of the k8s.* functions: the API server address and pods with the fields
// of Pod objects
export interface MockK8s {
  apiServerAddress?: string;
  pods?: Array<{
    metadata: { namespace: string; name: string };
    spec: {
      containers?: MockPodContainer[];
      initContainers?: MockPodContainer[];
      ephemeralContainers?: MockPodContainer[];
    };
  }>;
}

export interface MockPodContainer {
  name: string;
  // the command and the exec commands of the hooks count as executed for cp.was_executed
  command?: string[];
  lifecycle?: {
    preStop?: { exec?: { command?: string[] } };
    postStart?: { exec?: { command?: string[] } };
  };
  volumeMounts?: Array<{ mountPath: string }>;
}

// Default event data templates for each event type, used to pre-populate the editor.
export const defaultEventData: Record<EventType, object> = {
  exec: {
    comm: 'bash',
    pid: 1234,
    exepath: '/bin/bash',
    cwd: '/',
    args: ['/bin/bash'],
    upperlayer: false,
    pupperlayer: false,
    pcomm: 'containerd-shim',
    containerId: 'abc123',
    containerName: 'my-container',
    namespace: 'default',
    podName: 'my-pod',
  },
  open: {
    comm: 'cat',
    pid: 1234,
    path: '/etc/shadow',
    flags: ['O_RDONLY'],
    flagsRaw: 0,
    containerId: 'abc123',
    containerName: 'my-container',
  },
  syscall: {
    comm: 'bash',
    pid: 1234,
    syscallName: 'ptrace',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  capabilities: {
    comm: 'bash',
    pid: 1234,
    capName: 'CAP_NET_ADMIN',
    syscallName: 'socket',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  // an answered response
  dns: {
    comm: 'curl',
    name: 'pool.supportxmr.com.',
    qr: 'R',
    qtype: 'A',
    numAnswers: 1,
    rcode: 'Success',
    containerName: 'my-container',
    containerId: 'abc123',
  },
  // a query, or an error response, which the node-agent forwards to the rules with
  // dnsRuleForwarding; rcode is only set on a response
  dnsQuery: {
    comm: 'curl',
    name: '6578666976652d6461746121.exfil.example.com.',
    qr: 'Q',
    qtype: 'TXT',
    numAnswers: 0,
    containerName: 'my-container',
    containerId: 'abc123',
  },
  network: {
    comm: 'curl',
    pktType: 'OUTGOING',
    dstAddr: '8.8.8.8',
    dstPort: 443,
    proto: 'TCP',
    dstIp: '8.8.8.8',
    containerName: 'my-container',
    containerId: 'abc123',
  },
  bpf: {
    comm: 'bpftool',
    cmd: 5,
    containerId: 'abc123',
    containerName: 'my-container',
  },
  kmod: {
    comm: 'insmod',
    module: 'evil.ko',
    syscallName: 'init_module',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  ssh: {
    comm: 'ssh',
    srcPort: 45000,
    dstPort: 22,
    dstIp: '10.0.0.1',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  symlink: {
    comm: 'ln',
    oldPath: '/etc/shadow',
    newPath: '/tmp/shadow-link',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  hardlink: {
    comm: 'ln',
    oldPath: '/etc/shadow',
    newPath: '/tmp/shadow-hard',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  ptrace: {
    comm: 'strace',
    exepath: '/usr/bin/strace',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  randomx: {
    comm: 'xmrig',
    pid: 1234,
    exepath: '/tmp/xmrig',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  unshare: {
    comm: 'unshare',
    pcomm: 'bash',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  iouring: {
    comm: 'app',
    opcode: 1,
    flagsRaw: 0,
    containerId: 'abc123',
    containerName: 'my-container',
  },
  http: {
    comm: 'nginx',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  fork: {
    comm: 'bash',
    pid: 1234,
    containerId: 'abc123',
    containerName: 'my-container',
  },
  exit: {
    comm: 'bash',
    pid: 1234,
    containerId: 'abc123',
    containerName: 'my-container',
  },
  procfs: {
    comm: 'cat',
    pid: 1234,
    path: '/proc/1/mem',
    containerId: 'abc123',
    containerName: 'my-container',
  },
  // a request of the operator's admission webhook, with the fields of its AdmissionCelEvent;
  // Object, OldObject and Options are also the variables object, oldObject and options
  'k8s-admission': {
    Kind: 'Pod',
    Group: '',
    Version: 'v1',
    Resource: 'pods',
    Subresource: '',
    Name: 'my-pod',
    Namespace: 'default',
    Operation: 'CREATE',
    DryRun: false,
    UserInfo: { Username: 'jane', Groups: ['system:authenticated'], UID: '' },
    Object: {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: { name: 'my-pod', namespace: 'default' },
      spec: {
        hostNetwork: true,
        containers: [
          { name: 'my-container', image: 'nginx', securityContext: { privileged: true } },
        ],
        volumes: [{ name: 'host', hostPath: { path: '/var/run' } }],
      },
    },
  },
};
