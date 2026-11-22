// The defaults of the rule editor: the event types, MITRE ATT&CK ids, an empty rule and the
// empty mock data of the test dialog.

import { defaultEventData, EventType, Rule } from '../types/Rules';

export const EVENT_TYPES = Object.keys(defaultEventData) as EventType[];

// the namespace the chart installs Kubescape to by default, until the namespace of the cluster is
// found (useKubescapeNamespace)
export const DEFAULT_NAMESPACE = 'kubescape';

export const MITRE_TACTICS: { id: string; name: string }[] = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0040', name: 'Impact' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0043', name: 'Reconnaissance' },
];

export const MITRE_TECHNIQUES: { id: string; name: string }[] = [
  { id: 'T1005', name: 'Data from Local System' },
  { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol' },
  { id: 'T1036', name: 'Masquerading' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
  { id: 'T1055', name: 'Process Injection' },
  { id: 'T1059', name: 'Command and Scripting Interpreter' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
  { id: 'T1071', name: 'Application Layer Protocol' },
  { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
  { id: 'T1078', name: 'Valid Accounts' },
  { id: 'T1098', name: 'Account Manipulation' },
  { id: 'T1190', name: 'Exploit Public-Facing Application' },
  { id: 'T1210', name: 'Exploitation of Remote Services' },
  { id: 'T1218', name: 'System Binary Proxy Execution' },
  { id: 'T1496', name: 'Resource Hijacking' },
  { id: 'T1525', name: 'Implant Internal Image' },
  { id: 'T1528', name: 'Steal Application Access Token' },
  { id: 'T1543', name: 'Create or Modify System Process' },
  { id: 'T1547.006', name: 'Boot or Logon Autostart: Kernel Modules and Extensions' },
  { id: 'T1552.001', name: 'Unsecured Credentials: Credentials In Files' },
  { id: 'T1574.006', name: 'Hijack Execution Flow: Dynamic Linker Hijacking' },
  { id: 'T1609', name: 'Container Administration Command' },
  { id: 'T1610', name: 'Deploy Container' },
  { id: 'T1611', name: 'Escape to Host' },
  { id: 'T1613', name: 'Container and Resource Discovery' },
  { id: 'T1622', name: 'Debugger Evasion' },
];

export const EMPTY_RULE: Rule = {
  name: '',
  id: '',
  enabled: true,
  description: '',
  expressions: {
    message: '',
    uniqueId: '',
    ruleExpression: [{ eventType: 'exec', expression: '' }],
  },
  profileDependency: 2,
  severity: 5,
  supportPolicy: false,
  isTriggerAlert: true,
  mitreTactic: '',
  mitreTechnique: '',
  tags: [],
};

export const EMPTY_PROFILE_YAML = `# ApplicationProfile mock data (keyed by containerId)
# Paths match like the node-agent's: ⋯ is one segment, * zero or more
# containers:
#   abc123:
#     execs:
#       - path: /bin/bash
#         args: [/bin/bash, -c, ⋯]
#     opens:
#       - path: /etc/ssl/*
#     syscalls:
#       - read
#     capabilities:
#       - CAP_NET_BIND_SERVICE
#     endpoints:
#       - endpoint: ":8080/api/⋯/orders"
`;

export const EMPTY_NETWORK_YAML = `# NetworkNeighborhood mock data (keyed by containerId)
# Addresses may be CIDRs or *, domains *.example.com
# containers:
#   abc123:
#     egress:
#       - ipAddress: "8.8.8.8"
#         dns:
#           - "dns.google."
#       - ipAddresses: ["10.0.0.0/8"]
#         dnsNames: ["*.svc.cluster.local."]
`;

export const EMPTY_K8S_YAML = `# Kubernetes mock data of the k8s.* functions
# apiServerAddress: "10.96.0.1"
# pods:
#   - metadata:
#       namespace: default
#       name: my-pod
#     spec:
#       containers:
#         - name: my-container
#           command: ["/app/server"]
#           lifecycle:
#             preStop:
#               exec:
#                 command: ["/app/drain"]
#           volumeMounts:
#             - mountPath: /data
`;
