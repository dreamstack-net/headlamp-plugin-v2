// The reference of the CEL functions the runtime rules can call.
import { Icon } from '@iconify/react';
import {
  Box,
  IconButton,
  Popover,
  Table,
  TableBody,
  TableCell,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { useState } from 'react';

const GROUP_DESCRIPTIONS: Record<string, string> = {
  cp: 'Container profile — the baseline of what a container normally executes, opens, calls and contacts. Use cp.* to detect activity that was not seen during the learning phase. The node-agent also accepts the older names, ap.* for the behaviour and nn.* for the network, which are deprecated. Paths match like the node-agent: ⋯ is one segment, * zero or more, and a trailing slash is ignored.',
  k8s: 'Kubernetes metadata helpers — the API server address and the containers of a pod, from the Kubernetes mock in the playground.',
  parse: 'Parsing utilities for extracting values from event fields.',
  net: 'Network utilities for classifying IP addresses.',
  process: 'Process-level helpers (return empty values in the browser playground).',
};

export interface LibraryFunction {
  group: string;
  signature: string;
  description: string;
  // the deprecated name the node-agent also accepts
  alias?: string;
}

export const LIBRARY_FUNCTIONS: LibraryFunction[] = [
  {
    group: 'cp',
    signature: 'cp.was_executed(containerId, path) bool',
    alias: 'ap.was_executed',
    description:
      "Path was executed by the container in the baseline. For a container with a profile, the command and the exec commands of the lifecycle hooks of its pod spec (in the playground: the Kubernetes mock's pod of the event) also count",
  },
  {
    group: 'cp',
    signature: 'cp.was_executed_with_args(containerId, path, args) bool',
    alias: 'ap.was_executed_with_args',
    description:
      'Path was executed with these arguments (argv[0] included, compared by its base name); ⋯ is one argument, ⋯⋯ zero or more, and * is literal. Arguments the profile or the event lacks match',
  },
  {
    group: 'cp',
    signature: 'cp.was_path_opened(containerId, path) bool',
    alias: 'ap.was_path_opened',
    description: 'Path was opened by the container in the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.was_path_opened_with_flags(containerId, path, flags) bool',
    alias: 'ap.was_path_opened_with_flags',
    description: 'Path was opened; the node-agent does not compare the flags yet',
  },
  {
    group: 'cp',
    signature: 'cp.was_path_opened_with_suffix(containerId, suffix) bool',
    alias: 'ap.was_path_opened_with_suffix',
    description: 'Any opened path ends with suffix',
  },
  {
    group: 'cp',
    signature: 'cp.was_path_opened_with_prefix(containerId, prefix) bool',
    alias: 'ap.was_path_opened_with_prefix',
    description: 'Any opened path starts with prefix',
  },
  {
    group: 'cp',
    signature: 'cp.was_syscall_used(containerId, syscallName) bool',
    alias: 'ap.was_syscall_used',
    description: 'Syscall was used by the container in the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.was_capability_used(containerId, capName) bool',
    alias: 'ap.was_capability_used',
    description: 'Capability was used by the container in the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.was_endpoint_accessed(containerId, endpoint) bool',
    alias: 'ap.was_endpoint_accessed',
    description: 'HTTP endpoint is in the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.was_endpoint_accessed_with_method(containerId, endpoint, method) bool',
    alias: 'ap.was_endpoint_accessed_with_method',
    description: 'HTTP endpoint is in the baseline; the node-agent does not compare the method yet',
  },
  {
    group: 'cp',
    signature: 'cp.was_endpoint_accessed_with_methods(containerId, endpoint, methods) bool',
    alias: 'ap.was_endpoint_accessed_with_methods',
    description:
      'HTTP endpoint is in the baseline; the node-agent does not compare the methods yet',
  },
  {
    group: 'cp',
    signature: 'cp.was_endpoint_accessed_with_prefix(containerId, prefix) bool',
    alias: 'ap.was_endpoint_accessed_with_prefix',
    description: 'Any HTTP endpoint starts with prefix',
  },
  {
    group: 'cp',
    signature: 'cp.was_endpoint_accessed_with_suffix(containerId, suffix) bool',
    alias: 'ap.was_endpoint_accessed_with_suffix',
    description: 'Any HTTP endpoint ends with suffix',
  },
  {
    group: 'cp',
    signature: 'cp.was_host_accessed(containerId, host) bool',
    alias: 'ap.was_host_accessed',
    description: 'An HTTP endpoint of the baseline is on this host (or host:port)',
  },
  {
    group: 'cp',
    signature: 'cp.was_address_in_egress(containerId, address) bool',
    alias: 'nn.was_address_in_egress',
    description:
      'Address was contacted in the baseline; addresses are compared in their canonical form, and the baseline may hold CIDRs and *',
  },
  {
    group: 'cp',
    signature: 'cp.was_address_in_ingress(containerId, address) bool',
    alias: 'nn.was_address_in_ingress',
    description: 'Address contacted the container in the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.is_domain_in_egress(containerId, domain) bool',
    alias: 'nn.is_domain_in_egress',
    description:
      'Domain was looked up in the baseline, with or without the trailing dot; the baseline may hold *.example.com',
  },
  {
    group: 'cp',
    signature: 'cp.is_domain_in_ingress(containerId, domain) bool',
    alias: 'nn.is_domain_in_ingress',
    description: 'Domain is among the ingress peers of the baseline',
  },
  {
    group: 'cp',
    signature: 'cp.was_address_port_protocol_in_egress(containerId, address, port, protocol) bool',
    alias: 'nn.was_address_port_protocol_in_egress',
    description: 'Address is in the egress baseline; the node-agent does not compare the port yet',
  },
  {
    group: 'cp',
    signature: 'cp.was_address_port_protocol_in_ingress(containerId, address, port, protocol) bool',
    alias: 'nn.was_address_port_protocol_in_ingress',
    description: 'Address is in the ingress baseline; the node-agent does not compare the port yet',
  },
  {
    group: 'k8s',
    signature: 'k8s.is_api_server_address(addr) bool',
    description: 'Address matches the cluster API server',
  },
  {
    group: 'k8s',
    signature: 'k8s.get_container_mount_paths(ns, pod, container) list',
    description:
      'Returns the mount paths for a container; the node-agent fails the rule for a pod it does not know, the playground returns none',
  },
  {
    group: 'k8s',
    signature: 'k8s.get_container_by_name(ns, pod, container) bool',
    description: 'The pod has a container, init container or ephemeral container of this name',
  },
  {
    group: 'parse',
    signature: 'parse.get_exec_path(args, comm) string',
    description: 'Returns args[0] if non-empty, otherwise comm',
  },
  {
    group: 'parse',
    signature: 'parse.get_exec_path(args, comm, exepath) string',
    description:
      'Returns exepath if non-empty, as the profile records it; otherwise args[0], then comm',
  },
  {
    group: 'net',
    signature: 'net.is_private_ip(ip) bool',
    description:
      'True if the IP is loopback, link-local, private (RFC 1918, IPv6 unique local), in 100.64.0.0/10, or IPv4 from 224.0.0.0 (multicast, reserved)',
  },
  {
    group: 'process',
    signature: 'process.get_ld_hook_var(pid) string',
    description:
      'Returns the LD_PRELOAD hook variable (empty in playground). Takes the unsigned pid of the event: event.pid',
  },
  {
    group: 'process',
    signature: 'process.get_process_env(pid) map',
    description:
      'Returns the environment of the process (empty in playground, as for a process that exited). Takes an integer: int(event.pid)',
  },
];

export function LibraryReferenceButton() {
  const [anchor, setAnchor] = useState<HTMLButtonElement | null>(null);
  const groups = [...new Set(LIBRARY_FUNCTIONS.map(f => f.group))];

  return (
    <>
      <Tooltip title="CEL function reference">
        <IconButton size="small" onClick={e => setAnchor(e.currentTarget)}>
          <Icon icon="mdi:information-outline" />
        </IconButton>
      </Tooltip>
      <Popover
        open={!!anchor}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ p: 2, width: '60vw', maxWidth: 900, maxHeight: '70vh', overflow: 'auto' }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Available CEL functions
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            Rules of the event type k8s-admission are evaluated by the operator, which has none of
            these functions, but the variables object, oldObject and options of the request.
          </Typography>
          <Table size="small">
            <TableBody>
              {groups.flatMap(group => [
                <TableRow key={`hdr-${group}`}>
                  <TableCell colSpan={2} sx={{ pt: 1.5, pb: 0.25, borderBottom: 0 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>
                      {group}.*
                    </Typography>
                    {GROUP_DESCRIPTIONS[group] && (
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: 'block' }}
                      >
                        {GROUP_DESCRIPTIONS[group]}
                      </Typography>
                    )}
                  </TableCell>
                </TableRow>,
                ...LIBRARY_FUNCTIONS.filter(f => f.group === group).map(f => (
                  <TableRow key={f.signature}>
                    <TableCell
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.72rem',
                        verticalAlign: 'top',
                        py: 0.5,
                        borderBottom: 0,
                      }}
                    >
                      {f.signature}
                      {f.alias && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: 'block', fontFamily: 'monospace', fontSize: '0.68rem' }}
                        >
                          also {f.alias} (deprecated)
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell
                      sx={{
                        fontSize: '0.75rem',
                        color: 'text.secondary',
                        verticalAlign: 'top',
                        py: 0.5,
                        borderBottom: 0,
                      }}
                    >
                      {f.description}
                    </TableCell>
                  </TableRow>
                )),
              ])}
            </TableBody>
          </Table>
        </Box>
      </Popover>
    </>
  );
}
