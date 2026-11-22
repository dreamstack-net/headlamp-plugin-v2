package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// MockProfile is the user-supplied ApplicationProfile mock, keyed by containerId.
type MockProfile struct {
	Containers map[string]MockContainer `json:"containers" yaml:"containers"`
}

type MockContainer struct {
	Execs        []ExecCall     `json:"execs" yaml:"execs"`
	Opens        []OpenCall     `json:"opens" yaml:"opens"`
	Syscalls     []string       `json:"syscalls" yaml:"syscalls"`
	Capabilities []string       `json:"capabilities" yaml:"capabilities"`
	Endpoints    []HTTPEndpoint `json:"endpoints" yaml:"endpoints"`
}

type ExecCall struct {
	Path string   `json:"path" yaml:"path"`
	Args []string `json:"args" yaml:"args"`
}

type OpenCall struct {
	Path  string   `json:"path" yaml:"path"`
	Flags []string `json:"flags" yaml:"flags"`
}

// HTTPEndpoint is an HTTP endpoint of a profile, such as ":8080/api/users"
type HTTPEndpoint struct {
	Endpoint string   `json:"endpoint" yaml:"endpoint"`
	Methods  []string `json:"methods" yaml:"methods"`
}

// MockNetwork is the user-supplied NetworkNeighborhood mock, keyed by containerId.
type MockNetwork struct {
	Containers map[string]MockNetworkContainer `json:"containers" yaml:"containers"`
}

type MockNetworkContainer struct {
	Egress  []NetworkEntry `json:"egress" yaml:"egress"`
	Ingress []NetworkEntry `json:"ingress" yaml:"ingress"`
}

// NetworkEntry is a network neighbor. It takes the fields of a profile's neighbor (dns,
// dnsNames, ipAddress, ipAddresses), and also a list of names in dns, as the mock always did.
type NetworkEntry struct {
	IPAddress   string     `json:"ipAddress" yaml:"ipAddress"`
	IPAddresses []string   `json:"ipAddresses" yaml:"ipAddresses"`
	DNS         stringList `json:"dns" yaml:"dns"`
	DNSNames    []string   `json:"dnsNames" yaml:"dnsNames"`
}

// stringList is a list of strings that may also be written as one string
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one == "" {
			*l = nil
		} else {
			*l = stringList{one}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("dns must be a name or a list of names: %w", err)
	}
	*l = list
	return nil
}

// MockK8s holds mock Kubernetes data for k8s.* CEL functions.
type MockK8s struct {
	// APIServerAddress is compared by k8s.is_api_server_address().
	APIServerAddress string `json:"apiServerAddress" yaml:"apiServerAddress"`
	// Pods are the pods the node-agent knows, of which k8s.get_container_mount_paths() and
	// k8s.get_container_by_name() read the containers; the fields are those of a Pod object.
	Pods []MockPod `json:"pods" yaml:"pods"`
}

type MockPod struct {
	Metadata struct {
		Name      string `json:"name" yaml:"name"`
		Namespace string `json:"namespace" yaml:"namespace"`
	} `json:"metadata" yaml:"metadata"`
	Spec struct {
		Containers          []MockPodContainer `json:"containers" yaml:"containers"`
		InitContainers      []MockPodContainer `json:"initContainers" yaml:"initContainers"`
		EphemeralContainers []MockPodContainer `json:"ephemeralContainers" yaml:"ephemeralContainers"`
	} `json:"spec" yaml:"spec"`
}

type MockPodContainer struct {
	Name string `json:"name" yaml:"name"`
	// Command and the exec commands of the lifecycle hooks count as executed (execInPodSpec)
	Command   []string `json:"command" yaml:"command"`
	Lifecycle struct {
		PreStop   lifecycleHandler `json:"preStop" yaml:"preStop"`
		PostStart lifecycleHandler `json:"postStart" yaml:"postStart"`
	} `json:"lifecycle" yaml:"lifecycle"`
	VolumeMounts []struct {
		MountPath string `json:"mountPath" yaml:"mountPath"`
	} `json:"volumeMounts" yaml:"volumeMounts"`
}

type lifecycleHandler struct {
	Exec struct {
		Command []string `json:"command" yaml:"command"`
	} `json:"exec" yaml:"exec"`
}

// execInPodSpec is the node-agent's isExecInPodSpec: a path that is an element of the command of
// the container, or of the exec command of its preStop or postStart hook, counts as executed
func (c MockPodContainer) execInPodSpec(path string) bool {
	return slices.Contains(c.Command, path) ||
		slices.Contains(c.Lifecycle.PreStop.Exec.Command, path) ||
		slices.Contains(c.Lifecycle.PostStart.Exec.Command, path)
}

// pod is the pod of the mock with this namespace and name
func (k MockK8s) pod(namespace, name string) *MockPod {
	for i := range k.Pods {
		if k.Pods[i].Metadata.Namespace == namespace && k.Pods[i].Metadata.Name == name {
			return &k.Pods[i]
		}
	}
	return nil
}

// containers are the containers of a pod with this name: its containers, init containers and
// ephemeral containers
func (p *MockPod) containers(name string) []MockPodContainer {
	var found []MockPodContainer
	for _, group := range [][]MockPodContainer{p.Spec.Containers, p.Spec.InitContainers, p.Spec.EphemeralContainers} {
		for _, container := range group {
			if container.Name == name {
				found = append(found, container)
			}
		}
	}
	return found
}

func strVal(v ref.Val) (string, bool) {
	s, ok := v.Value().(string)
	return s, ok
}

// intVal is an integer argument; the numbers of the mock event are JSON numbers, which may also
// arrive as whole doubles
func intVal(v ref.Val) (int64, bool) {
	switch n := v.Value().(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}

// stringListVal is a list of strings, as the node-agent parses the list arguments of its
// functions
func stringListVal(v ref.Val) ([]string, error) {
	list, ok := v.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("invalid list format: expected list")
	}
	size, ok := list.Size().Value().(int64)
	if !ok {
		return nil, fmt.Errorf("invalid list size type")
	}
	result := make([]string, size)
	for i := range size {
		s, ok := list.Get(types.Int(i)).Value().(string)
		if !ok {
			return nil, fmt.Errorf("invalid element type in list at index %d", i)
		}
		result[i] = s
	}
	return result, nil
}

// libraryFunction is a CEL function of the libraries. Its arguments are declared with the types
// the node-agent declares, so that a call with a value of another type does not compile; the
// function also checks their types as the node-agent does.
type libraryFunction struct {
	name   string
	args   []*cel.Type
	result *cel.Type
	call   func(args []ref.Val) ref.Val
}

var (
	stringArgs1 = []*cel.Type{cel.StringType}
	stringArgs3 = []*cel.Type{cel.StringType, cel.StringType, cel.StringType}
	stringsArg  = cel.ListType(cel.StringType)
)

// declare declares functions under a namespace, such as "cp." with overload ids "cp_..."; the
// node-agent declares its profile functions as cp.* and, deprecated, as ap.* and nn.*
func declare(namespace string, functions []libraryFunction) []cel.EnvOption {
	options := make([]cel.EnvOption, 0, len(functions))
	for _, function := range functions {
		options = append(options, cel.Function(namespace+"."+function.name,
			cel.Overload(namespace+"_"+function.name, function.args, function.result,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val { return function.call(values) }),
			),
		))
	}
	return options
}

// profileFunction is a function that answers from the profile of a container; like the
// node-agent's, it answers false for a container without a profile. Its arguments are the id of
// the container, a string and those of the given types.
func profileFunction[T any](name string, more []*cel.Type, containers map[string]T, check func(container T, args []ref.Val) ref.Val) libraryFunction {
	args := append([]*cel.Type{cel.StringType, cel.StringType}, more...)
	return libraryFunction{name: name, args: args, result: cel.BoolType, call: func(values []ref.Val) ref.Val {
		for _, value := range values[:2] {
			if _, ok := strVal(value); !ok {
				return types.MaybeNoSuchOverloadErr(value)
			}
		}
		containerID, _ := strVal(values[0])
		container, ok := containers[containerID]
		if !ok {
			return types.Bool(false)
		}
		return check(container, values[1:])
	}}
}

func (c MockContainer) execPaths() []string {
	paths := make([]string, len(c.Execs))
	for i, exec := range c.Execs {
		paths[i] = exec.Path
	}
	return paths
}

func (c MockContainer) openPaths() []string {
	paths := make([]string, len(c.Opens))
	for i, open := range c.Opens {
		paths[i] = open.Path
	}
	return paths
}

func (c MockContainer) endpointPaths() []string {
	paths := make([]string, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		paths[i] = endpoint.Endpoint
	}
	return paths
}

func hasMatch(entries []string, matches func(entry string) bool) ref.Val {
	return types.Bool(slices.ContainsFunc(entries, matches))
}

// withPodSpecExecs adds to was_executed and was_executed_with_args what the node-agent adds
// (isExecInPodSpec): for a container with a profile, a path of its pod spec's command or exec
// hooks counts as executed, whatever the arguments. The node-agent also counts every later exec
// of a container whose preStop hook ran, which does not matter for the one event of the
// playground.
func withPodSpecExecs(function libraryFunction, containers map[string]MockContainer, podContainer func(containerID string) *MockPodContainer) libraryFunction {
	call := function.call
	function.call = func(values []ref.Val) ref.Val {
		result := call(values)
		if executed, ok := result.(types.Bool); !ok || bool(executed) {
			return result
		}
		containerID, _ := strVal(values[0])
		path, _ := strVal(values[1])
		// was_executed answers false for an empty path before it looks further
		if _, hasProfile := containers[containerID]; !hasProfile || (function.name == "was_executed" && path == "") {
			return result
		}
		if container := podContainer(containerID); container != nil && container.execInPodSpec(path) {
			return types.True
		}
		return result
	}
	return function
}

// profileFunctions are the functions of the node-agent's containerprofile library;
// podContainer is the container of the pod spec that a container id stands for
func profileFunctions(profile MockProfile, podContainer func(containerID string) *MockPodContainer) []libraryFunction {
	containers := profile.Containers
	path := func(container MockContainer, args []ref.Val, entries func(MockContainer) []string) ref.Val {
		query, _ := strVal(args[0])
		return types.Bool(matchProfilePath(entries(container), query))
	}
	// the functions with a list argument check it, although they only match the path
	pathWithList := func(what string, entries func(MockContainer) []string) func(MockContainer, []ref.Val) ref.Val {
		return func(container MockContainer, args []ref.Val) ref.Val {
			query, _ := strVal(args[0])
			if query == "" {
				return types.Bool(false)
			}
			if _, err := stringListVal(args[1]); err != nil {
				return types.NewErr("failed to parse %s: %v", what, err)
			}
			return types.Bool(matchProfilePath(entries(container), query))
		}
	}
	affix := func(entries func(MockContainer) []string, matches func(entry, affix string) bool) func(MockContainer, []ref.Val) ref.Val {
		return func(container MockContainer, args []ref.Val) ref.Val {
			value, _ := strVal(args[0])
			return hasMatch(entries(container), func(entry string) bool { return matches(entry, value) })
		}
	}
	contains := func(entries func(MockContainer) []string) func(MockContainer, []ref.Val) ref.Val {
		return func(container MockContainer, args []ref.Val) ref.Val {
			value, _ := strVal(args[0])
			return types.Bool(slices.Contains(entries(container), value))
		}
	}

	withList := []*cel.Type{stringsArg}
	return []libraryFunction{
		withPodSpecExecs(profileFunction("was_executed", nil, containers, func(c MockContainer, args []ref.Val) ref.Val {
			return path(c, args, MockContainer.execPaths)
		}), containers, podContainer),
		withPodSpecExecs(profileFunction("was_executed_with_args", withList, containers, func(c MockContainer, args []ref.Val) ref.Val {
			query, _ := strVal(args[0])
			runtimeArgs, err := stringListVal(args[1])
			if err != nil {
				return types.NewErr("failed to parse args: %v", err)
			}
			// the arguments of any exec of a path that matches: literal paths exactly, patterns
			// by their segments
			return types.Bool(slices.ContainsFunc(c.Execs, func(exec ExecCall) bool {
				matched := exec.Path == query
				if isPattern(exec.Path) {
					matched = compareDynamic(exec.Path, query)
				}
				return matched && matchExecArgv(exec.Args, runtimeArgs)
			}))
		}), containers, podContainer),
		profileFunction("was_path_opened", nil, containers, func(c MockContainer, args []ref.Val) ref.Val {
			return path(c, args, MockContainer.openPaths)
		}),
		profileFunction("was_path_opened_with_flags", withList, containers, pathWithList("flags", MockContainer.openPaths)),
		profileFunction("was_path_opened_with_suffix", nil, containers, affix(MockContainer.openPaths, strings.HasSuffix)),
		profileFunction("was_path_opened_with_prefix", nil, containers, affix(MockContainer.openPaths, strings.HasPrefix)),
		profileFunction("was_syscall_used", nil, containers, contains(func(c MockContainer) []string { return c.Syscalls })),
		profileFunction("was_capability_used", nil, containers, contains(func(c MockContainer) []string { return c.Capabilities })),
		profileFunction("was_endpoint_accessed", nil, containers, func(c MockContainer, args []ref.Val) ref.Val {
			return path(c, args, MockContainer.endpointPaths)
		}),
		// the node-agent does not compare the methods yet
		profileFunction("was_endpoint_accessed_with_method", stringArgs1, containers, func(c MockContainer, args []ref.Val) ref.Val {
			if _, ok := strVal(args[1]); !ok {
				return types.MaybeNoSuchOverloadErr(args[1])
			}
			return path(c, args, MockContainer.endpointPaths)
		}),
		profileFunction("was_endpoint_accessed_with_methods", withList, containers, pathWithList("methods", MockContainer.endpointPaths)),
		profileFunction("was_endpoint_accessed_with_prefix", nil, containers, affix(MockContainer.endpointPaths, strings.HasPrefix)),
		profileFunction("was_endpoint_accessed_with_suffix", nil, containers, affix(MockContainer.endpointPaths, strings.HasSuffix)),
		profileFunction("was_host_accessed", nil, containers, func(c MockContainer, args []ref.Val) ref.Val {
			host, _ := strVal(args[0])
			return hasMatch(c.endpointPaths(), func(endpoint string) bool {
				if parsed, err := url.Parse(endpoint); err == nil && parsed.Host != "" &&
					(parsed.Host == host || parsed.Hostname() == host) {
					return true
				}
				// a whole host, so that "api" does not match "/v1/api/users"
				return endpoint == host || strings.HasPrefix(endpoint, host+"/") || strings.HasPrefix(endpoint, host+":")
			})
		}),
	}
}

func (e NetworkEntry) addresses() []string {
	var addresses []string
	if e.IPAddress != "" {
		addresses = append(addresses, e.IPAddress)
	}
	return append(addresses, e.IPAddresses...)
}

func (e NetworkEntry) domains() []string {
	return append(append([]string{}, e.DNS...), e.DNSNames...)
}

func neighborValues(neighbors []NetworkEntry, values func(NetworkEntry) []string) []string {
	var all []string
	for _, neighbor := range neighbors {
		all = append(all, values(neighbor)...)
	}
	return all
}

// networkFunctions are the functions of the node-agent's containerprofilenetwork library
func networkFunctions(network MockNetwork) []libraryFunction {
	containers := network.Containers
	match := func(neighbors func(MockNetworkContainer) []NetworkEntry, values func(NetworkEntry) []string, matches func([]string, string) bool) func(MockNetworkContainer, []ref.Val) ref.Val {
		return func(c MockNetworkContainer, args []ref.Val) ref.Val {
			observed, _ := strVal(args[0])
			return types.Bool(matches(neighborValues(neighbors(c), values), observed))
		}
	}
	egress := func(c MockNetworkContainer) []NetworkEntry { return c.Egress }
	ingress := func(c MockNetworkContainer) []NetworkEntry { return c.Ingress }
	// the node-agent checks the port and the protocol, but only matches the address yet
	withPortProtocol := func(neighbors func(MockNetworkContainer) []NetworkEntry) func(MockNetworkContainer, []ref.Val) ref.Val {
		return func(c MockNetworkContainer, args []ref.Val) ref.Val {
			port, ok := intVal(args[1])
			if !ok {
				return types.MaybeNoSuchOverloadErr(args[1])
			}
			if port < 0 || port > 65535 {
				return types.Bool(false)
			}
			if _, ok := strVal(args[2]); !ok {
				return types.MaybeNoSuchOverloadErr(args[2])
			}
			return match(neighbors, NetworkEntry.addresses, matchIPField)(c, args)
		}
	}
	portProtocol := []*cel.Type{cel.IntType, cel.StringType}
	return []libraryFunction{
		profileFunction("was_address_in_egress", nil, containers, match(egress, NetworkEntry.addresses, matchIPField)),
		profileFunction("was_address_in_ingress", nil, containers, match(ingress, NetworkEntry.addresses, matchIPField)),
		profileFunction("is_domain_in_egress", nil, containers, match(egress, NetworkEntry.domains, matchDNSField)),
		profileFunction("is_domain_in_ingress", nil, containers, match(ingress, NetworkEntry.domains, matchDNSField)),
		profileFunction("was_address_port_protocol_in_egress", portProtocol, containers, withPortProtocol(egress)),
		profileFunction("was_address_port_protocol_in_ingress", portProtocol, containers, withPortProtocol(ingress)),
	}
}

// k8sFunctions are the functions of the node-agent's k8s library, answered from the mock
func k8sFunctions(k8sMock MockK8s) []libraryFunction {
	// the namespace, pod and container names
	containerArgs := func(values []ref.Val, answer func(pod *MockPod, container string) ref.Val) ref.Val {
		names := make([]string, 3)
		for i, value := range values {
			name, ok := strVal(value)
			if !ok {
				return types.MaybeNoSuchOverloadErr(value)
			}
			names[i] = name
		}
		return answer(k8sMock.pod(names[0], names[1]), names[2])
	}
	return []libraryFunction{
		{name: "is_api_server_address", args: stringArgs1, result: cel.BoolType, call: func(values []ref.Val) ref.Val {
			address, ok := strVal(values[0])
			if !ok {
				return types.MaybeNoSuchOverloadErr(values[0])
			}
			return types.Bool(k8sMock.APIServerAddress != "" && address == k8sMock.APIServerAddress)
		}},
		// the node-agent fails when it does not know the pod; the playground answers no mounts,
		// as a mock without the pod is the usual case
		{name: "get_container_mount_paths", args: stringArgs3, result: stringsArg, call: func(values []ref.Val) ref.Val {
			return containerArgs(values, func(pod *MockPod, container string) ref.Val {
				paths := []string{}
				if pod != nil {
					for _, c := range pod.containers(container) {
						for _, mount := range c.VolumeMounts {
							paths = append(paths, mount.MountPath)
						}
					}
				}
				return types.NewStringList(types.DefaultTypeAdapter, paths)
			})
		}},
		{name: "get_container_by_name", args: stringArgs3, result: cel.BoolType, call: func(values []ref.Val) ref.Val {
			return containerArgs(values, func(pod *MockPod, container string) ref.Val {
				return types.Bool(pod != nil && len(pod.containers(container)) > 0)
			})
		}},
	}
}

// getExecPath is parse.get_exec_path(args, comm): args[0] when it is not empty, else comm
func getExecPath(args, comm ref.Val) ref.Val {
	argsList, err := stringListVal(args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}
	commStr, ok := strVal(comm)
	if !ok {
		return types.MaybeNoSuchOverloadErr(comm)
	}
	if len(argsList) > 0 && argsList[0] != "" {
		return types.String(argsList[0])
	}
	return types.String(commStr)
}

// libraryEnvOptions returns the CEL environment options of the node-agent's libraries: cp.* with
// the deprecated aliases ap.* and nn.*, k8s.*, parse.*, net.* and process.*.
func libraryEnvOptions(profile MockProfile, network MockNetwork, k8sMock MockK8s, event map[string]any) []cel.EnvOption {
	if profile.Containers == nil {
		profile.Containers = map[string]MockContainer{}
	}
	if network.Containers == nil {
		network.Containers = map[string]MockNetworkContainer{}
	}
	// The node-agent knows the pod of every container it watches; the playground only knows
	// that of the event's container, by the namespace, podName and containerName of the event
	podContainer := func(containerID string) *MockPodContainer {
		text := func(key string) string {
			s, _ := event[key].(string)
			return s
		}
		if containerID == "" || containerID != text("containerId") || text("containerName") == "" {
			return nil
		}
		pod := k8sMock.pod(text("namespace"), text("podName"))
		if pod == nil {
			return nil
		}
		if containers := pod.containers(text("containerName")); len(containers) > 0 {
			return &containers[0]
		}
		return nil
	}

	profileLibrary := profileFunctions(profile, podContainer)
	networkLibrary := networkFunctions(network)
	var options []cel.EnvOption
	options = append(options, declare("cp", append(append([]libraryFunction{}, profileLibrary...), networkLibrary...))...)
	options = append(options, declare("ap", profileLibrary)...)
	options = append(options, declare("nn", networkLibrary)...)
	options = append(options, declare("k8s", k8sFunctions(k8sMock))...)

	return append(options,
		// parse.get_exec_path(args, comm) string: args[0] when it is not empty, else comm;
		// parse.get_exec_path(args, comm, exepath) string: exepath when it is not empty, else
		// the same
		cel.Function("parse.get_exec_path",
			cel.Overload("parse_get_exec_path",
				[]*cel.Type{stringsArg, cel.StringType}, cel.StringType,
				cel.BinaryBinding(getExecPath),
			),
			cel.Overload("parse_get_exec_path_with_exepath",
				[]*cel.Type{stringsArg, cel.StringType, cel.StringType}, cel.StringType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					exepath, ok := strVal(values[2])
					if !ok {
						return types.MaybeNoSuchOverloadErr(values[2])
					}
					if exepath != "" {
						return types.String(exepath)
					}
					return getExecPath(values[0], values[1])
				}),
			),
		),
		// net.is_private_ip(ip) bool; like the node-agent, an argument that is no string is an
		// error, and one that is no IP address is not private
		cel.Function("net.is_private_ip",
			cel.Overload("net_is_private_ip",
				stringArgs1, cel.BoolType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					ipStr, ok := strVal(value)
					if !ok {
						return types.MaybeNoSuchOverloadErr(value)
					}
					return types.Bool(isPrivateIP(ipStr))
				}),
			),
		),
		// process.get_ld_hook_var(pid) string: always "" in the browser, which has no processes;
		// the pid is unsigned, as event.pid is
		cel.Function("process.get_ld_hook_var",
			cel.Overload("process_get_ld_hook_var",
				[]*cel.Type{cel.UintType}, cel.StringType,
				cel.UnaryBinding(func(ref.Val) ref.Val { return types.String("") }),
			),
		),
		// process.get_process_env(pid) map(string, string): always empty in the browser, as the
		// node-agent answers for a process that has exited; the pid is an integer, int(event.pid)
		cel.Function("process.get_process_env",
			cel.Overload("process_get_process_env",
				[]*cel.Type{cel.IntType}, cel.MapType(cel.StringType, cel.StringType),
				cel.UnaryBinding(func(ref.Val) ref.Val {
					return types.NewStringStringMap(types.DefaultTypeAdapter, map[string]string{})
				}),
			),
		),
	)
}

// isPrivateIP is the check of the node-agent (pkg/rulemanager/cel/libraries/net): loopback,
// RFC 1918, IPv6 unique local and link-local unicast addresses, and of IPv4 also the shared
// address space 100.64.0.0/10 and everything from 224.0.0.0 (multicast, reserved, broadcast).
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] >= 224 || (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
}
