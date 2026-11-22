import { useClustersConf } from '@kinvolk/headlamp-plugin/lib/k8s';

// Re-exported so that tests of components using it can mock this module, as Headlamp's lib/k8s
// module only resolves in a plugin build.
export { useClustersConf };
