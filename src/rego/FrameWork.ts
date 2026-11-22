import { Control } from './Control';

export interface FrameWork {
  // the ConfigMap of a custom framework, and its namespace
  configmapManifestName?: any;
  configmapNamespace?: string;
  name: string;
  description?: string;
  attributes?: any;
  scanningScope?: any;
  typeTags?: string[];
  version?: any;
  controls: Control[];
  ControlsIDs?: string[];
  subSections?: any;
  // a custom framework its cluster shows while the user chose no frameworks
  // (label kubescape.io/default-framework: "true" on its ConfigMap)
  isDefault?: boolean;
}
