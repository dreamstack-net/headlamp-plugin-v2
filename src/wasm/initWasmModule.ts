import { errorMessage } from '../common/errors';
import './wasm_exec.js';
import './wasmTypes.d.ts';
import { useEffect, useState } from 'react';
import { getKubescapePluginUrl } from '../common/PluginHelper';

// the load in progress or done, shared by all pages; reset when it failed, so a later page
// tries again
let loading: Promise<void> | undefined;

// whether the Go program has registered its functions; they are declared, but only exist once
// it runs
function loaded() {
  return typeof window.AdmissionEval === 'function' && typeof window.RuleEval === 'function';
}

/** Loads the WASM module of the CEL evaluators once, however many pages ask for it. */
export function loadWasm(): Promise<void> {
  if (loaded()) return Promise.resolve();
  if (!loading) {
    loading = (async () => {
      const goWasm = new window.Go();
      const response = await fetch((await getKubescapePluginUrl()) + '/main.wasm');
      if (!response.ok) {
        throw new Error(`main.wasm could not be read: ${response.status} ${response.statusText}`);
      }
      const result = await WebAssembly.instantiateStreaming(response, goWasm.importObject);
      // the Go program registers its functions and keeps running
      void goWasm.run(result.instance);
      if (!loaded()) {
        throw new Error('main.wasm did not provide the evaluators');
      }
    })().catch(error => {
      loading = undefined;
      throw error;
    });
  }
  return loading;
}

/** Whether the WASM module is loaded, loading it when needed, and why it could not be. */
export function useWasm(): { ready: boolean; error?: string } {
  const [state, setState] = useState<{ ready: boolean; error?: string }>(() => ({
    ready: loaded(),
  }));
  useEffect(() => {
    if (state.ready) return;
    let active = true;
    loadWasm()
      .then(() => active && setState({ ready: true }))
      .catch(error => {
        console.error('Unable to load the WASM module', error);
        if (active) setState({ ready: false, error: errorMessage(error) });
      });
    return () => {
      active = false;
    };
    // loaded once
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return state;
}
