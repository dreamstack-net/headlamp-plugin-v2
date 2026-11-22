import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { ValidatingAdmissionPolicyEditor } from './ValidatingAdmissionPolicy';

const mocks = vi.hoisted(() => ({ request: vi.fn(), post: vi.fn(), evaluate: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
  put: vi.fn(),
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({ ShowHideLabel: () => null }));
vi.mock('../wasm/initWasmModule', () => ({
  loadWasm: async () => {},
  useWasm: () => ({ ready: true }),
}));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/PluginHelper', () => ({ getKubescapePluginUrl: async () => '/plugin' }));
// an editor of which the tests change the text, as a user who types in it
vi.mock('@monaco-editor/react', async () => {
  const { useEffect, useRef } = await vi.importActual<typeof import('react')>('react');
  return {
    default: (props: { onMount: (editor: unknown) => void }) => {
      const text = useRef<HTMLTextAreaElement>(null);
      const listeners = useRef<(() => void)[]>([]);
      useEffect(() => {
        props.onMount({
          getValue: () => text.current?.value ?? '',
          onDidChangeModelContent: (listener: () => void) => listeners.current.push(listener),
        });
        // mounted once, like the editor
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);
      return (
        <textarea
          ref={text}
          data-testid="editor"
          onChange={() => listeners.current.forEach(listener => listener())}
        />
      );
    },
  };
});

const noMatch = 'No resourceRule of the policy matches the request.';

beforeEach(() => {
  mocks.request.mockReset().mockRejectedValue(new Error('not found'));
  mocks.post.mockReset().mockResolvedValue({ status: { allowed: true } });
  mocks.evaluate
    .mockReset()
    .mockReturnValue(JSON.stringify({ matchConstraints: false, matchReason: noMatch }));
  window.AdmissionEval = mocks.evaluate;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, text: async () => '' }))
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// longer than the editors are left alone before the policy is evaluated
const pause = () => act(() => new Promise<void>(resolve => setTimeout(resolve, 400)));

it('evaluates and offers to install a policy that was typed, not only one that was chosen', async () => {
  render(<ValidatingAdmissionPolicyEditor />);
  await act(async () => {});
  // the editors of the policy, its parameters, the resource and its namespace
  const [policy, , resource] = screen.getAllByTestId('editor');
  const install = screen.getByRole('button', { name: 'Install in cluster' });
  expect(install).toHaveProperty('disabled', true);

  fireEvent.change(policy, { target: { value: 'kind: ValidatingAdmissionPolicy' } });
  expect(install).toHaveProperty('disabled', false);
  // there is nothing to evaluate without a resource
  await pause();
  expect(mocks.evaluate).not.toHaveBeenCalled();

  fireEvent.change(resource, { target: { value: 'kind: Pod' } });
  expect(await screen.findByText(`The resource does not match. ${noMatch}`)).toBeTruthy();
  expect(mocks.evaluate).toHaveBeenCalledWith(
    'kind: ValidatingAdmissionPolicy',
    'kind: Pod',
    '',
    '',
    '',
    ''
  );

  // the result goes with the resource, and the offer with the policy
  fireEvent.change(resource, { target: { value: ' ' } });
  await waitFor(() => expect(screen.queryByText(/The resource does not match/)).toBeNull());
  fireEvent.change(policy, { target: { value: '' } });
  expect(install).toHaveProperty('disabled', true);
});
