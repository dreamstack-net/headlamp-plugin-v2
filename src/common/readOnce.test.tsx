import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { ReadOnce, useReadOnce, useStorageObject } from './readOnce';

const mocks = vi.hoisted(() => ({
  fetchObject: vi.fn(),
  cluster: 'cluster-a' as string | null,
}));
vi.mock('../model', () => ({ fetchObject: mocks.fetchObject }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => mocks.cluster }));

beforeEach(() => {
  mocks.fetchObject.mockReset();
  mocks.cluster = 'cluster-a';
});
afterEach(cleanup);

/** A promise with its resolve and reject, to finish a read when a test says so. */
function deferred<T>() {
  let resolve: (value: T) => void = () => {};
  let reject: (error: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

let current: ReadOnce<string>;
function Reader(props: Readonly<{ readKey: string | null; read: () => Promise<string> }>) {
  current = useReadOnce(props.readKey, props.read);
  return <div data-testid="state">{JSON.stringify(current)}</div>;
}

it('reads once for a key, also when the component is drawn again', async () => {
  const read = vi.fn(async () => 'object a');
  const view = render(<Reader readKey="a" read={read} />);
  expect(current.loading).toBe(true);
  expect(current.data).toBeNull();
  await waitFor(() => expect(current.data).toBe('object a'));
  expect(current.loading).toBe(false);

  // a new read function, such as a closure of the next render, is no reason to read again
  view.rerender(<Reader readKey="a" read={async () => 'other'} />);
  view.rerender(<Reader readKey="a" read={async () => 'other'} />);
  await act(async () => {});
  expect(read).toHaveBeenCalledTimes(1);
  expect(current.data).toBe('object a');
});

it('never returns what was read for another key, also when that read finishes late', async () => {
  const first = deferred<string>();
  const second = deferred<string>();
  const view = render(<Reader readKey="a" read={() => first.promise} />);
  view.rerender(<Reader readKey="b" read={() => second.promise} />);
  await act(async () => first.resolve('object a'));
  expect(current.data).toBeNull();
  expect(current.loading).toBe(true);
  await act(async () => second.resolve('object b'));
  expect(current.data).toBe('object b');

  // back to the first key: read again, without the data of the second
  view.rerender(<Reader readKey="a" read={async () => 'object a again'} />);
  expect(current.data).toBeNull();
  await waitFor(() => expect(current.data).toBe('object a again'));
});

it('keeps the data while reading again, and replaces it with what was read', async () => {
  const again = deferred<string>();
  const read = vi.fn().mockResolvedValueOnce('first').mockReturnValueOnce(again.promise);
  render(<Reader readKey="a" read={read} />);
  await waitFor(() => expect(current.data).toBe('first'));

  act(() => current.reload());
  expect(current.loading).toBe(true);
  expect(current.data).toBe('first');
  await act(async () => again.resolve('second'));
  expect(current).toMatchObject({ data: 'second', loading: false, error: null });
  expect(read).toHaveBeenCalledTimes(2);
});

it('returns why it could not read, also when the read throws at once', async () => {
  const error = { status: 404, message: 'not found' };
  const view = render(<Reader readKey="a" read={() => Promise.reject(error)} />);
  await waitFor(() => expect(current.error).toBe(error));
  expect(current).toMatchObject({ data: null, loading: false });

  view.rerender(
    <Reader
      readKey="b"
      read={() => {
        throw new Error('no cluster');
      }}
    />
  );
  // the error of the other key is not returned
  expect(current.error).toBeNull();
  await waitFor(() => expect((current.error as Error)?.message).toBe('no cluster'));
});

it('reads nothing without a key', async () => {
  const read = vi.fn(async () => 'object');
  render(<Reader readKey={null} read={read} />);
  await act(async () => {});
  expect(read).not.toHaveBeenCalled();
  expect(current).toMatchObject({ data: null, error: null, loading: false });
});

it('ignores a read that finishes after the component is gone', async () => {
  const late = deferred<string>();
  const consoleError = vi.spyOn(console, 'error');
  const view = render(<Reader readKey="a" read={() => late.promise} />);
  view.unmount();
  await act(async () => late.resolve('late'));
  expect(consoleError).not.toHaveBeenCalled();
  consoleError.mockRestore();
});

function StorageReader(
  props: Readonly<{ cluster?: string; namespace?: string; objectClass?: any }>
) {
  const { data, error } = useStorageObject(
    props.objectClass === undefined ? { pluralName: 'vulnerabilitymanifests' } : props.objectClass,
    'image-123',
    props.namespace,
    props.cluster
  );
  return (
    <div>{error ? `error: ${(error as Error).message}` : data?.metadata.name ?? 'reading'}</div>
  );
}

it('reads an object of the storage once with a GET in the cluster of the page', async () => {
  mocks.fetchObject.mockResolvedValue({ metadata: { name: 'image-123' } });
  const view = render(<StorageReader namespace="kubescape" />);
  expect(await screen.findByText('image-123')).toBeTruthy();
  expect(mocks.fetchObject).toHaveBeenCalledWith('image-123', 'kubescape', 'cluster-a', {
    pluralName: 'vulnerabilitymanifests',
  });

  // another cluster is another object
  view.rerender(<StorageReader namespace="kubescape" cluster="cluster-b" />);
  await waitFor(() => expect(mocks.fetchObject).toHaveBeenCalledTimes(2));
  expect(mocks.fetchObject.mock.calls[1].slice(0, 3)).toEqual([
    'image-123',
    'kubescape',
    'cluster-b',
  ]);
});

it('reads objects that are not namespaced, and nothing without a class', async () => {
  mocks.fetchObject.mockRejectedValue(new Error('forbidden'));
  const view = render(<StorageReader />);
  expect(await screen.findByText('error: forbidden')).toBeTruthy();
  expect(mocks.fetchObject.mock.calls[0].slice(0, 3)).toEqual(['image-123', '', 'cluster-a']);

  view.rerender(<StorageReader objectClass={null} />);
  expect(await screen.findByText('reading')).toBeTruthy();
  expect(mocks.fetchObject).toHaveBeenCalledTimes(1);
});
