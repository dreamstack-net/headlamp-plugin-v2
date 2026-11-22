import { errorMessage, errorName, errorStatus } from './errors';

it('reads the message of anything thrown', () => {
  expect(errorMessage(new Error('forbidden'))).toBe('forbidden');
  // Headlamp's API proxy throws errors with a status
  expect(errorMessage(Object.assign(new Error('not found'), { status: 404 }))).toBe('not found');
  expect(errorMessage({ message: 'from an object' })).toBe('from an object');
  expect(errorMessage('a string')).toBe('a string');
  expect(errorMessage(undefined)).toBe('undefined');
  expect(errorMessage(null)).toBe('null');
  expect(errorMessage({ message: 42 })).toBe('[object Object]');
});

it('reads the status and the name of an error', () => {
  expect(errorStatus(Object.assign(new Error('gone'), { status: 404 }))).toBe(404);
  expect(errorStatus({ status: '404' })).toBeUndefined();
  expect(errorStatus(new Error('no status'))).toBeUndefined();
  expect(errorStatus(undefined)).toBeUndefined();
  expect(errorName(Object.assign(new Error('closed'), { name: 'AbortError' }))).toBe('AbortError');
  expect(errorName('AbortError')).toBeUndefined();
});
