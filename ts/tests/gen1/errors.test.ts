/**
 * Smoke tests for gen1 typed exception classes.
 *
 * Pins the class-shape contract for SchnorrSignError: it must extend the
 * built-in Error, expose its own .name (ES2015 subclasses do not inherit
 * the subclass name automatically), and faithfully carry the message
 * passed to its constructor. The load-bearing forced-failure tests for
 * the throw site itself live in schnorr.test.ts + registry.test.ts.
 */

import { describe, expect, it } from 'vitest';
import { SchnorrSignError } from '../../src/gen1/index.js';

describe('SchnorrSignError', () => {
  it('is an instance of Error', () => {
    const err = new SchnorrSignError('foo');
    expect(err).toBeInstanceOf(Error);
  });

  it('exposes its own class name on .name', () => {
    const err = new SchnorrSignError('foo');
    expect(err.name).toBe('SchnorrSignError');
  });

  it('carries the constructor message on .message', () => {
    const err = new SchnorrSignError('foo');
    expect(err.message).toBe('foo');
  });
});
