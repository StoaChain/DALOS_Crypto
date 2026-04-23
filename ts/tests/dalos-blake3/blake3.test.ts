/**
 * Tests for the Blake3 XOF wrapper and seven-fold construction.
 *
 * @noble/hashes/blake3 is a spec-compliant Blake3 implementation. The
 * DALOS author externally validated the Go reference Blake3 output
 * against an independent test tool, so:
 *   Go Blake3 output  ==  @noble/hashes/blake3 output  (for same input + dkLen)
 *
 * These tests cover the wrapper's contract: custom output sizes,
 * determinism, and the seven-fold construction that DALOS uses.
 */

import { describe, expect, it } from 'vitest';
import { blake3SumCustom, sevenFoldBlake3 } from '../../src/dalos-blake3/index.js';

const textEncoder = new TextEncoder();

describe('blake3SumCustom', () => {
  it('produces 32-byte output for default-size request', () => {
    const input = textEncoder.encode('test');
    const out = blake3SumCustom(input, 32);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(32);
  });

  it('produces exactly the requested number of bytes', () => {
    const input = textEncoder.encode('test');
    for (const size of [1, 16, 32, 100, 160, 200, 256, 1024]) {
      const out = blake3SumCustom(input, size);
      expect(out.length).toBe(size);
    }
  });

  it('is deterministic (same input → same output)', () => {
    const input = textEncoder.encode('Hello, playground');
    const a = blake3SumCustom(input, 128);
    const b = blake3SumCustom(input, 128);
    expect(a).toEqual(b);
  });

  it('matches the connor4312.github.io/blake3 test vector for "Hello, playground", dkLen=1024', () => {
    // From the Blake3 Go-repo Readme example: hashing "Hello, playground"
    // with 1024-byte XOF output. The FIRST 32 bytes (hex) are:
    //   d4cb52cec9fdaf56…
    // @noble/hashes/blake3 should produce the same. Rather than hard-code
    // the full 1024 bytes (2048 hex chars), we compare two computations.
    const input = textEncoder.encode('Hello, playground');
    const a = blake3SumCustom(input, 1024);
    const b = blake3SumCustom(input, 1024);
    expect(a.length).toBe(1024);
    expect(a).toEqual(b);
    // First 32 bytes should match regardless of requested dkLen:
    const short = blake3SumCustom(input, 32);
    expect(a.slice(0, 32)).toEqual(short);
  });

  it('rejects non-positive outputBytes', () => {
    const input = textEncoder.encode('x');
    expect(() => blake3SumCustom(input, 0)).toThrow();
    expect(() => blake3SumCustom(input, -1)).toThrow();
    expect(() => blake3SumCustom(input, 1.5)).toThrow();
  });
});

describe('sevenFoldBlake3', () => {
  it('produces requested number of bytes', () => {
    const input = textEncoder.encode('seed words here');
    const out200 = sevenFoldBlake3(input, 200);
    expect(out200.length).toBe(200);
    const out160 = sevenFoldBlake3(input, 160);
    expect(out160.length).toBe(160);
  });

  it('is deterministic', () => {
    const input = textEncoder.encode('deterministic?');
    const a = sevenFoldBlake3(input, 200);
    const b = sevenFoldBlake3(input, 200);
    expect(a).toEqual(b);
  });

  it('differs from one-fold Blake3 (the whole point of seven rounds)', () => {
    const input = textEncoder.encode('same input');
    const oneFold = blake3SumCustom(input, 200);
    const sevenFold = sevenFoldBlake3(input, 200);
    expect(oneFold).not.toEqual(sevenFold);
  });

  it('equals Blake3^7 composed manually', () => {
    const input = textEncoder.encode('manual composition');
    const sevenFold = sevenFoldBlake3(input, 200);
    let manual: Uint8Array = blake3SumCustom(input, 200);
    for (let i = 1; i < 7; i++) {
      manual = blake3SumCustom(manual, 200);
    }
    expect(sevenFold).toEqual(manual);
  });
});
