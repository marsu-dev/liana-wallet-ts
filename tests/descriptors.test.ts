import { describe, expect, it } from 'vitest';
import { descriptorChecksum, splitDescriptorChecksum, parseMultipath } from '../src/index.js';

describe('descriptor primitives', () => {
  it('computes the Bitcoin Core checksum vector for raw(deadbeef)', () => {
    expect(descriptorChecksum('raw(deadbeef)')).toBe('89f8spxm');
  });
  it('splits a descriptor and verifies its checksum without changing its body', () => {
    expect(splitDescriptorChecksum('raw(deadbeef)#89f8spxm')).toEqual({ body: 'raw(deadbeef)', checksum: '89f8spxm' });
    expect(() => splitDescriptorChecksum('raw(deadbeef)#00000000')).toThrow(/checksum/i);
  });
  it('preserves the ordered two multipath choices', () => {
    expect(parseMultipath('[deadbeef/48h/1h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/<7;3>/*')).toMatchObject({ fingerprint: 'deadbeef', originPath: '48h/1h', branches: [7, 3], wildcard: true });
  });
});
