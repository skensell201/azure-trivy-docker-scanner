import { splitArgs } from '../args';

describe('splitArgs', () => {
  it('splits on whitespace', () => {
    expect(splitArgs('--network none --user 1000')).toEqual([
      '--network',
      'none',
      '--user',
      '1000',
    ]);
  });

  it('keeps double-quoted segments together and strips the quotes', () => {
    expect(splitArgs('--label "scan run" --rm')).toEqual(['--label', 'scan run', '--rm']);
  });

  it('keeps single-quoted segments together', () => {
    expect(splitArgs("--label 'scan run'")).toEqual(['--label', 'scan run']);
  });

  it('returns an empty array for undefined or blank input', () => {
    expect(splitArgs(undefined)).toEqual([]);
    expect(splitArgs('   ')).toEqual([]);
  });

  it('rejects an unterminated quote instead of silently swallowing the rest', () => {
    expect(() => splitArgs('--label "scan run')).toThrow(/Unterminated quote/);
  });
});
