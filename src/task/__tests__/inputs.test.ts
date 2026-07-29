import * as tl from 'azure-pipelines-task-lib/task';
import { readInputs } from '../inputs';

jest.mock('azure-pipelines-task-lib/task');

const mocked = tl as jest.Mocked<typeof tl>;

const setInputs = (
  values: Record<string, string | undefined>,
  booleans: Record<string, boolean> = {},
) => {
  mocked.getInput.mockImplementation((name: string) => values[name]);
  mocked.getBoolInput.mockImplementation((name: string) => booleans[name] ?? false);
};

describe('readInputs', () => {
  it('reads the two required inputs', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2' });
    expect(readInputs()).toMatchObject({ scanType: 'image', target: 'app:1.4.2' });
  });

  it('leaves optional fields undefined so the resolver can apply defaults', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2' });
    const inputs = readInputs();
    expect(inputs.severities).toBeUndefined();
    expect(inputs.failOn).toBeUndefined();
    expect(inputs.runner).toBeUndefined();
  });

  it('parses severity and scanner lists', () => {
    setInputs({
      scanType: 'image',
      target: 'app:1.4.2',
      severities: 'critical,high',
      scanners: 'vuln,license',
    });
    const inputs = readInputs();
    expect(inputs.severities).toEqual(['CRITICAL', 'HIGH']);
    expect(inputs.scanners).toEqual(['vuln', 'license']);
  });

  it('rejects an unknown scan type naming the allowed values', () => {
    setInputs({ scanType: 'container', target: 'app:1.4.2' });
    expect(() => readInputs()).toThrow(/image, filesystem, repository, config, sbom/);
  });

  it('rejects an unknown scanner', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', scanners: 'vuln,telepathy' });
    expect(() => readInputs()).toThrow(/telepathy/);
  });

  it('accepts none as a failOn value', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', failOn: 'none' });
    expect(readInputs().failOn).toBe('none');
  });

  it('rejects a non-numeric timeout', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', timeoutMinutes: 'soon' });
    expect(() => readInputs()).toThrow(/timeoutMinutes/);
  });

  it('reads boolean inputs only when the pipeline set them', () => {
    setInputs(
      { scanType: 'image', target: 'app:1.4.2', useDockerSocket: 'true' },
      { useDockerSocket: true },
    );
    expect(readInputs().useDockerSocket).toBe(true);
  });

  // Amendment: FailOn excludes 'UNKNOWN' because it is a meaningless threshold (it would fail
  // on every finding, including ones Trivy could not score) even though it is a valid finding
  // severity. A naive `parseSeverityList(...)[0] as Severity` cast would let it through.
  it('rejects UNKNOWN as a failOn threshold with a clear message', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', failOn: 'UNKNOWN' });
    expect(() => readInputs()).toThrow(/UNKNOWN/);
  });
});
