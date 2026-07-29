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

  it('names the missing input and explains what to pass', () => {
    setInputs({ scanType: 'image' });
    expect(() => readInputs()).toThrow(/"target" is required/);
  });

  // Pins that an empty-string target is treated the same as an absent one, rather than
  // sailing through as a "valid" empty target that later confuses docker/trivy argv.
  it('treats an empty-string target the same as an absent one', () => {
    setInputs({ scanType: 'image', target: '' });
    expect(() => readInputs()).toThrow(/"target" is required/);
  });

  // Number() accepts more than plain integers: scientific notation and surrounding whitespace
  // both parse to a valid positive number, so both are accepted rather than rejected.
  it('accepts scientific notation and whitespace-padded numbers for timeoutMinutes', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', timeoutMinutes: '1e3' });
    expect(readInputs().timeoutMinutes).toBe(1000);

    setInputs({ scanType: 'image', target: 'app:1.4.2', timeoutMinutes: ' 5 ' });
    expect(readInputs().timeoutMinutes).toBe(5);
  });

  // A fractional timeout is not rejected: only "finite and > 0" is enforced here. Whether
  // trivy's "--timeout Xm" flag accepts a fraction is DockerCommand's concern, not this module's.
  it('accepts a fractional timeoutMinutes', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', timeoutMinutes: '0.5' });
    expect(readInputs().timeoutMinutes).toBe(0.5);
  });

  // The thrown message carries the offending element's own value, not just the field name or
  // its position, so a pipeline author can locate it in their YAML by searching for the value.
  it('names the offending element regardless of its position in the list', () => {
    setInputs({ scanType: 'image', target: 'app:1.4.2', scanners: 'telepathy,vuln,secret' });
    expect(() => readInputs()).toThrow(/telepathy/);
  });

  // Pins that every TaskInputs field this module owns is actually read from the task lib,
  // guarding against a field silently dropped from readInputs's return object.
  it('reads every declared input when the pipeline sets all of them', () => {
    setInputs(
      {
        scanType: 'filesystem',
        target: '.',
        runner: 'hardened',
        severities: 'high,critical',
        scanners: 'vuln,secret',
        failOn: 'high',
        ignoreFile: '.trivyignore',
        timeoutMinutes: '15',
        targetRegistryConnection: 'my-connection',
        formats: 'table,json',
        generateSbom: 'cyclonedx',
        extraTrivyArgs: '--offline-scan',
        workingDirectory: 'services/api',
        // optionalBool consults getInput first to tell "set" from "unset"; the mocked getInput
        // needs an entry for each boolean input too, mirroring the real task lib where a set
        // boolean input still has a string value behind it.
        ignoreUnfixed: 'true',
        skipDbUpdate: 'true',
        useDockerSocket: 'true',
        publishArtifact: 'false',
      },
      {
        ignoreUnfixed: true,
        skipDbUpdate: true,
        useDockerSocket: true,
        publishArtifact: false,
      },
    );

    expect(readInputs()).toEqual({
      scanType: 'filesystem',
      target: '.',
      runner: 'hardened',
      severities: ['HIGH', 'CRITICAL'],
      scanners: ['vuln', 'secret'],
      failOn: 'HIGH',
      ignoreUnfixed: true,
      ignoreFile: '.trivyignore',
      timeoutMinutes: 15,
      skipDbUpdate: true,
      targetRegistryConnection: 'my-connection',
      useDockerSocket: true,
      formats: ['table', 'json'],
      generateSbom: 'cyclonedx',
      publishArtifact: false,
      extraTrivyArgs: '--offline-scan',
      workingDirectory: 'services/api',
    });
  });
});
