# Trivy Docker Scanner — План 1: ядро и таск сканирования

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Рабочий pipeline-таск `TrivyScan@1`, который запускает Trivy в docker-контейнере из каталога раннеров, считает гейт по JSON-отчёту и публикует результат, упакованный в устанавливаемый `.vsix`.

**Architecture:** Ядро — чистые функции без I/O (`DockerCommand`, `ConfigResolver`, `ReportParser`, `GateEvaluator`, `validation`), вокруг них тонкие адаптеры (`ProcessRunner`, `ConfigClient`, `inputs`, `Publisher`), которые оркеструет `run.ts`. Всё, что касается docker и Azure DevOps, спрятано за интерфейсами, поэтому 90% кода тестируется юнит-тестами без docker и без сервера.

**Tech Stack:** TypeScript 5, Node 16/20, jest + ts-jest, `azure-pipelines-task-lib`, `tfx-cli` для упаковки. UI-зависимости (React, `azure-devops-ui`) в этом плане не нужны — они появятся в плане 2.

**Спека:** `docs/superpowers/specs/2026-07-29-trivy-docker-scanner-design.md`

---

## Структура файлов

| Файл | Ответственность |
|---|---|
| `src/shared/types.ts` | Типы конфигурации и отчёта, общие для таска и UI |
| `src/shared/severity.ts` | Порядок severity, парсинг списков, сравнение с порогом |
| `src/shared/args.ts` | Разбор строки доп. аргументов в argv с учётом кавычек |
| `src/shared/validation.ts` | Правила валидации раннеров и глобальных настроек |
| `src/task/ConfigResolver.ts` | `defaults + runners + inputs` → `ResolvedScanConfig`, применение политики |
| `src/task/DockerCommand.ts` | `ResolvedScanConfig` → argv для `docker` и env для trivy |
| `src/task/EnvFile.ts` | Временный env-файл с секретами (0600) и его удаление |
| `src/task/ReportParser.ts` | trivy JSON → `NormalizedReport`, разбор `trivy version` |
| `src/task/GateEvaluator.ts` | `NormalizedReport` + порог → исход сборки и причина |
| `src/task/ProcessRunner.ts` | Интерфейс запуска процесса + реализация на `child_process` |
| `src/task/ConfigClient.ts` | Чтение документов Extension Data по REST |
| `src/task/httpFetch.ts` | HTTP-клиент на модуле `https` (агент может быть на Node 16 без глобального `fetch`) |
| `src/task/inputs.ts` | Чтение inputs таска (единственный потребитель `task-lib`) |
| `src/task/Publisher.ts` | Логирование, attachment, артефакты, статус сборки |
| `src/task/run.ts` | Оркестрация шагов скана |
| `src/task/index.ts` | Точка входа: собирает реальные адаптеры и зовёт `run.ts` |
| `src/task/task.json` | Определение таска для Azure Pipelines |
| `scripts/build-task.js` | Сборка каталога таска для упаковки |
| `vss-extension.json` | Манифест расширения |

---

## Task 1: Скелет репозитория и тулчейн

**Files:**
- Create: `package.json`, `tsconfig.json`, `jest.config.js`, `.eslintrc.json`, `.prettierrc`, `src/shared/.gitkeep`, `src/task/.gitkeep`, `test/fixtures/.gitkeep`

- [ ] **Step 1: Создать `package.json`**

```json
{
  "name": "azure-trivy-docker-scanner",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "test": "jest",
    "lint": "eslint src test --ext .ts --no-error-on-unmatched-pattern",
    "typecheck": "tsc --noEmit -p tsconfig.json"
  },
  "dependencies": {
    "azure-pipelines-task-lib": "^4.17.0"
  },
  "devDependencies": {
    "@types/jest": "^29.5.12",
    "@types/node": "^20.14.0",
    "@typescript-eslint/eslint-plugin": "^7.13.0",
    "@typescript-eslint/parser": "^7.13.0",
    "eslint": "^8.57.0",
    "jest": "^29.7.0",
    "prettier": "^3.3.0",
    "tfx-cli": "^0.17.0",
    "ts-jest": "^29.1.4",
    "typescript": "^5.4.5"
  }
}
```

- [ ] **Step 2: Создать `tsconfig.json` и `tsconfig.build.json`**

`tsconfig.json` покрывает всё, включая тесты, — иначе `npm run typecheck` молча пропускает тестовый код:

```json
{
  "compilerOptions": {
    "target": "ES2021",
    "module": "commonjs",
    "lib": ["ES2021"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": false,
    "sourceMap": true
  },
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

`rootDir` и `outDir` здесь не объявляются намеренно: в конфиге с `--noEmit` они бессмысленны, а вместе с `include` на `test/**` дают `TS6059: File is not under rootDir` на первом же файле в `test/`.

`tsconfig.build.json` используется только для компиляции и выкидывает тесты из выпуска:

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "outDir": "build",
    "rootDir": "src"
  },
  "include": ["src/**/*.ts"],
  "exclude": ["src/**/__tests__/**", "test/**"]
}
```

- [ ] **Step 3: Создать `jest.config.js`**

```js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/test/**/*.test.ts'],
  clearMocks: true,
};
```

- [ ] **Step 4: Создать `.eslintrc.json` и `.prettierrc`**

`.eslintrc.json`:

```json
{
  "root": true,
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint"],
  "extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  "env": { "node": true, "es2021": true },
  "ignorePatterns": ["build", "dist", "node_modules", "TrivyScan"]
}
```

`.prettierrc`:

```json
{ "singleQuote": true, "printWidth": 100, "trailingComma": "all" }
```

- [ ] **Step 5: Установить зависимости и проверить тулчейн**

```bash
npm install
mkdir -p src/shared src/task test/fixtures && touch src/shared/.gitkeep src/task/.gitkeep test/fixtures/.gitkeep
npx jest --passWithNoTests
```

Expected: jest печатает `No tests found, exiting with code 0`.

`npm run typecheck` на этом шаге запускать бесполезно: пока под `src/` нет ни одного `.ts`, `tsc` жёстко падает с `TS18003: No inputs were found in config file`. Это не ошибка конфигурации и подавить её флагом нельзя — проверка типов становится осмысленной начиная с Task 3, где появляются первые исходники.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json tsconfig.json jest.config.js .eslintrc.json .prettierrc src test
git commit -m "chore: typescript, jest and lint toolchain"
```

---

## Task 2: Спайк — чтение Extension Data с агента сборки

Ручная проверка на живом Azure DevOps Server. Снимает риск №1 из спеки. Пока он не снят, `ConfigClient` (Task 12) писать не на что.

**Files:**
- Create: `docs/superpowers/spikes/2026-07-29-extension-data-from-agent.md`

- [ ] **Step 1: Завести тестовые документы через REST**

С машины с доступом к серверу, подставив свой PAT и URL коллекции:

```bash
export ADO="https://dev.example.com/DefaultCollection"
export PAT="<pat-with-extension-data-scope>"
export PUB="iksoftware"; export EXT="trivy-docker-scanner"

curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"runners","__etag":-1,"value":[{"alias":"baseline","image":"registry.example.com/trivy:0.58.1","isDefault":true,"enabled":true}]}'
```

Ожидается: 200 и тело документа с непустым `__etag`.

- [ ] **Step 2: Прочитать документ тем же PAT**

```bash
curl -sS -u ":$PAT" \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1"
```

Ожидается: JSON с `"alias":"baseline"`.

- [ ] **Step 3: Прочитать тот же документ с агента сборки под `System.AccessToken`**

Временный пайплайн:

```yaml
steps:
  - bash: |
      curl -sS -w '\nHTTP %{http_code}\n' \
        -H "Authorization: Bearer $(System.AccessToken)" \
        "$(System.CollectionUri)_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1"
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

- [ ] **Step 4: Записать результат в `docs/superpowers/spikes/2026-07-29-extension-data-from-agent.md`**

Файл должен содержать: точный URL, который сработал, HTTP-код, кто выступал идентичностью, и вывод — какой режим авторизации становится дефолтным в `ConfigClient`:

- **HTTP 200** → дефолт `authMode: 'bearer'` (`System.AccessToken`), PAT остаётся опцией.
- **HTTP 401/403** → дефолт `authMode: 'pat'`; в `task.json` (Task 16) поле `configConnection` становится обязательным, в README описывается создание service connection с PAT.

Код `ConfigClient` поддерживает оба режима, поэтому реализацию это не блокирует — меняется только значение по умолчанию.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/spikes/2026-07-29-extension-data-from-agent.md
git commit -m "docs: spike result for reading extension data from build agent"
```

---

## Task 3: Типы и работа с severity

**Files:**
- Create: `src/shared/types.ts`, `src/shared/severity.ts`
- Test: `src/shared/__tests__/severity.test.ts`

- [ ] **Step 1: Создать `src/shared/types.ts`**

Файл без тестов — только типы, потребители появятся в следующих задачах.

```ts
export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
/** UNKNOWN is a valid finding severity but a meaningless threshold: it would block everything. */
export type FailOn = Exclude<Severity, 'UNKNOWN'> | 'none';
export type ScanType = 'image' | 'filesystem' | 'repository' | 'config' | 'sbom';
export type Scanner = 'vuln' | 'secret' | 'misconfig' | 'license';
export type OutputFormat = 'table' | 'json' | 'sarif';
export type SbomFormat = 'off' | 'cyclonedx' | 'spdx-json';
export type FindingKind = 'vulnerability' | 'secret' | 'misconfiguration' | 'license';

export type OverridableField =
  | 'runner'
  | 'severities'
  | 'scanners'
  | 'failOn'
  | 'ignoreUnfixed'
  | 'timeoutMinutes'
  | 'skipDbUpdate'
  | 'useDockerSocket'
  | 'extraTrivyArgs'
  | 'ignoreFile';

export interface RunnerConfig {
  alias: string;
  image: string;
  displayName?: string;
  description?: string;
  registryConnection?: string;
  extraDockerArgs?: string;
  isDefault?: boolean;
  enabled?: boolean;
}

export interface DefaultsConfig {
  dbRepository: string;
  javaDbRepository?: string;
  dbRegistryConnection?: string;
  cacheDir?: string;
  skipDbUpdate?: boolean;
  severities?: Severity[];
  scanners?: Scanner[];
  failOn?: FailOn;
  ignoreUnfixed?: boolean;
  timeoutMinutes?: number;
  allowOverrides?: OverridableField[];
}

export interface TaskInputs {
  scanType: ScanType;
  target: string;
  runner?: string;
  severities?: Severity[];
  scanners?: Scanner[];
  failOn?: FailOn;
  ignoreUnfixed?: boolean;
  ignoreFile?: string;
  timeoutMinutes?: number;
  skipDbUpdate?: boolean;
  targetRegistryConnection?: string;
  useDockerSocket?: boolean;
  formats?: OutputFormat[];
  generateSbom?: SbomFormat;
  publishArtifact?: boolean;
  extraTrivyArgs?: string;
  workingDirectory?: string;
}

/** Окружение агента, известное только в рантайме таска. */
export interface AgentContext {
  sourcesDir: string;
  agentHomeDir: string;
  tempDir: string;
  buildId: string;
}

/** Полностью определённая конфигурация одного запуска. Опциональны только реально необязательные поля. */
export interface ResolvedScanConfig {
  runner: RunnerConfig;
  scanType: ScanType;
  target: string;
  severities: Severity[];
  scanners: Scanner[];
  failOn: FailOn;
  ignoreUnfixed: boolean;
  skipDbUpdate: boolean;
  timeoutMinutes: number;
  dbRepository: string;
  javaDbRepository?: string;
  cacheDir: string;
  sourcesDir: string;
  workingDirectory?: string;
  ignoreFile?: string;
  useDockerSocket: boolean;
  formats: OutputFormat[];
  generateSbom: SbomFormat;
  publishArtifact: boolean;
  extraTrivyArgs?: string;
  buildId: string;
  scanIndex: number;
}

export interface Finding {
  kind: FindingKind;
  severity: Severity;
  id: string;
  title: string;
  target: string;
  pkgName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  location?: string;
}

export interface RunnerInfo {
  alias: string;
  image: string;
  trivyVersion?: string;
  dbUpdatedAt?: string;
}

export interface NormalizedReport {
  schemaVersion: 1;
  scanType: ScanType;
  target: string;
  artifactName: string;
  createdAt?: string;
  runner: RunnerInfo;
  findings: Finding[];
  counts: Record<Severity, number>;
  kindCounts: Record<FindingKind, number>;
}
```

- [ ] **Step 2: Написать падающий тест `src/shared/__tests__/severity.test.ts`**

```ts
import { compareSeverity, isAtLeast, parseSeverityList, emptySeverityCounts } from '../severity';

describe('severity', () => {
  it('orders severities from UNKNOWN to CRITICAL', () => {
    expect(compareSeverity('CRITICAL', 'HIGH')).toBeGreaterThan(0);
    expect(compareSeverity('LOW', 'MEDIUM')).toBeLessThan(0);
    expect(compareSeverity('HIGH', 'HIGH')).toBe(0);
  });

  it('treats a severity as meeting a threshold when equal or higher', () => {
    expect(isAtLeast('CRITICAL', 'HIGH')).toBe(true);
    expect(isAtLeast('HIGH', 'HIGH')).toBe(true);
    expect(isAtLeast('MEDIUM', 'HIGH')).toBe(false);
  });

  it('parses a comma separated list case-insensitively and trims blanks', () => {
    expect(parseSeverityList(' critical , HIGH ')).toEqual(['CRITICAL', 'HIGH']);
  });

  it('rejects an unknown severity naming the offending value', () => {
    expect(() => parseSeverityList('CRITICAL,BOGUS')).toThrow(/BOGUS/);
  });

  it('returns zeroed counts for every severity', () => {
    expect(emptySeverityCounts()).toEqual({
      UNKNOWN: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    });
  });
});
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `npx jest src/shared/__tests__/severity.test.ts`
Expected: FAIL — `Cannot find module '../severity'`.

- [ ] **Step 4: Реализовать `src/shared/severity.ts`**

```ts
import { Severity, SeverityCounts } from './types';

export const SEVERITY_ORDER = [
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
] as const satisfies readonly Severity[];

/** Throws on a value outside the vocabulary: a silent -1 would sort below UNKNOWN and block everything. */
export function severityRank(value: Severity): number {
  const rank = (SEVERITY_ORDER as readonly string[]).indexOf(value);
  if (rank === -1) {
    throw new Error(
      `Unknown severity "${value}". Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
    );
  }
  return rank;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}

export function isAtLeast(value: Severity, threshold: Severity): boolean {
  return compareSeverity(value, threshold) >= 0;
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(value);
}

export function parseSeverity(raw: string): Severity {
  const value = raw.trim().toUpperCase();
  if (value.length === 0) {
    throw new Error(`Expected a severity, got an empty value.`);
  }
  if (!isSeverity(value)) {
    throw new Error(`Unknown severity "${value}". Allowed values: ${SEVERITY_ORDER.join(', ')}.`);
  }
  return value;
}

export function parseSeverityList(raw: string): Severity[] {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  if (parts.length === 0) {
    throw new Error(`Expected a comma separated list of severities, got "${raw}".`);
  }

  return parts.map(parseSeverity);
}

export function emptySeverityCounts(): SeverityCounts {
  return { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
}
```

- [ ] **Step 5: Убедиться, что тесты проходят**

Run: `npx jest src/shared/__tests__/severity.test.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 6: Commit**

```bash
git add src/shared/types.ts src/shared/severity.ts src/shared/__tests__/severity.test.ts
git commit -m "feat: shared config types and severity helpers"
```

- [ ] **Step 7: Ужесточить словарь severity (по итогам ревью)**

`indexOf` возвращает `-1` для значения вне союза, из-за чего `failOn: "critical"` в нижнем регистре сортируется ниже `UNKNOWN` и делает блокирующей любую находку. Ни `validation.ts`, ни `ConfigClient` значение `failOn` не проверяют, так что попасть туда мусор может. Поэтому:

- `SEVERITY_ORDER` объявляется как `readonly Severity[]` (в `isSeverity` внутренний каст становится `as readonly string[]`);
- добавляется `severityRank(value: Severity): number`, который бросает исключение на неизвестном значении; через него идут `compareSeverity` и `isAtLeast`;
- добавляется `parseSeverity(raw: string): Severity` — тримит, приводит к верхнему регистру, бросает на пустой строке и на неизвестном значении;
- `parseSeverityList` разбирает элементы через `parseSeverity` и бросает, если не получилось ни одного значения (иначе `--severity ''` уходит в trivy).

Тесты: бросок `severityRank` на неизвестном значении, бросок `isAtLeast` на неизвестном пороге, `parseSeverity` на ' high ' и на пустой строке, отказ `parseSeverityList` на `''` и `' ,, '`, регистрозависимость `isSeverity`, и вместо повтора литерала — проверка, что `emptySeverityCounts()` возвращает свежий объект (его мутирует `ReportParser`).

- [ ] **Step 8: Именованные типы счётчиков и `findingKind.ts`**

В `types.ts` добавляются `export type SeverityCounts = Record<Severity, number>` и `export type KindCounts = Record<FindingKind, number>`, которые используются в `NormalizedReport`. Рядом создаётся `src/shared/findingKind.ts` с `FINDING_KINDS: readonly FindingKind[]` и `emptyKindCounts(): KindCounts` плюс тест на нулевые значения и свежесть объекта — иначе этот литерал дублируется в `ReportParser` и во вкладке результатов.

Док-комментарии в `types.ts` пишутся по-английски (файл читают оба UI-плана) и покрывают только неочевидное: `enabled` (отсутствие означает «включён»), `allowOverrides` (отсутствие — можно переопределять всё, пустой массив — ничего), `schemaVersion`, `artifactName` против `target`, `scanIndex`, неуникальность `Finding.id`, нестабильный формат `Finding.location`.

---

## Task 4: Разбор строки дополнительных аргументов

`extraDockerArgs` и `extraTrivyArgs` приходят одной строкой, а в `spawn` нужен массив. Наивный `split(' ')` ломается на `--label "scan run"`.

**Files:**
- Create: `src/shared/args.ts`
- Test: `src/shared/__tests__/args.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
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

  it('preserves an explicitly empty argument', () => {
    expect(splitArgs('--label ""')).toEqual(['--label', '']);
  });

  it('joins a quoted segment to adjacent unquoted text', () => {
    expect(splitArgs('--label description="my scan"')).toEqual(['--label', 'description=my scan']);
  });
});
```

Последние два теста не декоративные: без них два правдоподобных «упрощения» реализации проходят весь набор. Замена `hasContent` на проверку `current` на истинность теряет пустой аргумент, а он в argv значим — массив уходит в `spawn` без шелла, и потеря элемента сдвигает все последующие позиционные аргументы, из-за чего trivy читает как цель скана не то значение. Разрыв токена на кавычке ломает обычную докеровскую запись `--label key="value"`.

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/shared/__tests__/args.test.ts`
Expected: FAIL — `Cannot find module '../args'`.

- [ ] **Step 3: Реализовать `src/shared/args.ts`**

```ts
export function splitArgs(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  const result: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let quoteStart = -1;
  // True once a token has been opened, including an empty quoted one: `current` truthiness is not a substitute.
  let hasContent = false;
  let position = 0;

  for (const char of raw) {
    position += 1;

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      quoteStart = position;
      hasContent = true;
      continue;
    }

    // Unicode whitespace separates arguments deliberately, so a pasted NBSP does not become part of a token.
    if (/\s/.test(char)) {
      if (hasContent) {
        result.push(current);
        current = '';
        hasContent = false;
      }
      continue;
    }

    current += char;
    hasContent = true;
  }

  if (quote) {
    // Report the position, not the string: extraTrivyArgs comes from the pipeline and lands in the build log.
    throw new Error(`Unterminated quote in arguments at position ${quoteStart}.`);
  }
  if (hasContent) {
    result.push(current);
  }
  return result;
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/shared/__tests__/args.test.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/shared/args.ts src/shared/__tests__/args.test.ts
git commit -m "feat: quote-aware argument string splitter"
```

---

## Task 5: Валидация конфигурации

Один и тот же модуль используется админкой (план 2) и таском, поэтому живёт в `shared/`.

**Files:**
- Create: `src/shared/validation.ts`
- Test: `src/shared/__tests__/validation.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import { validateRunner, validateCatalog, validateDefaults } from '../validation';
import { DefaultsConfig, RunnerConfig } from '../types';

const runner = (over: Partial<RunnerConfig> = {}): RunnerConfig => ({
  alias: 'baseline',
  image: 'registry.example.com/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  ...over,
});

const defaults = (over: Partial<DefaultsConfig> = {}): DefaultsConfig => ({
  dbRepository: 'registry.example.com/trivy-db:2',
  ...over,
});

describe('validateRunner', () => {
  it('accepts a well-formed runner', () => {
    expect(validateRunner(runner())).toEqual([]);
  });

  it('rejects an alias that is not lowercase kebab', () => {
    const issues = validateRunner(runner({ alias: 'Base Line' }));
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('lowercase') }]);
  });

  it('requires an image reference', () => {
    const issues = validateRunner(runner({ image: '' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('required') }]);
  });

  it('requires an explicit tag on the image', () => {
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('rejects the latest tag because it is not reproducible', () => {
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy:latest' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('latest') }]);
  });

  it('rejects unparsable extra docker args', () => {
    const issues = validateRunner(runner({ extraDockerArgs: '--label "oops' }));
    expect(issues).toEqual([
      { field: 'extraDockerArgs', message: expect.stringContaining('Unterminated quote') },
    ]);
  });
});

describe('validateCatalog', () => {
  it('accepts a catalog with unique aliases and exactly one default', () => {
    expect(validateCatalog([runner(), runner({ alias: 'hardened', isDefault: false })])).toEqual([]);
  });

  it('rejects duplicate aliases naming the duplicate', () => {
    const issues = validateCatalog([runner(), runner({ isDefault: false })]);
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('baseline') }]);
  });

  it('rejects more than one default runner', () => {
    const issues = validateCatalog([runner(), runner({ alias: 'hardened' })]);
    expect(issues).toEqual([
      { field: 'isDefault', message: expect.stringContaining('exactly one') },
    ]);
  });

  it('rejects a catalog whose only default runner is disabled', () => {
    const issues = validateCatalog([runner({ enabled: false })]);
    expect(issues).toEqual([{ field: 'isDefault', message: expect.stringContaining('disabled') }]);
  });
});

describe('validateDefaults', () => {
  it('accepts minimal defaults', () => {
    expect(validateDefaults(defaults())).toEqual([]);
  });

  it('requires a db repository because the target environment has no internet', () => {
    const issues = validateDefaults(defaults({ dbRepository: '  ' }));
    expect(issues).toEqual([
      { field: 'dbRepository', message: expect.stringContaining('required') },
    ]);
  });

  it('rejects a non-positive timeout', () => {
    const issues = validateDefaults(defaults({ timeoutMinutes: 0 }));
    expect(issues).toEqual([
      { field: 'timeoutMinutes', message: expect.stringContaining('greater than zero') },
    ]);
  });

  it('rejects an empty severity list', () => {
    const issues = validateDefaults(defaults({ severities: [] }));
    expect(issues).toEqual([
      { field: 'severities', message: expect.stringContaining('at least one') },
    ]);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/shared/__tests__/validation.test.ts`
Expected: FAIL — `Cannot find module '../validation'`.

- [ ] **Step 3: Реализовать `src/shared/validation.ts`**

```ts
import { splitArgs } from './args';
import { DefaultsConfig, RunnerConfig } from './types';

export interface ValidationIssue {
  field: string;
  message: string;
}

const ALIAS_PATTERN = /^[a-z0-9][a-z0-9-]{1,30}$/;

export function validateRunner(runner: RunnerConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (!ALIAS_PATTERN.test(runner.alias ?? '')) {
    issues.push({
      field: 'alias',
      message:
        'Alias must be lowercase letters, digits and dashes, 2 to 31 characters, starting with a letter or digit.',
    });
  }

  const image = (runner.image ?? '').trim();
  if (image.length === 0) {
    issues.push({ field: 'image', message: 'Image reference is required.' });
  } else {
    const tagSeparator = image.lastIndexOf(':');
    const hasTag = tagSeparator > image.lastIndexOf('/');
    if (!hasTag) {
      issues.push({
        field: 'image',
        message: 'Image must carry an explicit tag, for example registry.example.com/trivy:0.58.1.',
      });
    } else if (image.slice(tagSeparator + 1) === 'latest') {
      issues.push({
        field: 'image',
        message: 'The latest tag is not allowed because scans must be reproducible.',
      });
    }
  }

  if (runner.extraDockerArgs) {
    try {
      splitArgs(runner.extraDockerArgs);
    } catch (error) {
      issues.push({ field: 'extraDockerArgs', message: (error as Error).message });
    }
  }

  return issues;
}

export function validateCatalog(runners: RunnerConfig[]): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  const seen = new Set<string>();
  for (const runner of runners) {
    if (seen.has(runner.alias)) {
      issues.push({ field: 'alias', message: `Duplicate runner alias "${runner.alias}".` });
    }
    seen.add(runner.alias);
  }

  const defaults = runners.filter((runner) => runner.isDefault);
  if (defaults.length !== 1) {
    issues.push({
      field: 'isDefault',
      message: `The catalog must contain exactly one default runner, found ${defaults.length}.`,
    });
  } else if (defaults[0].enabled === false) {
    issues.push({
      field: 'isDefault',
      message: `Default runner "${defaults[0].alias}" is disabled. Enable it or mark another runner as default.`,
    });
  }

  return issues;
}

export function validateDefaults(config: DefaultsConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if ((config.dbRepository ?? '').trim().length === 0) {
    issues.push({
      field: 'dbRepository',
      message: 'A vulnerability database repository is required: build agents have no internet access.',
    });
  }

  if (config.timeoutMinutes !== undefined && config.timeoutMinutes <= 0) {
    issues.push({ field: 'timeoutMinutes', message: 'Timeout must be greater than zero.' });
  }

  if (config.severities !== undefined && config.severities.length === 0) {
    issues.push({ field: 'severities', message: 'Select at least one severity.' });
  }

  if (config.scanners !== undefined && config.scanners.length === 0) {
    issues.push({ field: 'scanners', message: 'Select at least one scanner.' });
  }

  return issues;
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/shared/__tests__/validation.test.ts`
Expected: PASS, 14 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/shared/validation.ts src/shared/__tests__/validation.test.ts
git commit -m "feat: shared validation rules for runners and defaults"
```

- [ ] **Step 6: Ужесточить модуль против непроверенных документов (по итогам ревью)**

Обещание «возвращаем список проблем, а не бросаем» выполняется только для входа, который уже соответствует типам, — то есть ровно для случая, который не нуждается в валидации. Таск же скармливает сюда результат `JSON.parse` из документа, правимого руками через REST. Сейчас `validateCatalog(null)` даёт `TypeError: runners is not iterable`, а `"severities": null` — `Cannot read properties of null`, потому что `null !== undefined` и охранное условие пропускает такое значение. В логе сборки это выглядит как внутренняя ошибка вместо «документ настроек испорчен».

Поэтому:

- все три функции принимают `unknown` вместо объявленных типов — это честная сигнатура для кода, чья работа и состоит в проверке недоверенной формы (со старой сигнатурой тесты на испорченный вход просто не компилировались). Возвращаемый тип и форма `ValidationIssue` не меняются;
- каждая из трёх функций начинается с проверки формы: не массив → одна проблема на поле `runners`; не объект → проблема на поле `runner`/`defaults`; элемент каталога не объект → проблема с указанием индекса;
- значения не того типа не проходят молча: `timeoutMinutes` проверяется через `typeof === 'number' && Number.isFinite && > 0` (иначе `NaN` уезжает в докер-команду), `severities` и `scanners` — через `Array.isArray` (иначе строка `'HIGH'` считается непустым списком), `alias`, `image`, `dbRepository` — через `typeof === 'string'`;
- тег образа проверяется шаблоном `^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`, иначе проходят `registry.example.com/trivy:` и `registry.example.com/trivy:0.58.1 --privileged`. Ссылки по digest (`@sha256:...`) распознаются отдельно и принимаются намеренно: digest — самая воспроизводимая ссылка из возможных, отвергать её было бы ровно наоборот;
- сообщения дедуплицируются (один и тот же дублирующийся alias сообщается один раз), а сообщение про раннер по умолчанию называет виновников: `found 2: "baseline", "hardened"`;
- на `validateCatalog` вешается док-комментарий о том, что он проверяет только межраннерные инварианты: сейчас каталог из одного раннера с плохим alias и тегом `latest` получает от него чистый вердикт, и ничто не подсказывает вызывающему, что нужно ещё пройтись `validateRunner` по элементам.

Тесты, которых не хватало (мутационное тестирование показало, что без них правки реализации проходят весь набор): отказ на пустом `scanners` — единственное правило `validateDefaults`, не покрытое вообще; принятие раннера с опущенным `enabled` (в `types.ts` задокументировано, что отсутствие означает «включён»); границы длины alias — 2 и 32 символа; приём `registry.example.com/latest-trivy:0.58.1`, чтобы правило про `latest` смотрело на тег, а не на подстроку имени; и три формы digest-ссылок.

---

## Task 6: Слияние конфигурации и политика переопределений

**Files:**
- Create: `src/task/ConfigResolver.ts`
- Test: `src/task/__tests__/ConfigResolver.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import { resolveConfig, PolicyViolationError, RunnerNotFoundError } from '../ConfigResolver';
import { AgentContext, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
  { alias: 'hardened', image: 'registry.example.com/trivy-fips:0.58.1', enabled: true },
  { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: false },
];

const defaults: DefaultsConfig = { dbRepository: 'registry.example.com/trivy-db:2' };

const agent: AgentContext = {
  sourcesDir: '/agent/_work/1/s',
  agentHomeDir: '/agent',
  tempDir: '/agent/_work/_temp',
  buildId: '1042',
};

const inputs = (over: Partial<TaskInputs> = {}): TaskInputs => ({
  scanType: 'image',
  target: 'app:1.4.2',
  ...over,
});

describe('resolveConfig', () => {
  it('falls back to the default runner when the pipeline names none', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 0 });
    expect(config.runner.alias).toBe('baseline');
  });

  it('applies built-in defaults when neither admin nor pipeline set a value', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 0 });
    expect(config.severities).toEqual(['CRITICAL', 'HIGH']);
    expect(config.scanners).toEqual(['vuln', 'secret']);
    expect(config.failOn).toBe('CRITICAL');
    expect(config.timeoutMinutes).toBe(10);
    expect(config.ignoreUnfixed).toBe(false);
    expect(config.cacheDir).toBe('/agent/_trivy-cache');
  });

  it('prefers admin defaults over built-in defaults', () => {
    const config = resolveConfig({
      defaults: { ...defaults, failOn: 'HIGH', timeoutMinutes: 25 },
      runners,
      inputs: inputs(),
      agent,
      scanIndex: 0,
    });
    expect(config.failOn).toBe('HIGH');
    expect(config.timeoutMinutes).toBe(25);
  });

  it('lets the pipeline override a field when policy allows it', () => {
    const config = resolveConfig({
      defaults: { ...defaults, failOn: 'CRITICAL' },
      runners,
      inputs: inputs({ failOn: 'LOW' }),
      agent,
      scanIndex: 0,
    });
    expect(config.failOn).toBe('LOW');
  });

  it('rejects an override of a field the policy withholds', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'] },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('names both the field and the allowed fields when policy rejects an override', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'] },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/failOn.*severities/s);
  });

  it('lists the available aliases when the requested runner does not exist', () => {
    expect(() =>
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'nope' }), agent, scanIndex: 0 }),
    ).toThrow(/baseline, hardened/);
  });

  it('refuses a disabled runner', () => {
    expect(() =>
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'legacy' }), agent, scanIndex: 0 }),
    ).toThrow(RunnerNotFoundError);
  });

  it('fails when the catalog is empty', () => {
    expect(() =>
      resolveConfig({ defaults, runners: [], inputs: inputs(), agent, scanIndex: 0 }),
    ).toThrow(/no runners/i);
  });

  it('carries agent context into the resolved config', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 2 });
    expect(config.sourcesDir).toBe('/agent/_work/1/s');
    expect(config.buildId).toBe('1042');
    expect(config.scanIndex).toBe(2);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/ConfigResolver.test.ts`
Expected: FAIL — `Cannot find module '../ConfigResolver'`.

- [ ] **Step 3: Реализовать `src/task/ConfigResolver.ts`**

```ts
import * as path from 'path';
import {
  AgentContext,
  DefaultsConfig,
  OverridableField,
  ResolvedScanConfig,
  RunnerConfig,
  TaskInputs,
} from '../shared/types';

export class PolicyViolationError extends Error {}
export class RunnerNotFoundError extends Error {}

const ALL_OVERRIDABLE: OverridableField[] = [
  'runner',
  'severities',
  'scanners',
  'failOn',
  'ignoreUnfixed',
  'timeoutMinutes',
  'skipDbUpdate',
];

export interface ResolveArgs {
  defaults: DefaultsConfig;
  runners: RunnerConfig[];
  inputs: TaskInputs;
  agent: AgentContext;
  scanIndex: number;
}

export function resolveConfig(args: ResolveArgs): ResolvedScanConfig {
  const { defaults, runners, inputs, agent, scanIndex } = args;
  const allowed = defaults.allowOverrides ?? ALL_OVERRIDABLE;

  const pick = <T>(field: OverridableField, fromInputs: T | undefined, fallback: T): T => {
    if (fromInputs === undefined) {
      return fallback;
    }
    if (!allowed.includes(field)) {
      throw new PolicyViolationError(
        `The pipeline sets "${field}", but the collection policy does not allow overriding it. ` +
          `Overridable fields: ${allowed.join(', ') || 'none'}. Change the value in Collection Settings > Trivy Scanner.`,
      );
    }
    return fromInputs;
  };

  const runner = selectRunner(runners, pick('runner', inputs.runner, undefined));

  return {
    runner,
    scanType: inputs.scanType,
    target: inputs.target,
    severities: pick('severities', inputs.severities, defaults.severities ?? ['CRITICAL', 'HIGH']),
    scanners: pick('scanners', inputs.scanners, defaults.scanners ?? ['vuln', 'secret']),
    failOn: pick('failOn', inputs.failOn, defaults.failOn ?? 'CRITICAL'),
    ignoreUnfixed: pick('ignoreUnfixed', inputs.ignoreUnfixed, defaults.ignoreUnfixed ?? false),
    skipDbUpdate: pick('skipDbUpdate', inputs.skipDbUpdate, defaults.skipDbUpdate ?? false),
    timeoutMinutes: pick('timeoutMinutes', inputs.timeoutMinutes, defaults.timeoutMinutes ?? 10),
    dbRepository: defaults.dbRepository,
    javaDbRepository: defaults.javaDbRepository,
    cacheDir: defaults.cacheDir ?? path.posix.join(agent.agentHomeDir, '_trivy-cache'),
    sourcesDir: agent.sourcesDir,
    workingDirectory: inputs.workingDirectory,
    ignoreFile: inputs.ignoreFile,
    useDockerSocket: inputs.useDockerSocket ?? false,
    formats: inputs.formats ?? ['table', 'json'],
    generateSbom: inputs.generateSbom ?? 'off',
    publishArtifact: inputs.publishArtifact ?? true,
    extraTrivyArgs: inputs.extraTrivyArgs,
    buildId: agent.buildId,
    scanIndex,
  };
}

function selectRunner(runners: RunnerConfig[], requested: string | undefined): RunnerConfig {
  const usable = runners.filter((runner) => runner.enabled !== false);

  if (runners.length === 0) {
    throw new RunnerNotFoundError(
      'The collection has no runners configured. Add one in Collection Settings > Trivy Scanner > Runners.',
    );
  }

  if (requested) {
    const match = usable.find((runner) => runner.alias === requested);
    if (!match) {
      throw new RunnerNotFoundError(
        `Runner "${requested}" is not available. Enabled runners: ${usable
          .map((runner) => runner.alias)
          .join(', ')}.`,
      );
    }
    return match;
  }

  const fallback = usable.find((runner) => runner.isDefault);
  if (!fallback) {
    throw new RunnerNotFoundError(
      'No default runner is configured. Mark one runner as default in Collection Settings > Trivy Scanner > Runners, or set the "runner" input.',
    );
  }
  return fallback;
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/ConfigResolver.test.ts`
Expected: PASS, 10 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/ConfigResolver.ts src/task/__tests__/ConfigResolver.test.ts
git commit -m "feat: resolve scan config from defaults, catalog and inputs"
```

- [ ] **Step 6: Закрыть обход политики и связать `pick` с полем (по итогам ревью)**

Три поля доходили до `ResolvedScanConfig` мимо `pick`, и каждое отменяет политику:

- `extraTrivyArgs` дописывается после `--severity` и `--scanners`, а в cobra выигрывает последнее вхождение флага, так что `allowOverrides: []` не мешает пайплайну написать `--severity LOW --ignore-unfixed`;
- `ignoreFile` глушит находки через `.trivyignore` и обходит `failOn`;
- `useDockerSocket` монтирует docker-сокет — root на агенте.

Поэтому `OverridableField` расширяется этими тремя полями (см. Task 3), и все три идут через `pick`. `scanType` и `target` остаются вне политики намеренно, как и `formats`, `generateSbom`, `publishArtifact`, `workingDirectory`.

Заодно чинится сам `pick`: сейчас `pick('severities', inputs.failOn, ...)` компилируется, то есть ключ политики и значение можно случайно взять из разных полей — гейт встанет не на то поле и сообщение назовёт не то имя. Ключ связывается со значением через `F extends OverridableField & keyof TaskInputs`, а `ALL_OVERRIDABLE` выводится из литерала с `satisfies Record<OverridableField, ...>`, иначе список молча расходится с союзом и новое поле оказывается непереопределяемым даже при опущенном `allowOverrides`. Проверка присутствия остаётся `=== undefined`: явный `false` из пайплайна должен побеждать.

Сообщения: пустой список включённых раннеров не печатается как `Enabled runners: .`; отключённый раннер по умолчанию описывается теми же словами, что в `validateCatalog`, а не советом «пометьте раннер по умолчанию»; опечатка в алиасе отличается от намеренно отключённого раннера; `PolicyViolationError` называет действующее значение; `runner: ''` считается отсутствующим. Все нарушения политики собираются и сообщаются одним исключением, иначе пайплайн чинит их по одному за сборку.

Тесты: мутационное тестирование показало 14 регрессий, проходящих весь набор, — в том числе замена `useDockerSocket ?? false` на `?? true`, монтирующая docker-сокет в каждую сборку. Закрывается двумя проверками целиком собранного объекта: на минимальном входе (фиксирует все встроенные умолчания) и на полностью заполненных `defaults` и `inputs` при разрешающей политике (фиксирует все pass-through и приоритеты).

---

## Task 7: Построение команды docker

Самый важный чистый модуль: он определяет, что реально уйдёт в процесс.

**Files:**
- Create: `src/task/DockerCommand.ts`
- Test: `src/task/__tests__/DockerCommand.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import {
  buildScanArgs,
  buildVersionArgs,
  buildTrivyEnv,
  containerReportPath,
  hostReportPath,
} from '../DockerCommand';
import { ResolvedScanConfig } from '../../shared/types';

const config = (over: Partial<ResolvedScanConfig> = {}): ResolvedScanConfig => ({
  runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
  scanType: 'image',
  target: 'app:1.4.2',
  severities: ['CRITICAL', 'HIGH'],
  scanners: ['vuln', 'secret'],
  failOn: 'CRITICAL',
  ignoreUnfixed: false,
  skipDbUpdate: false,
  timeoutMinutes: 10,
  dbRepository: 'registry.example.com/trivy-db:2',
  cacheDir: '/agent/_trivy-cache',
  sourcesDir: '/agent/_work/1/s',
  useDockerSocket: false,
  formats: ['table', 'json'],
  generateSbom: 'off',
  publishArtifact: true,
  buildId: '1042',
  scanIndex: 0,
  ...over,
});

describe('buildScanArgs', () => {
  it('mounts the cache and the sources and runs the runner image', () => {
    const args = buildScanArgs(config(), '/tmp/trivy.env');
    expect(args).toEqual([
      'run',
      '--rm',
      '--name',
      'trivyscan-1042-0',
      '--env-file',
      '/tmp/trivy.env',
      '-v',
      '/agent/_trivy-cache:/root/.cache/trivy',
      '-v',
      '/agent/_work/1/s:/workspace',
      '-w',
      '/workspace',
      'registry.example.com/trivy:0.58.1',
      'image',
      '--format',
      'json',
      '--output',
      '/workspace/.trivy/report-0.json',
      '--exit-code',
      '0',
      '--severity',
      'CRITICAL,HIGH',
      '--scanners',
      'vuln,secret',
      '--timeout',
      '10m',
      'app:1.4.2',
    ]);
  });

  it('never places a secret in argv', () => {
    const args = buildScanArgs(config(), '/tmp/trivy.env');
    expect(args.join(' ')).not.toMatch(/password|token/i);
  });

  it('mounts the docker socket only when asked', () => {
    expect(buildScanArgs(config(), '/tmp/e').join(' ')).not.toContain('docker.sock');
    expect(buildScanArgs(config({ useDockerSocket: true }), '/tmp/e')).toContain(
      '/var/run/docker.sock:/var/run/docker.sock',
    );
  });

  it('inserts extra docker args before the image and extra trivy args after the flags', () => {
    const args = buildScanArgs(
      config({
        runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', extraDockerArgs: '--network none' },
        extraTrivyArgs: '--offline-scan',
      }),
      '/tmp/e',
    );
    expect(args.indexOf('--network')).toBeLessThan(args.indexOf('registry.example.com/trivy:0.58.1'));
    expect(args.indexOf('--offline-scan')).toBeGreaterThan(args.indexOf('--timeout'));
    expect(args[args.length - 1]).toBe('app:1.4.2');
  });

  it('adds ignore-unfixed and skip-db-update flags when enabled', () => {
    const args = buildScanArgs(config({ ignoreUnfixed: true, skipDbUpdate: true }), '/tmp/e');
    expect(args).toContain('--ignore-unfixed');
    expect(args).toContain('--skip-db-update');
  });

  it('passes the ignore file through its container path', () => {
    const args = buildScanArgs(config({ ignoreFile: '.trivyignore' }), '/tmp/e');
    expect(args.slice(args.indexOf('--ignorefile'), args.indexOf('--ignorefile') + 2)).toEqual([
      '--ignorefile',
      '/workspace/.trivyignore',
    ]);
  });

  it('omits the scanners flag for a config scan because trivy config rejects it', () => {
    const args = buildScanArgs(config({ scanType: 'config', target: './infra' }), '/tmp/e');
    expect(args).not.toContain('--scanners');
    expect(args[args.length - 1]).toBe('./infra');
  });

  it('gives each scan in a build its own container name and report file', () => {
    const args = buildScanArgs(config({ scanIndex: 3 }), '/tmp/e');
    expect(args).toContain('trivyscan-1042-3');
    expect(args).toContain('/workspace/.trivy/report-3.json');
  });
});

describe('buildVersionArgs', () => {
  it('asks the runner image for its trivy and database version as json', () => {
    expect(buildVersionArgs(config())).toEqual([
      'run',
      '--rm',
      '-v',
      '/agent/_trivy-cache:/root/.cache/trivy',
      'registry.example.com/trivy:0.58.1',
      'version',
      '--format',
      'json',
    ]);
  });
});

describe('buildTrivyEnv', () => {
  it('points trivy at the internal database mirror and cache', () => {
    expect(buildTrivyEnv(config(), {})).toMatchObject({
      TRIVY_DB_REPOSITORY: 'registry.example.com/trivy-db:2',
      TRIVY_CACHE_DIR: '/root/.cache/trivy',
      TRIVY_NO_PROGRESS: 'true',
    });
  });

  it('includes the java database mirror only when configured', () => {
    expect(buildTrivyEnv(config(), {})).not.toHaveProperty('TRIVY_JAVA_DB_REPOSITORY');
    expect(
      buildTrivyEnv(config({ javaDbRepository: 'registry.example.com/trivy-java-db:1' }), {}),
    ).toMatchObject({ TRIVY_JAVA_DB_REPOSITORY: 'registry.example.com/trivy-java-db:1' });
  });

  it('carries registry credentials for the scanned image', () => {
    expect(buildTrivyEnv(config(), { username: 'svc', password: 'p@ss' })).toMatchObject({
      TRIVY_USERNAME: 'svc',
      TRIVY_PASSWORD: 'p@ss',
    });
  });
});

describe('report paths', () => {
  it('maps the container report path onto the host workspace', () => {
    expect(containerReportPath(config({ scanIndex: 1 }))).toBe('/workspace/.trivy/report-1.json');
    expect(hostReportPath(config({ scanIndex: 1 }))).toBe(
      '/agent/_work/1/s/.trivy/report-1.json',
    );
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/DockerCommand.test.ts`
Expected: FAIL — `Cannot find module '../DockerCommand'`.

- [ ] **Step 3: Реализовать `src/task/DockerCommand.ts`**

```ts
import * as path from 'path';
import { splitArgs } from '../shared/args';
import { ResolvedScanConfig } from '../shared/types';

const WORKSPACE = '/workspace';
const CACHE_MOUNT = '/root/.cache/trivy';

export interface RegistryCredentials {
  username?: string;
  password?: string;
}

export function containerName(config: ResolvedScanConfig): string {
  return `trivyscan-${config.buildId}-${config.scanIndex}`;
}

export function containerReportPath(config: ResolvedScanConfig): string {
  return `${WORKSPACE}/.trivy/report-${config.scanIndex}.json`;
}

export function hostReportPath(config: ResolvedScanConfig): string {
  return path.posix.join(config.sourcesDir, '.trivy', `report-${config.scanIndex}.json`);
}

export function buildScanArgs(config: ResolvedScanConfig, envFilePath: string): string[] {
  const docker = [
    'run',
    '--rm',
    '--name',
    containerName(config),
    '--env-file',
    envFilePath,
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    '-v',
    `${config.sourcesDir}:${WORKSPACE}`,
    '-w',
    config.workingDirectory ? path.posix.join(WORKSPACE, config.workingDirectory) : WORKSPACE,
  ];

  if (config.useDockerSocket) {
    docker.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  }

  docker.push(...splitArgs(config.runner.extraDockerArgs), config.runner.image);

  const trivy = [
    config.scanType,
    '--format',
    'json',
    '--output',
    containerReportPath(config),
    '--exit-code',
    '0',
    '--severity',
    config.severities.join(','),
  ];

  // trivy config has no --scanners flag: it always runs the misconfiguration scanner.
  if (config.scanType !== 'config') {
    trivy.push('--scanners', config.scanners.join(','));
  }

  if (config.ignoreUnfixed) {
    trivy.push('--ignore-unfixed');
  }
  if (config.skipDbUpdate) {
    trivy.push('--skip-db-update');
  }

  trivy.push('--timeout', `${config.timeoutMinutes}m`);

  if (config.ignoreFile) {
    trivy.push('--ignorefile', path.posix.join(WORKSPACE, config.ignoreFile));
  }

  trivy.push(...splitArgs(config.extraTrivyArgs), config.target);

  return [...docker, ...trivy];
}

export function buildVersionArgs(config: ResolvedScanConfig): string[] {
  return [
    'run',
    '--rm',
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    config.runner.image,
    'version',
    '--format',
    'json',
  ];
}

export function buildTrivyEnv(
  config: ResolvedScanConfig,
  credentials: RegistryCredentials,
): Record<string, string> {
  const env: Record<string, string> = {
    TRIVY_DB_REPOSITORY: config.dbRepository,
    TRIVY_CACHE_DIR: CACHE_MOUNT,
    TRIVY_NO_PROGRESS: 'true',
  };

  if (config.javaDbRepository) {
    env.TRIVY_JAVA_DB_REPOSITORY = config.javaDbRepository;
  }
  if (credentials.username) {
    env.TRIVY_USERNAME = credentials.username;
  }
  if (credentials.password) {
    env.TRIVY_PASSWORD = credentials.password;
  }

  return env;
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/DockerCommand.test.ts`
Expected: PASS, 13 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/DockerCommand.ts src/task/__tests__/DockerCommand.test.ts
git commit -m "feat: build docker run arguments and trivy environment"
```

- [ ] **Step 6: Защитить инварианты от `extraTrivyArgs` и путей-побегов (по итогам ревью)**

Порядок аргументов в этом модуле — не косметика: trivy построен на cobra, где из двух одинаковых скалярных флагов выигрывает последний, а `extraTrivyArgs` дописывается в конец. Из-за этого пайплайн мог поставить `--exit-code 1` (гейт возвращается внутрь trivy, `failOn: 'none'` перестаёт означать «никогда не падать»), `--format table` или другой `--output` (парсер получает не тот файл и падает невнятно), а также включить `--ignore-unfixed` и `--skip-db-update` — оба поля политики, то есть запертое админом обходится.

Закрывается двумя дополняющими мерами:

- `--format json`, `--output` и `--exit-code 0` переутверждаются **после** `extraTrivyArgs`; позиционной остаётся только цель. Что бы ни написал пайплайн, контракт парсера и гейта выигрывает;
- зарезервированные флаги в `extraTrivyArgs` отвергаются: `--format`/`-f`, `--output`/`-o`, `--exit-code`, `--severity`/`-s`, `--scanners`, `--ignore-unfixed`, `--skip-db-update`, `--ignorefile`, `--timeout`, в написании и через пробел, и через `=`. Сообщение называет флаг и говорит, каким input он управляется.

`workingDirectory` и `ignoreFile` после `path.posix.join` с `/workspace` нормализуются, и результат обязан остаться внутри `/workspace`, иначе — исключение с указанием поля. Не обрезка, а отказ: тихая обрезка спрятала бы ошибку, а её последствие — ложный негатив (скан `filesystem` с целью `.` уходит в образ-раннер и проходит гейт чистым).

`cacheDir` валидируется в `validateDefaults` (Task 5): строка, абсолютный путь, не корень и не корневой каталог вроде `/etc`. Значение уезжает в `-v`, и `cacheDir: "/"` смонтировал бы корень хоста в контейнер на запись.

Тесты, которых не хватало: `workingDirectory: 'subdir'` действительно даёт `-w /workspace/subdir` (удаление всей поддержки `workingDirectory` до этого проходило все 113 тестов); `--exit-code 0` и `--format json` проверяются отдельными утверждениями, а не только внутри golden-массива, иначе законная перегенерация массива молча снимает оба инварианта. Рядом с местом, где `extraDockerArgs` вставляется в argv, ставится комментарий о границе доверия: это поле недоступно из пайплайна и намеренно не ограничивается, потому что тот же администратор выбирает сам образ раннера и уже может запустить на агенте что угодно.

---

## Task 8: Временный env-файл с секретами

**Files:**
- Create: `src/task/EnvFile.ts`
- Test: `src/task/__tests__/EnvFile.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { removeEnvFile, writeEnvFile } from '../EnvFile';

describe('writeEnvFile', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envfile-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('writes one KEY=value line per entry', () => {
    const file = writeEnvFile(dir, 'scan-0', { TRIVY_DB_REPOSITORY: 'reg/db:2', TRIVY_USERNAME: 'svc' });
    expect(fs.readFileSync(file, 'utf8')).toBe('TRIVY_DB_REPOSITORY=reg/db:2\nTRIVY_USERNAME=svc\n');
  });

  it('creates the file readable only by the owner', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it('rejects a value containing a newline because docker env-file cannot express it', () => {
    expect(() => writeEnvFile(dir, 'scan-0', { A: 'line1\nline2' })).toThrow(/newline/i);
  });

  it('removes the file and stays silent when it is already gone', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    removeEnvFile(file);
    expect(fs.existsSync(file)).toBe(false);
    expect(() => removeEnvFile(file)).not.toThrow();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/EnvFile.test.ts`
Expected: FAIL — `Cannot find module '../EnvFile'`.

- [ ] **Step 3: Реализовать `src/task/EnvFile.ts`**

```ts
import * as fs from 'fs';
import * as path from 'path';

export function writeEnvFile(dir: string, name: string, env: Record<string, string>): string {
  const lines = Object.entries(env).map(([key, value]) => {
    if (value.includes('\n')) {
      throw new Error(`Value of ${key} contains a newline, which a docker env-file cannot express.`);
    }
    return `${key}=${value}`;
  });

  const file = path.join(dir, `trivy-${name}.env`);
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

export function removeEnvFile(file: string): void {
  fs.rmSync(file, { force: true });
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/EnvFile.test.ts`
Expected: PASS, 4 теста.

- [ ] **Step 5: Commit**

```bash
git add src/task/EnvFile.ts src/task/__tests__/EnvFile.test.ts
git commit -m "feat: owner-only env file for trivy secrets"
```

- [ ] **Step 6: Защитить путь записи (по итогам ревью)**

Показанный выше `writeFileSync` следует за символической ссылкой: подложенный по этому пути симлинк увёл бы пароль к registry в чужой файл, который заодно получил бы права 0600. Файл открывается вручную с `O_NOFOLLOW`, права выставляются через `fchmodSync` на уже открытом дескрипторе — `chmodSync` по пути заново его разрешает, оставляя окно на подмену между закрытием и сменой прав.

`O_NOFOLLOW` не спасает от **жёсткой** ссылки: предусловие то же самое (чужой процесс может создавать имена во временном каталоге агента), поэтому путь либо предварительно удаляется и открывается с `O_EXCL`, либо проверяется через `fstatSync` на `nlink !== 1`. Права сужаются **до** записи: на уже существующем файле с правами 0644 `O_TRUNC` их не меняет, и запись прошла бы в 0644.

`removeEnvFile` не имеет права бросать исключение: он вызывается в `finally`, и `force: true` глушит только `ENOENT` — на `EACCES` или блокировке антивирусом реальная причина падения скана подменилась бы ошибкой удаления, а файл с паролем остался бы на диске.

Проверка `mode` при создании ничего не гарантирует сама по себе: umask её только сужает, но на существующем файле она вовсе игнорируется. Единственная гарантия — `fchmod`, и в наборе тестов должен быть тест, который отличает `fchmod(fd)` от `chmod(path)`, иначе вся эта защита для набора невидима.

---

## Task 9: Фикстуры вывода trivy и парсер отчёта

**Files:**
- Create: `test/fixtures/trivy/image-vulns.json`, `test/fixtures/trivy/empty.json`, `test/fixtures/trivy/secrets-and-misconfig.json`, `test/fixtures/trivy/version.json`
- Create: `src/task/ReportParser.ts`
- Test: `src/task/__tests__/ReportParser.test.ts`

Фикстуры ниже соответствуют схеме trivy `SchemaVersion: 2`. Когда появится доступ к раннеру, перегенерируйте их реальным запуском (`docker run --rm registry.example.com/trivy:0.58.1 image --format json alpine:3.19`) и убедитесь, что тесты по-прежнему проходят — это и есть проверка, что мы читаем настоящий формат.

- [ ] **Step 1: Создать `test/fixtures/trivy/image-vulns.json`**

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-07-28T09:12:44.512Z",
  "ArtifactName": "app:1.4.2",
  "ArtifactType": "container_image",
  "Metadata": { "OS": { "Family": "debian", "Name": "12.5" } },
  "Results": [
    {
      "Target": "app:1.4.2 (debian 12.5)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-21626",
          "PkgName": "runc",
          "InstalledVersion": "1.1.7-0+deb12u1",
          "FixedVersion": "1.1.12-0+deb12u1",
          "Severity": "CRITICAL",
          "Title": "runc: file descriptor leak allows container escape"
        },
        {
          "VulnerabilityID": "CVE-2023-45853",
          "PkgName": "zlib1g",
          "InstalledVersion": "1:1.2.13.dfsg-1",
          "Severity": "CRITICAL",
          "Title": "zlib: integer overflow in zipOpenNewFileInZip4_64"
        },
        {
          "VulnerabilityID": "CVE-2024-2961",
          "PkgName": "libc6",
          "InstalledVersion": "2.36-9+deb12u4",
          "FixedVersion": "2.36-9+deb12u7",
          "Severity": "HIGH",
          "Title": "glibc: out of bounds write in iconv"
        },
        {
          "VulnerabilityID": "CVE-2023-4641",
          "PkgName": "passwd",
          "InstalledVersion": "1:4.13+dfsg1-1",
          "Severity": "MEDIUM",
          "Title": "shadow-utils: possible password leak"
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Создать `test/fixtures/trivy/empty.json`**

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-07-28T09:20:01.004Z",
  "ArtifactName": "app:1.4.3",
  "ArtifactType": "container_image",
  "Results": []
}
```

- [ ] **Step 3: Создать `test/fixtures/trivy/secrets-and-misconfig.json`**

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-07-28T09:31:17.220Z",
  "ArtifactName": ".",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "deploy/values.yaml",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "aws-access-key-id",
          "Category": "AWS",
          "Severity": "CRITICAL",
          "Title": "AWS Access Key ID",
          "StartLine": 14
        }
      ]
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": { "Successes": 21, "Failures": 1 },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "Image user should not be 'root'",
          "Severity": "HIGH",
          "Status": "FAIL"
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS026",
          "Title": "No HEALTHCHECK defined",
          "Severity": "LOW",
          "Status": "PASS"
        }
      ]
    }
  ]
}
```

- [ ] **Step 4: Создать `test/fixtures/trivy/version.json`**

```json
{
  "Version": "0.58.1",
  "VulnerabilityDB": {
    "Version": 2,
    "UpdatedAt": "2026-07-28T06:11:53.123456789Z",
    "NextUpdate": "2026-07-28T12:11:53.123456789Z"
  }
}
```

- [ ] **Step 5: Написать падающий тест `src/task/__tests__/ReportParser.test.ts`**

```ts
import * as fs from 'fs';
import * as path from 'path';
import { parseTrivyReport, parseVersion, TrivyReportParseError } from '../ReportParser';

const fixture = (name: string): string =>
  fs.readFileSync(path.join(__dirname, '../../../test/fixtures/trivy', name), 'utf8');

const meta = { scanType: 'image' as const, target: 'app:1.4.2', runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' } };

describe('parseTrivyReport', () => {
  it('flattens vulnerabilities from every result into findings', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.findings).toHaveLength(4);
    expect(report.findings[0]).toEqual({
      kind: 'vulnerability',
      severity: 'CRITICAL',
      id: 'CVE-2024-21626',
      title: 'runc: file descriptor leak allows container escape',
      target: 'app:1.4.2 (debian 12.5)',
      pkgName: 'runc',
      installedVersion: '1.1.7-0+deb12u1',
      fixedVersion: '1.1.12-0+deb12u1',
    });
  });

  it('counts findings per severity', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.counts).toEqual({ UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 2 });
  });

  it('counts findings per kind', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.kindCounts).toEqual({
      vulnerability: 4,
      secret: 0,
      misconfiguration: 0,
      license: 0,
    });
  });

  it('carries artifact name and creation time from the report', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.artifactName).toBe('app:1.4.2');
    expect(report.createdAt).toBe('2026-07-28T09:12:44.512Z');
  });

  it('returns an empty report with zeroed counts when nothing was found', () => {
    const report = parseTrivyReport(fixture('empty.json'), meta);
    expect(report.findings).toEqual([]);
    expect(report.counts.CRITICAL).toBe(0);
  });

  it('reads secrets and keeps their file location', () => {
    const report = parseTrivyReport(fixture('secrets-and-misconfig.json'), meta);
    const secret = report.findings.find((finding) => finding.kind === 'secret');
    expect(secret).toEqual({
      kind: 'secret',
      severity: 'CRITICAL',
      id: 'aws-access-key-id',
      title: 'AWS Access Key ID',
      target: 'deploy/values.yaml',
      location: 'deploy/values.yaml:14',
    });
  });

  it('reads only failing misconfigurations', () => {
    const report = parseTrivyReport(fixture('secrets-and-misconfig.json'), meta);
    const misconfigurations = report.findings.filter(
      (finding) => finding.kind === 'misconfiguration',
    );
    expect(misconfigurations).toEqual([
      {
        kind: 'misconfiguration',
        severity: 'HIGH',
        id: 'DS002',
        title: "Image user should not be 'root'",
        target: 'Dockerfile',
      },
    ]);
  });

  it('rejects malformed json with the runner and target in the message', () => {
    expect(() => parseTrivyReport('{not json', meta)).toThrow(TrivyReportParseError);
    expect(() => parseTrivyReport('{not json', meta)).toThrow(/registry.example.com\/trivy:0.58.1/);
  });

  it('rejects a json document that is not a trivy report', () => {
    expect(() => parseTrivyReport('{"hello":"world"}', meta)).toThrow(/Results/);
  });
});

describe('parseVersion', () => {
  it('extracts the trivy version and the database timestamp', () => {
    expect(parseVersion(fixture('version.json'))).toEqual({
      trivyVersion: '0.58.1',
      dbUpdatedAt: '2026-07-28T06:11:53.123456789Z',
    });
  });

  it('returns an empty object when the output cannot be parsed', () => {
    expect(parseVersion('not json')).toEqual({});
  });
});
```

- [ ] **Step 6: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/ReportParser.test.ts`
Expected: FAIL — `Cannot find module '../ReportParser'`.

- [ ] **Step 7: Реализовать `src/task/ReportParser.ts`**

```ts
import { emptyKindCounts } from '../shared/findingKind';
import { emptySeverityCounts, isSeverity } from '../shared/severity';
import { Finding, NormalizedReport, RunnerInfo, ScanType, Severity } from '../shared/types';

export class TrivyReportParseError extends Error {}

export interface ReportMeta {
  scanType: ScanType;
  target: string;
  runner: RunnerInfo;
}

interface RawResult {
  Target?: string;
  Vulnerabilities?: RawVulnerability[];
  Secrets?: RawSecret[];
  Misconfigurations?: RawMisconfiguration[];
  Licenses?: RawLicense[];
}

interface RawVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
}

interface RawSecret {
  RuleID?: string;
  Title?: string;
  Severity?: string;
  StartLine?: number;
}

interface RawMisconfiguration {
  ID?: string;
  Title?: string;
  Severity?: string;
  Status?: string;
}

interface RawLicense {
  Name?: string;
  PkgName?: string;
  Severity?: string;
  Category?: string;
}

function toSeverity(raw: string | undefined): Severity {
  const value = (raw ?? '').toUpperCase();
  return isSeverity(value) ? value : 'UNKNOWN';
}

export function parseTrivyReport(raw: string, meta: ReportMeta): NormalizedReport {
  let document: { Results?: RawResult[]; ArtifactName?: string; CreatedAt?: string };
  try {
    document = JSON.parse(raw);
  } catch (error) {
    throw new TrivyReportParseError(
      `Runner ${meta.runner.image} produced output that is not valid JSON while scanning "${meta.target}": ${
        (error as Error).message
      }`,
    );
  }

  if (!Array.isArray(document.Results)) {
    throw new TrivyReportParseError(
      `Runner ${meta.runner.image} produced JSON without a "Results" array while scanning "${meta.target}". Check that the image really contains trivy.`,
    );
  }

  const findings: Finding[] = [];

  for (const result of document.Results) {
    const target = result.Target ?? meta.target;

    for (const item of result.Vulnerabilities ?? []) {
      findings.push({
        kind: 'vulnerability',
        severity: toSeverity(item.Severity),
        id: item.VulnerabilityID ?? 'UNKNOWN',
        title: item.Title ?? item.VulnerabilityID ?? 'Unknown vulnerability',
        target,
        pkgName: item.PkgName,
        installedVersion: item.InstalledVersion,
        ...(item.FixedVersion ? { fixedVersion: item.FixedVersion } : {}),
      });
    }

    for (const item of result.Secrets ?? []) {
      findings.push({
        kind: 'secret',
        severity: toSeverity(item.Severity),
        id: item.RuleID ?? 'UNKNOWN',
        title: item.Title ?? item.RuleID ?? 'Unknown secret',
        target,
        location: item.StartLine ? `${target}:${item.StartLine}` : target,
      });
    }

    for (const item of result.Misconfigurations ?? []) {
      if (item.Status !== 'FAIL') {
        continue;
      }
      findings.push({
        kind: 'misconfiguration',
        severity: toSeverity(item.Severity),
        id: item.ID ?? 'UNKNOWN',
        title: item.Title ?? item.ID ?? 'Unknown misconfiguration',
        target,
      });
    }

    for (const item of result.Licenses ?? []) {
      findings.push({
        kind: 'license',
        severity: toSeverity(item.Severity),
        id: item.Name ?? 'UNKNOWN',
        title: `${item.Category ?? 'license'}: ${item.Name ?? 'unknown'}`,
        target,
        pkgName: item.PkgName,
      });
    }
  }

  const counts = emptySeverityCounts();
  const kindCounts = emptyKindCounts();

  for (const finding of findings) {
    counts[finding.severity] += 1;
    kindCounts[finding.kind] += 1;
  }

  return {
    schemaVersion: 1,
    scanType: meta.scanType,
    target: meta.target,
    artifactName: document.ArtifactName ?? meta.target,
    createdAt: document.CreatedAt,
    runner: meta.runner,
    findings,
    counts,
    kindCounts,
  };
}

export function parseVersion(raw: string): { trivyVersion?: string; dbUpdatedAt?: string } {
  try {
    const document = JSON.parse(raw) as {
      Version?: string;
      VulnerabilityDB?: { UpdatedAt?: string };
    };
    return {
      ...(document.Version ? { trivyVersion: document.Version } : {}),
      ...(document.VulnerabilityDB?.UpdatedAt ? { dbUpdatedAt: document.VulnerabilityDB.UpdatedAt } : {}),
    };
  } catch {
    return {};
  }
}
```

- [ ] **Step 8: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/ReportParser.test.ts`
Expected: PASS, 11 тестов.

- [ ] **Step 9: Commit**

```bash
git add test/fixtures/trivy src/task/ReportParser.ts src/task/__tests__/ReportParser.test.ts
git commit -m "feat: normalize trivy json reports and version output"
```

- [ ] **Step 10: Обеззараживание и устойчивость к кривому JSON (по итогам ревью)**

Текстовые поля находок обеззараживаются на входе в модель: управляющие символы схлопываются в пробел. Причина — имена пакетов и версии в сканах `filesystem` и `repository` берутся из lock-файлов, то есть их содержимое контролирует автор зависимости, а дальше они попадают в logging-команды Azure Pipelines, где строка, начинающаяся с `##vso[`, исполняется агентом. Это одна половина защиты; вторая — экранирование в `Publisher` в момент сборки команды.

Обеззараживание распространяется и на `artifactName`, `createdAt` и вывод `parseVersion`: они уходят во вкладку результатов и в сводку. Отдельно важно, что значения могут оказаться не строками — `{"Version": 42}` от враждебного образа раннера роняло таск уже **после** успешного скана.

Модуль обязан завершаться либо валидным отчётом, либо `TrivyReportParseError`. Мимо этого контракта проходили: документ-`null`, `null` внутри `Results`, нестроковые `PkgName`/`Title`/`Severity` и `Vulnerabilities: 42`. Хуже всех — `Vulnerabilities: "abc"`: строка итерируема, поэтому вместо ошибки получались три находки-призрака.

Понижение неизвестной severity до `UNKNOWN` остаётся (вывод trivy — не наш формат данных, и одна незнакомая метка не повод выбрасывать результат скана), но перестаёт быть безмолвным: `FailOn` исключает `UNKNOWN`, а сам он ниже всех, поэтому переименование метки в новой версии trivy сделало бы такие находки структурно неспособными завалить сборку — незаметно. Нераспознанные метки собираются и отдаются вызывающему для предупреждения.

---

## Task 10: Гейт сборки

**Files:**
- Create: `src/task/GateEvaluator.ts`
- Test: `src/task/__tests__/GateEvaluator.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import { evaluateGate } from '../GateEvaluator';
import { Finding, NormalizedReport, Severity } from '../../shared/types';

const finding = (severity: Severity, id: string): Finding => ({
  kind: 'vulnerability',
  severity,
  id,
  title: `${id} title`,
  target: 'app:1.4.2',
});

const report = (findings: Finding[]): NormalizedReport => {
  const counts = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  findings.forEach((item) => (counts[item.severity] += 1));
  return {
    schemaVersion: 1,
    scanType: 'image',
    target: 'app:1.4.2',
    artifactName: 'app:1.4.2',
    runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
    findings,
    counts,
    kindCounts: { vulnerability: findings.length, secret: 0, misconfiguration: 0, license: 0 },
  };
};

describe('evaluateGate', () => {
  it('succeeds on a clean report', () => {
    const result = evaluateGate(report([]), 'CRITICAL');
    expect(result.outcome).toBe('succeeded');
    expect(result.blocking).toEqual([]);
  });

  it('fails when a finding reaches the threshold', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'CRITICAL');
    expect(result.outcome).toBe('failed');
    expect(result.blocking).toHaveLength(1);
  });

  it('counts every finding at or above the threshold as blocking', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('HIGH', 'CVE-2'), finding('LOW', 'CVE-3')]),
      'HIGH',
    );
    expect(result.blocking.map((item) => item.id)).toEqual(['CVE-1', 'CVE-2']);
  });

  it('warns instead of failing when findings stay below the threshold', () => {
    const result = evaluateGate(report([finding('MEDIUM', 'CVE-1')]), 'CRITICAL');
    expect(result.outcome).toBe('succeededWithIssues');
  });

  it('succeeds regardless of findings when the gate is disabled', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'none');
    expect(result.outcome).toBe('succeeded');
    expect(result.reason).toMatch(/gate is disabled/i);
  });

  it('explains a failure with the counts that crossed the threshold', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('CRITICAL', 'CVE-2'), finding('HIGH', 'CVE-3')]),
      'HIGH',
    );
    expect(result.reason).toBe('2 CRITICAL, 1 HIGH at or above the failOn threshold HIGH');
  });

  it('explains a warning with the total number of findings', () => {
    const result = evaluateGate(report([finding('LOW', 'CVE-1')]), 'CRITICAL');
    expect(result.reason).toBe('1 finding below the failOn threshold CRITICAL');
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/GateEvaluator.test.ts`
Expected: FAIL — `Cannot find module '../GateEvaluator'`.

- [ ] **Step 3: Реализовать `src/task/GateEvaluator.ts`**

```ts
import { isAtLeast, SEVERITY_ORDER } from '../shared/severity';
import { FailOn, Finding, NormalizedReport } from '../shared/types';

export type GateOutcome = 'succeeded' | 'succeededWithIssues' | 'failed';

export interface GateResult {
  outcome: GateOutcome;
  reason: string;
  blocking: Finding[];
}

export function evaluateGate(report: NormalizedReport, failOn: FailOn): GateResult {
  if (failOn === 'none') {
    return {
      outcome: 'succeeded',
      reason: `${report.findings.length} finding(s) reported, the gate is disabled (failOn: none)`,
      blocking: [],
    };
  }

  const blocking = report.findings.filter((finding) => isAtLeast(finding.severity, failOn));

  if (blocking.length === 0) {
    if (report.findings.length === 0) {
      return { outcome: 'succeeded', reason: 'No findings', blocking: [] };
    }
    const noun = report.findings.length === 1 ? 'finding' : 'findings';
    return {
      outcome: 'succeededWithIssues',
      reason: `${report.findings.length} ${noun} below the failOn threshold ${failOn}`,
      blocking: [],
    };
  }

  const breakdown = [...SEVERITY_ORDER]
    .reverse()
    .map((severity) => ({ severity, count: blocking.filter((f) => f.severity === severity).length }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`)
    .join(', ');

  return {
    outcome: 'failed',
    reason: `${breakdown} at or above the failOn threshold ${failOn}`,
    blocking,
  };
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/GateEvaluator.test.ts`
Expected: PASS, 7 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/GateEvaluator.ts src/task/__tests__/GateEvaluator.test.ts
git commit -m "feat: evaluate build gate from normalized report"
```

- [ ] **Step 6: Порядок, структура и словарь порога (по итогам ревью)**

- `blocking` возвращается отсортированным по убыванию severity. В порядке отчёта при 40 MEDIUM и 3 CRITICAL публикатор, режущий список на 20, выпишет двадцать MEDIUM, а все CRITICAL уедут в строчку «и ещё N»; вкладка отрендерит тот же список с тем же эффектом.
- Сообщение о падении добавляет общее число находок: `2 CRITICAL at or above the failOn threshold CRITICAL (502 findings total)`. Иначе ветка падения считает только блокирующие, ветка предупреждения — все, и читатель не знает, какой знаменатель перед ним.
- `GateResult` отдаёт не только готовую английскую строку, но и разобранные части: `threshold`, `blockingCounts: SeverityCounts`, `blockingKindCounts: KindCounts`. Строку `reason` нужно показать и в текстовой сводке сборки, и в HTML-шапке вкладки, а перестроить её они не могут, не разбирая английский текст. Счётчики по видам важны отдельно: на CRITICAL-секрет и CRITICAL-CVE реакция совершенно разная — ротировать учётку против обновить пакет.
- `failOn: 'UNKNOWN'` убирается на уровне типа (`Exclude<Severity, 'UNKNOWN'>`): `isAtLeast(x, 'UNKNOWN')` истинно для любой severity, то есть это самый строгий порог из возможных, тогда как в выпадающем списке администратор прочитает его как «падать только на неоценённых находках» — ровно наоборот. Отдельным док-комментарием фиксируется и обратное решение: находка с `UNKNOWN` не блокирует гейт `CRITICAL`, хотя «trivy не смог оценить» не то же самое, что «не важно».

Тесты, которых не хватало: `blocking` пуст при `failOn: 'none'` (без этого отключённый гейт напишет двадцать красных issue в сборку), множественное число в ветке предупреждения, и хоть какое-то покрытие `UNKNOWN`.

---

## Task 11: Запуск процессов

**Files:**
- Create: `src/task/ProcessRunner.ts`
- Test: `src/task/__tests__/ProcessRunner.test.ts`

Тесты запускают `process.execPath` (сам node), поэтому не зависят ни от docker, ни от платформы.

- [ ] **Step 1: Написать падающий тест**

```ts
import { ChildProcessRunner } from '../ProcessRunner';

const runner = new ChildProcessRunner();

describe('ChildProcessRunner', () => {
  it('captures stdout and a zero exit code', async () => {
    const result = await runner.run(process.execPath, ['-e', 'process.stdout.write("hello")']);
    expect(result).toMatchObject({ exitCode: 0, stdout: 'hello', timedOut: false });
  });

  it('captures stderr and a non-zero exit code without throwing', async () => {
    const result = await runner.run(process.execPath, [
      '-e',
      'process.stderr.write("boom"); process.exit(3)',
    ]);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain('boom');
  });

  it('kills a process that outlives its timeout and reports it', async () => {
    const result = await runner.run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], {
      timeoutMs: 200,
    });
    expect(result.timedOut).toBe(true);
    expect(result.exitCode).not.toBe(0);
  });

  it('writes stdin to the process when provided', async () => {
    const result = await runner.run(
      process.execPath,
      ['-e', 'process.stdin.on("data", (d) => process.stdout.write("got:" + d))'],
      { stdin: 'secret' },
    );
    expect(result.stdout).toBe('got:secret');
  });

  it('reports a missing executable as a failed result instead of rejecting', async () => {
    const result = await runner.run('definitely-not-a-real-binary-9182', []);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/ENOENT|not found/i);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/ProcessRunner.test.ts`
Expected: FAIL — `Cannot find module '../ProcessRunner'`.

- [ ] **Step 3: Реализовать `src/task/ProcessRunner.ts`**

```ts
import { spawn } from 'child_process';

export interface RunOptions {
  timeoutMs?: number;
  stdin?: string;
  cwd?: string;
  onStdout?: (chunk: string) => void;
}

export interface ProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ProcessRunner {
  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult>;
}

export class ChildProcessRunner implements ProcessRunner {
  run(command: string, args: string[], options: RunOptions = {}): Promise<ProcessResult> {
    return new Promise((resolve) => {
      const child = spawn(command, args, { cwd: options.cwd });
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const timer = options.timeoutMs
        ? setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
          }, options.timeoutMs)
        : undefined;

      child.stdout.on('data', (chunk: Buffer) => {
        const text = chunk.toString();
        stdout += text;
        options.onStdout?.(text);
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        resolve({ exitCode: 127, stdout, stderr: `${stderr}${error.message}`, timedOut });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ exitCode: code ?? (timedOut ? 124 : 1), stdout, stderr, timedOut });
      });

      if (options.stdin !== undefined) {
        child.stdin.end(options.stdin);
      }
    });
  }
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/ProcessRunner.test.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/ProcessRunner.ts src/task/__tests__/ProcessRunner.test.ts
git commit -m "feat: child process runner with timeout and stdin support"
```

- [ ] **Step 6: Не ронять процесс на EPIPE (по итогам ревью)**

У `child.stdin` нет обработчика `error`, а событие `'error'` на `EventEmitter` без слушателя бросается синхронно и убивает **весь** процесс таска, а не одну операцию. Воспроизведено: дочерний процесс, завершившийся раньше, чем прочитал stdin, даёт `write EPIPE` и падение с кодом 1. Это ровно тот путь, которым пароль уходит в `docker login --password-stdin`.

Обработчик вешается до записи. `EPIPE` и `ERR_STREAM_DESTROYED` игнорируются — это штатная ситуация, когда дочерний процесс не стал читать ввод, и его собственный код возврата уже всё объясняет. Любая другая ошибка stdin дописывается в собранный `stderr`, иначе крах меняется на невидимый сбой.

Отдельно фиксируется в док-комментарии, почему промис резолвится на `close`, а не на `exit`: `close` дожидается закрытия потоков, поэтому вывод собирается целиком. Полнота вывода при этом всё равно зависит от того, успел ли дочерний процесс сбросить буфер перед выходом — у Go-бинарника trivy запись в пайп блокирующая, так что это не наша проблема, но знать об этом читателю нужно.

---

## Task 12: Чтение конфигурации из Extension Data

Режим авторизации по умолчанию берётся из результата спайка (Task 2). Код поддерживает оба, поэтому от исхода спайка зависит только значение `authMode` в `index.ts` и `task.json`.

**Files:**
- Create: `src/task/ConfigClient.ts`
- Test: `src/task/__tests__/ConfigClient.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import { ConfigClient, ConfigUnavailableError } from '../ConfigClient';

const okResponse = (value: unknown) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({ id: 'runners', value }),
});

describe('ConfigClient', () => {
  it('requests the document from the extension data collection', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([{ alias: 'baseline' }]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection/',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(
      'https://dev.example.com/DefaultCollection/_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1',
    );
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('sends basic auth when configured for a personal access token', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'pat', token: 'mypat' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const expected = `Basic ${Buffer.from(':mypat').toString('base64')}`;
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe(expected);
  });

  it('returns the value field of the document', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([{ alias: 'baseline' }]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toEqual([{ alias: 'baseline' }]);
  });

  it('returns undefined when the document does not exist yet', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 404, text: async () => '' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toBeUndefined();
  });

  it('explains an authorization failure in terms the pipeline author can act on', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 403, text: async () => 'no' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/Allow scripts to access the OAuth token|configConnection/);
  });

  it('surfaces a transport failure as ConfigUnavailableError', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(/ECONNREFUSED/);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/ConfigClient.test.ts`
Expected: FAIL — `Cannot find module '../ConfigClient'`.

- [ ] **Step 3: Реализовать `src/task/ConfigClient.ts`**

```ts
export class ConfigUnavailableError extends Error {}

export type AuthMode = 'bearer' | 'pat';

export interface FetchLike {
  (url: string, init: { headers: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
  }>;
}

export interface ConfigClientOptions {
  collectionUri: string;
  publisher: string;
  extensionId: string;
  auth: { mode: AuthMode; token: string };
  fetch: FetchLike;
}

const API_VERSION = '3.2-preview.1';

export class ConfigClient {
  constructor(private readonly options: ConfigClientOptions) {}

  async readDocument<T>(documentId: string): Promise<T | undefined> {
    const base = this.options.collectionUri.replace(/\/+$/, '');
    const url =
      `${base}/_apis/ExtensionManagement/InstalledExtensions/${this.options.publisher}/${this.options.extensionId}` +
      `/Data/Scopes/Default/Current/Collections/%24settings/Documents/${documentId}?api-version=${API_VERSION}`;

    let response;
    try {
      response = await this.options.fetch(url, { headers: { Authorization: this.authHeader() } });
    } catch (error) {
      throw new ConfigUnavailableError(
        `Could not reach ${base} to read the "${documentId}" settings document: ${(error as Error).message}`,
      );
    }

    if (response.status === 404) {
      return undefined;
    }

    if (!response.ok) {
      throw new ConfigUnavailableError(
        `Reading the "${documentId}" settings document failed with HTTP ${response.status}. ` +
          'Enable "Allow scripts to access the OAuth token" on the job, or point the task at a PAT service connection through the configConnection input.',
      );
    }

    const document = JSON.parse(await response.text()) as { value: T };
    return document.value;
  }

  private authHeader(): string {
    if (this.options.auth.mode === 'pat') {
      return `Basic ${Buffer.from(`:${this.options.auth.token}`).toString('base64')}`;
    }
    return `Bearer ${this.options.auth.token}`;
  }
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/ConfigClient.test.ts`
Expected: PASS, 6 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/ConfigClient.ts src/task/__tests__/ConfigClient.test.ts
git commit -m "feat: read admin settings from extension data service"
```

- [ ] **Step 6: Отличать «не настроено» от «сломано» (по итогам ревью)**

`JSON.parse` уходит внутрь `try`: ответ 200 с HTML-страницей входа — реалистичный сценарий для on-prem — иначе приезжал сырым `SyntaxError` без единого намёка на то, что читался документ настроек. В сообщение попадает начало тела, обрезанное и обеззараженное (без управляющих символов и без `##vso[`), чтобы «это была страница логина» было видно сразу.

Ответ 200 без поля `value` — тоже ошибка, а не «ещё не настроено»: иначе испорченный документ выглядел бы для администратора как ненастроенный. Единственный путь, возвращающий `undefined`, — 404.

`collectionUri` проверяется на непустоту и схему с указанием `System.CollectionUri`, иначе сообщение выглядело как сетевая проблема и не называло настоящую причину. Из всех сообщений вырезается userinfo: `https://user:s3cr3t@dev.example.com/DC` иначе печатается в лог сборки целиком.

`documentId`, `publisher` и `extensionId` кодируются перед подстановкой в URL. `%24settings` при этом трогать нельзя — это уже закодированное имя коллекции `$settings`.

---

## Task 12b: HTTP-клиент без глобального fetch

Агент может выполнять таск на Node 16, где глобального `fetch` нет. Свой минимальный клиент на модуле `https` убирает эту зависимость.

**Files:**
- Create: `src/task/httpFetch.ts`
- Test: `src/task/__tests__/httpFetch.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import * as http from 'http';
import { AddressInfo } from 'net';
import { httpFetch } from '../httpFetch';

describe('httpFetch', () => {
  let server: http.Server;
  let base: string;
  let seenAuth: string | undefined;

  beforeAll((done) => {
    server = http.createServer((request, response) => {
      seenAuth = request.headers.authorization;
      if (request.url?.includes('missing')) {
        response.writeHead(404).end('nope');
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"value":[1,2]}');
    });
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it('returns ok with the body for a 200 response', async () => {
    const response = await httpFetch(`${base}/doc`, { headers: {} });
    expect(response.ok).toBe(true);
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{"value":[1,2]}');
  });

  it('sends the authorization header', async () => {
    await httpFetch(`${base}/doc`, { headers: { Authorization: 'Bearer tok' } });
    expect(seenAuth).toBe('Bearer tok');
  });

  it('reports a non-ok status without throwing', async () => {
    const response = await httpFetch(`${base}/missing`, { headers: {} });
    expect(response).toMatchObject({ ok: false, status: 404 });
  });

  it('rejects when the host refuses the connection', async () => {
    await expect(httpFetch('http://127.0.0.1:1/doc', { headers: {} })).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/httpFetch.test.ts`
Expected: FAIL — `Cannot find module '../httpFetch'`.

- [ ] **Step 3: Реализовать `src/task/httpFetch.ts`**

```ts
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { FetchLike } from './ConfigClient';

export const httpFetch: FetchLike = (url, init) =>
  new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'http:' ? http : https;

    const request = transport.request(
      parsed,
      { method: 'GET', headers: init.headers },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          body += chunk;
        });
        response.on('end', () => {
          const status = response.statusCode ?? 0;
          resolve({ ok: status >= 200 && status < 300, status, text: async () => body });
        });
      },
    );

    request.on('error', reject);
    request.end();
  });
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/httpFetch.test.ts`
Expected: PASS, 4 теста.

- [ ] **Step 5: Commit**

```bash
git add src/task/httpFetch.ts src/task/__tests__/httpFetch.test.ts
git commit -m "feat: minimal http client so the task runs on node 16"
```

- [ ] **Step 6: Ограничить запрос по-настоящему (по итогам ревью)**

Запрос обязан завершаться всегда. Наивная версия не завершалась в двух случаях, оба воспроизведены:

- **разрыв посреди тела.** Единственный путь отказа висел на `request.on('error')`, а Node при преждевременном закрытии сообщает об ошибке на **ответе**, а не на запросе; сторож, зарегистрированный через `request.setTimeout`, умирает вместе с сокетом. И `socket.destroy()` (RST), и `socket.end()` при недобранном `Content-Length` оставляли промис висеть навсегда — то есть ровно то, ради чего таймаут и вводился. Нужны слушатели `error` и `aborted` на ответе;
- **медленная капля.** `request.setTimeout` сбрасывается на каждом байте, поэтому сервер, отдающий по байту раз в 29 секунд, при умолчании в 30 секунд держит сборку бесконечно. Нужен общий дедлайн в замыкании, а не сторож простоя.

Тело ответа буферизуется целиком, поэтому нужен предел размера: документ настроек весит килобайты, а восьмимегабайтный ответ принимался молча. При превышении — отказ с указанием предела, не тихое обрезание: обрезанный документ упал бы позже на разборе JSON с невнятным сообщением.

Все три таймаутных теста передавали явные 50 мс, поэтому умолчание, которое и защищает продакшен, не проверялось вообще; замена его на ~24 дня проходила весь набор.

---

## Task 13: Чтение inputs таска

**Files:**
- Create: `src/task/inputs.ts`
- Test: `src/task/__tests__/inputs.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import * as tl from 'azure-pipelines-task-lib/task';
import { readInputs } from '../inputs';

jest.mock('azure-pipelines-task-lib/task');

const mocked = tl as jest.Mocked<typeof tl>;

const setInputs = (values: Record<string, string | undefined>, booleans: Record<string, boolean> = {}) => {
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
    setInputs({ scanType: 'image', target: 'app:1.4.2', severities: 'critical,high', scanners: 'vuln,license' });
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
    setInputs({ scanType: 'image', target: 'app:1.4.2', useDockerSocket: 'true' }, { useDockerSocket: true });
    expect(readInputs().useDockerSocket).toBe(true);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/inputs.test.ts`
Expected: FAIL — `Cannot find module '../inputs'`.

- [ ] **Step 3: Реализовать `src/task/inputs.ts`**

```ts
import * as tl from 'azure-pipelines-task-lib/task';
import { parseSeverity, parseSeverityList } from '../shared/severity';
import {
  FailOn,
  OutputFormat,
  SbomFormat,
  Scanner,
  ScanType,
  TaskInputs,
} from '../shared/types';

const SCAN_TYPES: ScanType[] = ['image', 'filesystem', 'repository', 'config', 'sbom'];
const SCANNERS: Scanner[] = ['vuln', 'secret', 'misconfig', 'license'];
const FORMATS: OutputFormat[] = ['table', 'json', 'sarif'];
const SBOM_FORMATS: SbomFormat[] = ['off', 'cyclonedx', 'spdx-json'];

function oneOf<T extends string>(name: string, raw: string, allowed: T[]): T {
  const value = raw.trim() as T;
  if (!allowed.includes(value)) {
    throw new Error(`Input "${name}" has value "${raw}". Allowed values: ${allowed.join(', ')}.`);
  }
  return value;
}

function listOf<T extends string>(name: string, raw: string, allowed: T[]): T[] {
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => oneOf(name, part, allowed));
}

/** Set the boolean only when the pipeline provided it, so admin defaults still apply. */
function optionalBool(name: string): boolean | undefined {
  return tl.getInput(name) === undefined ? undefined : tl.getBoolInput(name);
}

export function readInputs(): TaskInputs {
  const scanTypeRaw = tl.getInput('scanType') ?? 'image';
  const target = tl.getInput('target');
  if (!target) {
    throw new Error('Input "target" is required: pass an image reference or a path to scan.');
  }

  const severitiesRaw = tl.getInput('severities');
  const scannersRaw = tl.getInput('scanners');
  const failOnRaw = tl.getInput('failOn');
  const timeoutRaw = tl.getInput('timeoutMinutes');
  const formatsRaw = tl.getInput('formats');
  const sbomRaw = tl.getInput('generateSbom');

  let timeoutMinutes: number | undefined;
  if (timeoutRaw !== undefined) {
    timeoutMinutes = Number(timeoutRaw);
    if (!Number.isFinite(timeoutMinutes) || timeoutMinutes <= 0) {
      throw new Error(`Input "timeoutMinutes" must be a positive number, got "${timeoutRaw}".`);
    }
  }

  let failOn: FailOn | undefined;
  if (failOnRaw !== undefined) {
    failOn = failOnRaw.trim().toLowerCase() === 'none' ? 'none' : parseSeverity(failOnRaw);
  }

  return {
    scanType: oneOf('scanType', scanTypeRaw, SCAN_TYPES),
    target,
    runner: tl.getInput('runner'),
    severities: severitiesRaw === undefined ? undefined : parseSeverityList(severitiesRaw),
    scanners: scannersRaw === undefined ? undefined : listOf('scanners', scannersRaw, SCANNERS),
    failOn,
    ignoreUnfixed: optionalBool('ignoreUnfixed'),
    ignoreFile: tl.getInput('ignoreFile'),
    timeoutMinutes,
    skipDbUpdate: optionalBool('skipDbUpdate'),
    targetRegistryConnection: tl.getInput('targetRegistryConnection'),
    useDockerSocket: optionalBool('useDockerSocket'),
    formats: formatsRaw === undefined ? undefined : listOf('formats', formatsRaw, FORMATS),
    generateSbom: sbomRaw === undefined ? undefined : oneOf('generateSbom', sbomRaw, SBOM_FORMATS),
    publishArtifact: optionalBool('publishArtifact'),
    extraTrivyArgs: tl.getInput('extraTrivyArgs'),
    workingDirectory: tl.getInput('workingDirectory'),
  };
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/inputs.test.ts`
Expected: PASS, 8 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/inputs.ts src/task/__tests__/inputs.test.ts
git commit -m "feat: read and validate task inputs"
```

- [ ] **Step 6: Разбор значений и сообщения (по итогам ревью)**

Показанный выше код для `failOn` не компилируется против нынешнего `FailOn`: `parseSeverity` возвращает `Severity`, куда входит `UNKNOWN`. Появляется `parseFailOn`, который отвергает `UNKNOWN` отдельным сообщением — порогом это значение быть не может, оно заблокировало бы всё.

Прочее:

- `listOf` бросает исключение, если после отбрасывания пустых элементов не осталось ничего. Иначе `scanners: ' '` даёт `[]`, а пустой массив — это не `undefined`, поэтому `ConfigResolver` принимает его за настоящее переопределение и выбрасывает настройку админа; для `formats` пустой массив ещё и обходит фоллбэк `?? ['table','json']`, и скан не пишет вообще никакого вывода;
- сообщения об ошибках называют input. `failOn: 'critcal'` раньше сообщал `Unknown severity "CRITCAL". Allowed values: UNKNOWN, ...` — реклама `UNKNOWN`, который двумя строками ниже отвергается, отсутствие `none`, который разрешён, и ни слова о том, какой из двух severity-подобных inputs виноват;
- `oneOf` приводит значение к нижнему регистру: все четыре словаря лежат в нижнем регистре, а до этого `severities: 'critical'` работало, тогда как `scanType: 'Image'` падало;
- `runner`, `ignoreFile`, `workingDirectory`, `targetRegistryConnection` обрезаются по краям — `tl.getInput` этого не делает, и `runner: ' hardened '` падал с сообщением `Runner " hardened " is not available`. `target` намеренно не обрезается: он эхом уходит дальше, и тихая правка спрятала бы опечатку автора пайплайна.

**Контракт с `task.json`, без которого рушится вся модель:** ни у одного input, кроме `scanType`, не должно быть `defaultValue`. Агент материализует объявленные умолчания в переменные `INPUT_*` непустыми строками, поэтому `defaultValue: "false"` сделает `getInput` возвращающим `'false'` на каждом запуске — неотличимо от того, что автор пайплайна задал значение сам. Дальше `ConfigResolver` либо молча переопределит настройку администратора, либо при строгой политике завалит каждую сборку, назвав поле, которого никто не трогал. Модуль защититься от этого не может, поэтому контракт записан док-комментарием у `readInputs` и продублирован в Task 16.

---

## Task 14: Публикация результатов

**Files:**
- Create: `src/task/Publisher.ts`
- Test: `src/task/__tests__/Publisher.test.ts`

`Publisher` пишет logging-команды Azure Pipelines через инжектируемую функцию вывода, поэтому тестируется без агента.

- [ ] **Step 1: Написать падающий тест**

```ts
import { Publisher } from '../Publisher';
import { NormalizedReport } from '../../shared/types';

const report: NormalizedReport = {
  schemaVersion: 1,
  scanType: 'image',
  target: 'app:1.4.2',
  artifactName: 'app:1.4.2',
  runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
  findings: [
    {
      kind: 'vulnerability',
      severity: 'CRITICAL',
      id: 'CVE-2024-21626',
      title: 'runc escape',
      target: 'app:1.4.2',
      pkgName: 'runc',
      installedVersion: '1.1.7',
      fixedVersion: '1.1.12',
    },
  ],
  counts: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1 },
  kindCounts: { vulnerability: 1, secret: 0, misconfiguration: 0, license: 0 },
};

describe('Publisher', () => {
  let lines: string[];
  let publisher: Publisher;

  beforeEach(() => {
    lines = [];
    publisher = new Publisher((line) => lines.push(line));
  });

  it('attaches the report under the trivy.report type with a per-scan name', () => {
    publisher.attachReport('/agent/_work/1/s/.trivy/report-2.json', 2);
    expect(lines).toEqual([
      '##vso[task.addattachment type=trivy.report;name=trivy-report-2;]/agent/_work/1/s/.trivy/report-2.json',
    ]);
  });

  it('uploads the sarif file into the CodeAnalysisLogs artifact', () => {
    publisher.publishSarif('/agent/_work/1/s/.trivy/report-0.sarif');
    expect(lines).toEqual([
      '##vso[artifact.upload artifactname=CodeAnalysisLogs;]/agent/_work/1/s/.trivy/report-0.sarif',
    ]);
  });

  it('logs one error per blocking finding so they surface in the build summary', () => {
    publisher.logBlockingFindings(report.findings);
    expect(lines).toEqual([
      '##vso[task.logissue type=error]CRITICAL CVE-2024-21626 in runc 1.1.7 (fixed in 1.1.12): runc escape',
    ]);
  });

  it('says when a finding has no fix available', () => {
    publisher.logBlockingFindings([{ ...report.findings[0], fixedVersion: undefined }]);
    expect(lines[0]).toContain('(no fix available)');
  });

  it('caps the number of logged findings and says how many were hidden', () => {
    const many = Array.from({ length: 30 }, (_, index) => ({
      ...report.findings[0],
      id: `CVE-${index}`,
    }));
    publisher.logBlockingFindings(many);
    expect(lines).toHaveLength(21);
    expect(lines[20]).toContain('10 more');
  });

  it('prints a summary table of severity counts', () => {
    publisher.printSummary(report, 'baseline');
    expect(lines.join('\n')).toContain('CRITICAL: 1');
    expect(lines.join('\n')).toContain('baseline');
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/Publisher.test.ts`
Expected: FAIL — `Cannot find module '../Publisher'`.

- [ ] **Step 3: Реализовать `src/task/Publisher.ts`**

```ts
import { compareSeverity, SEVERITY_ORDER } from '../shared/severity';
import { Finding, NormalizedReport } from '../shared/types';

const MAX_LOGGED_FINDINGS = 20;

export type LineWriter = (line: string) => void;

export class Publisher {
  constructor(private readonly write: LineWriter = (line) => console.log(line)) {}

  attachReport(hostPath: string, scanIndex: number): void {
    this.write(
      `##vso[task.addattachment type=trivy.report;name=trivy-report-${scanIndex};]${hostPath}`,
    );
  }

  publishSarif(hostPath: string): void {
    this.write(`##vso[artifact.upload artifactname=CodeAnalysisLogs;]${hostPath}`);
  }

  publishArtifact(hostPath: string, artifactName: string): void {
    this.write(`##vso[artifact.upload artifactname=${artifactName};]${hostPath}`);
  }

  logBlockingFindings(findings: Finding[]): void {
    for (const finding of findings.slice(0, MAX_LOGGED_FINDINGS)) {
      const pkg = finding.pkgName
        ? ` in ${finding.pkgName}${finding.installedVersion ? ` ${finding.installedVersion}` : ''}`
        : '';
      const fix = finding.fixedVersion
        ? ` (fixed in ${finding.fixedVersion})`
        : ' (no fix available)';
      this.write(
        `##vso[task.logissue type=error]${finding.severity} ${finding.id}${pkg}${fix}: ${finding.title}`,
      );
    }

    const hidden = findings.length - MAX_LOGGED_FINDINGS;
    if (hidden > 0) {
      this.write(
        `##vso[task.logissue type=error]${hidden} more blocking finding(s) not listed here, see the Trivy tab.`,
      );
    }
  }

  printSummary(report: NormalizedReport, runnerAlias: string): void {
    this.write(`Trivy scan of ${report.target} using runner ${runnerAlias} (${report.runner.image})`);
    if (report.runner.dbUpdatedAt) {
      this.write(`Vulnerability database updated at ${report.runner.dbUpdatedAt}`);
    }
    for (const severity of [...SEVERITY_ORDER].reverse()) {
      this.write(`  ${severity}: ${report.counts[severity]}`);
    }
  }
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/Publisher.test.ts`
Expected: PASS, 6 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/Publisher.ts src/task/__tests__/Publisher.test.ts
git commit -m "feat: publish attachments, artifacts and build issues"
```

---

## Task 15: Оркестрация скана

**Files:**
- Create: `src/task/run.ts`
- Test: `src/task/__tests__/run.test.ts`

- [ ] **Step 1: Написать падающий тест**

```ts
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from '../run';
import { ProcessResult, ProcessRunner, RunOptions } from '../ProcessRunner';
import { Publisher } from '../Publisher';
import { AgentContext, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

class FakeRunner implements ProcessRunner {
  calls: { command: string; args: string[]; options?: RunOptions }[] = [];
  results: ProcessResult[] = [];

  constructor(private readonly onScan?: () => void) {}

  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult> {
    this.calls.push({ command, args, options });
    if (args.includes('version')) {
      return Promise.resolve({
        exitCode: 0,
        stdout: '{"Version":"0.58.1","VulnerabilityDB":{"UpdatedAt":"2026-07-28T06:11:53Z"}}',
        stderr: '',
        timedOut: false,
      });
    }
    this.onScan?.();
    return Promise.resolve(
      this.results.shift() ?? { exitCode: 0, stdout: '', stderr: '', timedOut: false },
    );
  }
}

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
];
const defaults: DefaultsConfig = { dbRepository: 'registry.example.com/trivy-db:2' };
const inputs: TaskInputs = { scanType: 'image', target: 'app:1.4.2' };

let workspace: string;
let agent: AgentContext;
let lines: string[];

const reportBody = JSON.stringify({
  SchemaVersion: 2,
  ArtifactName: 'app:1.4.2',
  Results: [
    {
      Target: 'app:1.4.2',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'runc', Severity: 'CRITICAL', Title: 'escape' },
      ],
    },
  ],
});

const writeReport = () => {
  fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
  fs.writeFileSync(path.join(workspace, '.trivy', 'report-0.json'), reportBody);
};

beforeEach(() => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'run-'));
  fs.mkdirSync(path.join(workspace, 'temp'), { recursive: true });
  agent = {
    sourcesDir: workspace,
    agentHomeDir: workspace,
    tempDir: path.join(workspace, 'temp'),
    buildId: '1042',
  };
  lines = [];
});

afterEach(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

const invoke = (runner: ProcessRunner) =>
  runScan({
    defaults,
    runners,
    inputs,
    agent,
    scanIndex: 0,
    processRunner: runner,
    publisher: new Publisher((line) => lines.push(line)),
    credentials: {},
  });

describe('runScan', () => {
  it('probes the runner version and then runs the scan', async () => {
    const runner = new FakeRunner(writeReport);
    await invoke(runner);
    expect(runner.calls[0].args).toContain('version');
    expect(runner.calls[1].args).toContain('image');
  });

  it('returns a failed gate when a critical finding is present', async () => {
    const result = await invoke(new FakeRunner(writeReport));
    expect(result.gate.outcome).toBe('failed');
    expect(result.report.findings).toHaveLength(1);
  });

  it('records the runner version and database timestamp in the report', async () => {
    const result = await invoke(new FakeRunner(writeReport));
    expect(result.report.runner).toMatchObject({
      trivyVersion: '0.58.1',
      dbUpdatedAt: '2026-07-28T06:11:53Z',
    });
  });

  it('attaches the report for the results tab', async () => {
    await invoke(new FakeRunner(writeReport));
    expect(lines.some((line) => line.includes('task.addattachment'))).toBe(true);
  });

  it('deletes the env file even when the scan fails', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'docker: not found', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow();
    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  it('reports a docker failure as an infrastructure error, not as findings', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'Cannot connect to the Docker daemon', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow(/Docker daemon/);
  });

  it('names the timeout input when the container is killed', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 137, stdout: '', stderr: '', timedOut: true }];
    await expect(invoke(runner)).rejects.toThrow(/timeoutMinutes/);
  });

  it('removes a leftover container after a timeout', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 137, stdout: '', stderr: '', timedOut: true }];
    await expect(invoke(runner)).rejects.toThrow();
    expect(runner.calls.some((call) => call.args.join(' ').includes('rm -f trivyscan-1042-0'))).toBe(
      true,
    );
  });

  it('fails with a clear message when the runner produced no report file', async () => {
    await expect(invoke(new FakeRunner())).rejects.toThrow(/did not produce a report/);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/task/__tests__/run.test.ts`
Expected: FAIL — `Cannot find module '../run'`.

- [ ] **Step 3: Реализовать `src/task/run.ts`**

```ts
import * as fs from 'fs';
import * as path from 'path';
import { resolveConfig } from './ConfigResolver';
import {
  buildScanArgs,
  buildTrivyEnv,
  buildVersionArgs,
  containerName,
  hostReportPath,
  RegistryCredentials,
} from './DockerCommand';
import { removeEnvFile, writeEnvFile } from './EnvFile';
import { evaluateGate, GateResult } from './GateEvaluator';
import { ProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { parseTrivyReport, parseVersion } from './ReportParser';
import {
  AgentContext,
  DefaultsConfig,
  NormalizedReport,
  RunnerConfig,
  TaskInputs,
} from '../shared/types';

export class ScanExecutionError extends Error {}

export interface RunScanArgs {
  defaults: DefaultsConfig;
  runners: RunnerConfig[];
  inputs: TaskInputs;
  agent: AgentContext;
  scanIndex: number;
  processRunner: ProcessRunner;
  publisher: Publisher;
  credentials: RegistryCredentials;
}

export interface RunScanResult {
  report: NormalizedReport;
  gate: GateResult;
  reportPath: string;
}

export async function runScan(args: RunScanArgs): Promise<RunScanResult> {
  const { processRunner, publisher } = args;
  const config = resolveConfig({
    defaults: args.defaults,
    runners: args.runners,
    inputs: args.inputs,
    agent: args.agent,
    scanIndex: args.scanIndex,
  });

  const version = await processRunner.run('docker', buildVersionArgs(config));
  const runnerInfo = {
    alias: config.runner.alias,
    image: config.runner.image,
    ...parseVersion(version.stdout),
  };

  fs.mkdirSync(config.cacheDir, { recursive: true });
  fs.mkdirSync(path.join(config.sourcesDir, '.trivy'), { recursive: true });

  const envFile = writeEnvFile(
    args.agent.tempDir,
    `scan-${config.scanIndex}`,
    buildTrivyEnv(config, args.credentials),
  );

  let scan;
  try {
    scan = await processRunner.run('docker', buildScanArgs(config, envFile), {
      timeoutMs: config.timeoutMinutes * 60_000 + 30_000,
      onStdout: (chunk) => process.stdout.write(chunk),
    });
  } finally {
    removeEnvFile(envFile);
  }

  if (scan.timedOut) {
    await processRunner.run('docker', ['rm', '-f', containerName(config)]);
    throw new ScanExecutionError(
      `The scan exceeded ${config.timeoutMinutes} minutes and was killed. Raise the timeoutMinutes input or the collection default.`,
    );
  }

  if (scan.exitCode !== 0) {
    throw new ScanExecutionError(
      `docker exited with code ${scan.exitCode} while running ${config.runner.image}. ` +
        `This is an infrastructure failure, not a scan result. Output: ${scan.stderr.trim() || scan.stdout.trim()}`,
    );
  }

  const reportPath = hostReportPath(config);
  if (!fs.existsSync(reportPath)) {
    throw new ScanExecutionError(
      `Runner ${config.runner.image} did not produce a report at ${reportPath}. Check that the image entrypoint is trivy.`,
    );
  }

  const report = parseTrivyReport(fs.readFileSync(reportPath, 'utf8'), {
    scanType: config.scanType,
    target: config.target,
    runner: runnerInfo,
  });

  const gate = evaluateGate(report, config.failOn);

  publisher.printSummary(report, config.runner.alias);
  publisher.attachReport(reportPath, config.scanIndex);
  if (gate.blocking.length > 0) {
    publisher.logBlockingFindings(gate.blocking);
  }

  return { report, gate, reportPath };
}
```

- [ ] **Step 4: Убедиться, что тесты проходят**

Run: `npx jest src/task/__tests__/run.test.ts`
Expected: PASS, 9 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/task/run.ts src/task/__tests__/run.test.ts
git commit -m "feat: orchestrate a scan from config to gate result"
```

---

## Task 15b: SARIF, SBOM и таблица в логе

Спека обещает SARIF-артефакт, SBOM и человекочитаемый вывод. JSON нужен всегда (гейт и вкладка), остальные форматы — дополнительные запуски того же раннера; таблицу рисуем сами из уже распарсенного отчёта, чтобы не сканировать дважды ради текста.

**Files:**
- Modify: `src/task/DockerCommand.ts`, `src/task/Publisher.ts`, `src/task/run.ts`
- Test: `src/task/__tests__/DockerCommand.test.ts`, `src/task/__tests__/Publisher.test.ts`, `src/task/__tests__/run.test.ts`

- [ ] **Step 1: Дописать падающие тесты в `src/task/__tests__/DockerCommand.test.ts`**

Добавьте импорты `buildFormatArgs`, `hostExtraPath` к существующему импорту из `../DockerCommand` и допишите блок:

```ts
describe('buildFormatArgs', () => {
  it('reuses the scan command with a different format and output', () => {
    const args = buildFormatArgs(config(), '/tmp/e', 'sarif');
    expect(args.slice(args.indexOf('--format'), args.indexOf('--format') + 2)).toEqual([
      '--format',
      'sarif',
    ]);
    expect(args).toContain('/workspace/.trivy/report-0.sarif');
    expect(args[args.length - 1]).toBe('app:1.4.2');
  });

  it('gives the extra run its own container name so it cannot clash with the scan', () => {
    expect(buildFormatArgs(config(), '/tmp/e', 'sarif')).toContain('trivyscan-1042-0-sarif');
  });

  it('names the sbom output after the sbom format', () => {
    expect(buildFormatArgs(config(), '/tmp/e', 'cyclonedx')).toContain(
      '/workspace/.trivy/sbom-0.json',
    );
  });

  it('maps extra outputs onto host paths', () => {
    expect(hostExtraPath(config(), 'sarif')).toBe('/agent/_work/1/s/.trivy/report-0.sarif');
    expect(hostExtraPath(config(), 'spdx-json')).toBe('/agent/_work/1/s/.trivy/sbom-0.json');
  });
});
```

- [ ] **Step 2: Дописать падающие тесты в `src/task/__tests__/Publisher.test.ts`**

```ts
  it('renders a table of findings sorted by severity', () => {
    publisher.printFindingsTable(report);
    const text = lines.join('\n');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('CVE-2024-21626');
    expect(text).toContain('runc');
  });

  it('says so instead of printing an empty table', () => {
    publisher.printFindingsTable({ ...report, findings: [] });
    expect(lines.join('\n')).toMatch(/no findings/i);
  });

  it('emits a warning issue', () => {
    publisher.warn('sarif run failed');
    expect(lines).toEqual(['##vso[task.logissue type=warning]sarif run failed']);
  });
```

- [ ] **Step 3: Дописать падающие тесты в `src/task/__tests__/run.test.ts`**

```ts
  it('runs a second container to produce sarif when the format is requested', async () => {
    const runner = new FakeRunner(writeReport);
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'] },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(runner.calls.filter((call) => call.args.includes('sarif'))).toHaveLength(1);
    expect(lines.some((line) => line.includes('CodeAnalysisLogs'))).toBe(true);
  });

  it('runs a second container to produce an sbom when asked', async () => {
    const runner = new FakeRunner(writeReport);
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, generateSbom: 'cyclonedx' },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(runner.calls.filter((call) => call.args.includes('cyclonedx'))).toHaveLength(1);
    expect(lines.some((line) => line.includes('TrivySBOM'))).toBe(true);
  });

  it('warns but does not fail the scan when the sarif run fails', async () => {
    const runner = new FakeRunner(writeReport);
    runner.results = [
      { exitCode: 0, stdout: '', stderr: '', timedOut: false },
      { exitCode: 1, stdout: '', stderr: 'sarif template missing', timedOut: false },
    ];
    const result = await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'] },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(result.gate.outcome).toBe('failed');
    expect(lines.some((line) => line.includes('type=warning'))).toBe(true);
  });
```

- [ ] **Step 4: Убедиться, что тесты падают**

Run: `npx jest src/task/__tests__/DockerCommand.test.ts src/task/__tests__/Publisher.test.ts src/task/__tests__/run.test.ts`
Expected: FAIL — `buildFormatArgs is not a function`, `publisher.printFindingsTable is not a function`.

- [ ] **Step 5: Расширить `src/task/DockerCommand.ts`**

Замените `containerName`, `buildScanArgs` и добавьте новые функции:

```ts
export type ExtraFormat = 'sarif' | 'cyclonedx' | 'spdx-json';

export function containerName(config: ResolvedScanConfig, suffix = ''): string {
  return `trivyscan-${config.buildId}-${config.scanIndex}${suffix ? `-${suffix}` : ''}`;
}

function extraFileName(config: ResolvedScanConfig, format: ExtraFormat): string {
  return format === 'sarif' ? `report-${config.scanIndex}.sarif` : `sbom-${config.scanIndex}.json`;
}

export function containerExtraPath(config: ResolvedScanConfig, format: ExtraFormat): string {
  return `${WORKSPACE}/.trivy/${extraFileName(config, format)}`;
}

export function hostExtraPath(config: ResolvedScanConfig, format: ExtraFormat): string {
  return path.posix.join(config.sourcesDir, '.trivy', extraFileName(config, format));
}

export function buildScanArgs(config: ResolvedScanConfig, envFilePath: string): string[] {
  return buildArgs(config, envFilePath, 'json', containerReportPath(config), '');
}

export function buildFormatArgs(
  config: ResolvedScanConfig,
  envFilePath: string,
  format: ExtraFormat,
): string[] {
  return buildArgs(
    config,
    envFilePath,
    format,
    containerExtraPath(config, format),
    format === 'sarif' ? 'sarif' : 'sbom',
  );
}

function buildArgs(
  config: ResolvedScanConfig,
  envFilePath: string,
  format: string,
  containerOutput: string,
  nameSuffix: string,
): string[] {
  const docker = [
    'run',
    '--rm',
    '--name',
    containerName(config, nameSuffix),
    '--env-file',
    envFilePath,
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    '-v',
    `${config.sourcesDir}:${WORKSPACE}`,
    '-w',
    config.workingDirectory ? path.posix.join(WORKSPACE, config.workingDirectory) : WORKSPACE,
  ];

  if (config.useDockerSocket) {
    docker.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  }

  docker.push(...splitArgs(config.runner.extraDockerArgs), config.runner.image);

  const trivy = [
    config.scanType,
    '--format',
    format,
    '--output',
    containerOutput,
    '--exit-code',
    '0',
    '--severity',
    config.severities.join(','),
  ];

  // trivy config has no --scanners flag: it always runs the misconfiguration scanner.
  if (config.scanType !== 'config') {
    trivy.push('--scanners', config.scanners.join(','));
  }

  if (config.ignoreUnfixed) {
    trivy.push('--ignore-unfixed');
  }
  if (config.skipDbUpdate) {
    trivy.push('--skip-db-update');
  }

  trivy.push('--timeout', `${config.timeoutMinutes}m`);

  if (config.ignoreFile) {
    trivy.push('--ignorefile', path.posix.join(WORKSPACE, config.ignoreFile));
  }

  trivy.push(...splitArgs(config.extraTrivyArgs), config.target);

  return [...docker, ...trivy];
}
```

- [ ] **Step 6: Расширить `src/task/Publisher.ts`**

Добавьте в класс:

```ts
  warn(message: string): void {
    this.write(`##vso[task.logissue type=warning]${message}`);
  }

  printFindingsTable(report: NormalizedReport): void {
    if (report.findings.length === 0) {
      this.write('No findings.');
      return;
    }

    const rows = [...report.findings].sort((a, b) => compareSeverity(b.severity, a.severity));

    this.write('SEVERITY  ID                   PACKAGE                   FIXED IN');
    for (const finding of rows) {
      const id = finding.id.padEnd(20).slice(0, 20);
      const pkg = `${finding.pkgName ?? finding.target}${
        finding.installedVersion ? ` ${finding.installedVersion}` : ''
      }`
        .padEnd(25)
        .slice(0, 25);
      this.write(
        `${finding.severity.padEnd(9)} ${id} ${pkg} ${finding.fixedVersion ?? '-'}`,
      );
    }
  }
```

- [ ] **Step 7: Переписать секцию запусков в `src/task/run.ts`**

Импорты дополняются `buildFormatArgs`, `hostExtraPath`, `ExtraFormat`. Замените всё от `const envFile = ...` до `return { report, gate, reportPath };` на:

```ts
  const envFile = writeEnvFile(
    args.agent.tempDir,
    `scan-${config.scanIndex}`,
    buildTrivyEnv(config, args.credentials),
  );
  const timeoutMs = config.timeoutMinutes * 60_000 + 30_000;

  try {
    const scan = await processRunner.run('docker', buildScanArgs(config, envFile), {
      timeoutMs,
      onStdout: (chunk) => process.stdout.write(chunk),
    });

    if (scan.timedOut) {
      await processRunner.run('docker', ['rm', '-f', containerName(config)]);
      throw new ScanExecutionError(
        `The scan exceeded ${config.timeoutMinutes} minutes and was killed. Raise the timeoutMinutes input or the collection default.`,
      );
    }

    if (scan.exitCode !== 0) {
      throw new ScanExecutionError(
        `docker exited with code ${scan.exitCode} while running ${config.runner.image}. ` +
          `This is an infrastructure failure, not a scan result. Output: ${
            scan.stderr.trim() || scan.stdout.trim()
          }`,
      );
    }

    const reportPath = hostReportPath(config);
    if (!fs.existsSync(reportPath)) {
      throw new ScanExecutionError(
        `Runner ${config.runner.image} did not produce a report at ${reportPath}. Check that the image entrypoint is trivy.`,
      );
    }

    const report = parseTrivyReport(fs.readFileSync(reportPath, 'utf8'), {
      scanType: config.scanType,
      target: config.target,
      runner: runnerInfo,
    });
    const gate = evaluateGate(report, config.failOn);

    publisher.printSummary(report, config.runner.alias);
    if (config.formats.includes('table')) {
      publisher.printFindingsTable(report);
    }
    publisher.attachReport(reportPath, config.scanIndex);
    if (config.publishArtifact) {
      publisher.publishArtifact(reportPath, 'TrivyReports');
    }
    if (gate.blocking.length > 0) {
      publisher.logBlockingFindings(gate.blocking);
    }

    if (config.formats.includes('sarif')) {
      await emitExtraFormat(config, envFile, 'sarif', timeoutMs, processRunner, publisher, (host) =>
        publisher.publishSarif(host),
      );
    }
    if (config.generateSbom !== 'off') {
      await emitExtraFormat(
        config,
        envFile,
        config.generateSbom,
        timeoutMs,
        processRunner,
        publisher,
        (host) => publisher.publishArtifact(host, 'TrivySBOM'),
      );
    }

    return { report, gate, reportPath };
  } finally {
    removeEnvFile(envFile);
  }
}

/** An extra format is a convenience, not the gate: a failure here warns instead of failing the build. */
async function emitExtraFormat(
  config: ResolvedScanConfig,
  envFile: string,
  format: ExtraFormat,
  timeoutMs: number,
  processRunner: ProcessRunner,
  publisher: Publisher,
  publish: (hostPath: string) => void,
): Promise<void> {
  const result = await processRunner.run('docker', buildFormatArgs(config, envFile, format), {
    timeoutMs,
  });
  const hostPath = hostExtraPath(config, format);

  if (result.exitCode !== 0 || !fs.existsSync(hostPath)) {
    publisher.warn(
      `Could not produce the ${format} output: ${result.stderr.trim() || 'no file was written'}. The scan result itself is unaffected.`,
    );
    return;
  }

  publish(hostPath);
}
```

`ResolvedScanConfig` добавляется в импорт типов из `../shared/types`.

- [ ] **Step 8: Убедиться, что все тесты проходят**

Run: `npm test`
Expected: PASS, включая ранее написанные тесты Task 7, 14 и 15 — сигнатуры не менялись.

- [ ] **Step 9: Commit**

```bash
git add src/task/DockerCommand.ts src/task/Publisher.ts src/task/run.ts src/task/__tests__
git commit -m "feat: sarif artifact, sbom generation and findings table"
```

---

## Task 16: Точка входа и определение таска

**Files:**
- Create: `src/task/index.ts`, `src/task/task.json`

`index.ts` только собирает реальные адаптеры — логики в нём нет, поэтому отдельных юнит-тестов у него нет; он проверяется интеграционным тестом в Task 17.

- [ ] **Step 1: Создать `src/task/task.json`**

⚠️ Ни у одного input, кроме `scanType`, не должно быть `defaultValue`. Агент подставляет объявленные умолчания в переменные `INPUT_*` непустыми строками, и тогда `readInputs` не может отличить «пайплайн промолчал» от «пайплайн задал значение». Результат — либо молчаливое переопределение настройки администратора, либо, при строгом `allowOverrides`, падение каждой сборки с указанием поля, которого автор пайплайна не касался. Умолчания живут в настройках коллекции и применяются в `ConfigResolver`; `defaultValue` у `scanType` допустим только потому, что это не поле политики.

`id` — фиксированный GUID таска; сгенерируйте свой один раз командой `node -e "console.log(require('crypto').randomUUID())"` и подставьте вместо значения ниже, после чего больше никогда не меняйте.

```json
{
  "id": "9f1d3c62-4a17-4c9c-9d1e-2b6a5f0c7d21",
  "name": "TrivyScan",
  "friendlyName": "Trivy Scan (containerized)",
  "description": "Run Trivy from a curated docker runner image and gate the build on findings.",
  "author": "iksoftware",
  "helpMarkDown": "See the project README for configuration.",
  "category": "Utility",
  "visibility": ["Build", "Release"],
  "demands": [],
  "version": { "Major": 1, "Minor": 0, "Patch": 0 },
  "instanceNameFormat": "Trivy scan $(target)",
  "groups": [
    { "name": "policy", "displayName": "Severity and gate", "isExpanded": true },
    { "name": "output", "displayName": "Output", "isExpanded": false },
    { "name": "advanced", "displayName": "Advanced", "isExpanded": false }
  ],
  "inputs": [
    {
      "name": "scanType",
      "type": "pickList",
      "label": "Scan type",
      "defaultValue": "image",
      "required": true,
      "options": {
        "image": "Container image",
        "filesystem": "Filesystem",
        "repository": "Repository",
        "config": "IaC misconfiguration",
        "sbom": "SBOM file"
      }
    },
    {
      "name": "target",
      "type": "string",
      "label": "Target",
      "required": true,
      "helpMarkDown": "Image reference for an image scan, otherwise a path relative to the sources directory."
    },
    {
      "name": "runner",
      "type": "string",
      "label": "Runner alias",
      "required": false,
      "helpMarkDown": "Alias from Collection Settings > Trivy Scanner. Leave empty to use the default runner."
    },
    { "name": "severities", "type": "string", "label": "Severities", "required": false, "groupName": "policy" },
    { "name": "scanners", "type": "string", "label": "Scanners", "required": false, "groupName": "policy" },
    { "name": "failOn", "type": "string", "label": "Fail on severity", "required": false, "groupName": "policy" },
    { "name": "ignoreUnfixed", "type": "boolean", "label": "Ignore unfixed", "required": false, "groupName": "policy" },
    { "name": "ignoreFile", "type": "filePath", "label": "Ignore file", "required": false, "groupName": "policy" },
    { "name": "formats", "type": "string", "label": "Output formats", "required": false, "groupName": "output" },
    {
      "name": "generateSbom",
      "type": "pickList",
      "label": "Generate SBOM",
      "required": false,
      "groupName": "output",
      "options": { "off": "Off", "cyclonedx": "CycloneDX", "spdx-json": "SPDX JSON" }
    },
    { "name": "publishArtifact", "type": "boolean", "label": "Publish report artifact", "required": false, "groupName": "output" },
    { "name": "targetRegistryConnection", "type": "connectedService:dockerregistry", "label": "Registry connection for the scanned image", "required": false, "groupName": "advanced" },
    { "name": "configConnection", "type": "connectedService:Generic", "label": "Settings connection (PAT)", "required": false, "groupName": "advanced", "helpMarkDown": "Only needed when the job cannot read extension settings with its OAuth token." },
    { "name": "useDockerSocket", "type": "boolean", "label": "Mount the docker socket", "required": false, "groupName": "advanced" },
    { "name": "skipDbUpdate", "type": "boolean", "label": "Skip database update", "required": false, "groupName": "advanced" },
    { "name": "timeoutMinutes", "type": "string", "label": "Timeout in minutes", "required": false, "groupName": "advanced" },
    { "name": "extraTrivyArgs", "type": "string", "label": "Extra trivy arguments", "required": false, "groupName": "advanced" },
    { "name": "workingDirectory", "type": "filePath", "label": "Working directory", "required": false, "groupName": "advanced" }
  ],
  "execution": {
    "Node16": { "target": "index.js" },
    "Node20_1": { "target": "index.js" }
  }
}
```

- [ ] **Step 2: Создать `src/task/index.ts`**

```ts
import * as tl from 'azure-pipelines-task-lib/task';
import { ConfigClient } from './ConfigClient';
import { httpFetch } from './httpFetch';
import { readInputs } from './inputs';
import { ChildProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { runScan } from './run';
import { validateCatalog, validateDefaults, validateRunner } from '../shared/validation';
import { AgentContext, DefaultsConfig, RunnerConfig } from '../shared/types';

const PUBLISHER = 'iksoftware';
const EXTENSION_ID = 'trivy-docker-scanner';

function agentContext(): AgentContext {
  return {
    sourcesDir: tl.getVariable('Build.SourcesDirectory') ?? process.cwd(),
    agentHomeDir: tl.getVariable('Agent.HomeDirectory') ?? process.cwd(),
    tempDir: tl.getVariable('Agent.TempDirectory') ?? process.cwd(),
    buildId: tl.getVariable('Build.BuildId') ?? '0',
  };
}

/** Each task instance in a job gets its own index so reports and containers never collide. */
function nextScanIndex(): number {
  const raw = Number(process.env.TRIVY_SCAN_INDEX ?? '0');
  const index = Number.isFinite(raw) ? raw : 0;
  tl.setVariable('TRIVY_SCAN_INDEX', String(index + 1));
  return index;
}

function buildConfigClient(): ConfigClient {
  const connection = tl.getInput('configConnection');
  if (connection) {
    const token =
      tl.getEndpointAuthorizationParameter(connection, 'password', true) ??
      tl.getEndpointAuthorizationParameter(connection, 'apitoken', true) ??
      '';
    return new ConfigClient({
      collectionUri: tl.getVariable('System.CollectionUri') ?? '',
      publisher: PUBLISHER,
      extensionId: EXTENSION_ID,
      auth: { mode: 'pat', token },
      fetch: httpFetch,
    });
  }

  return new ConfigClient({
    collectionUri: tl.getVariable('System.CollectionUri') ?? '',
    publisher: PUBLISHER,
    extensionId: EXTENSION_ID,
    auth: { mode: 'bearer', token: tl.getVariable('System.AccessToken') ?? '' },
    fetch: fetch as never,
  });
}

function registryCredentials(): { username?: string; password?: string } {
  const connection = tl.getInput('targetRegistryConnection');
  if (!connection) {
    return {};
  }
  return {
    username: tl.getEndpointAuthorizationParameter(connection, 'username', true),
    password: tl.getEndpointAuthorizationParameter(connection, 'password', true),
  };
}

async function main(): Promise<void> {
  try {
    const client = buildConfigClient();
    const runners = (await client.readDocument<RunnerConfig[]>('runners')) ?? [];
    const defaults = await client.readDocument<DefaultsConfig>('defaults');

    if (!defaults) {
      throw new Error(
        'The collection has no Trivy settings yet. Open Collection Settings > Trivy Scanner and configure the database mirror and at least one runner.',
      );
    }

    // The documents are hand-editable through the REST API, so validate before building a docker command from them.
    const issues = [
      ...validateDefaults(defaults),
      ...validateCatalog(runners),
      ...runners.flatMap((runner, index) =>
        validateRunner(runner).map((issue) => ({
          field: `runners[${index}].${issue.field}`,
          message: issue.message,
        })),
      ),
    ];
    if (issues.length > 0) {
      throw new Error(
        `The Trivy settings for this collection are invalid:\n${issues
          .map((issue) => `  ${issue.field}: ${issue.message}`)
          .join('\n')}`,
      );
    }

    const { gate } = await runScan({
      defaults,
      runners,
      inputs: readInputs(),
      agent: agentContext(),
      scanIndex: nextScanIndex(),
      processRunner: new ChildProcessRunner(),
      publisher: new Publisher(),
      credentials: registryCredentials(),
    });

    if (gate.outcome === 'failed') {
      tl.setResult(tl.TaskResult.Failed, gate.reason);
    } else if (gate.outcome === 'succeededWithIssues') {
      tl.setResult(tl.TaskResult.SucceededWithIssues, gate.reason);
    } else {
      tl.setResult(tl.TaskResult.Succeeded, gate.reason);
    }
  } catch (error) {
    tl.setResult(tl.TaskResult.Failed, (error as Error).message);
  }
}

void main();
```

- [ ] **Step 3: Проверить типы и линт**

Run: `npm run typecheck && npm run lint`
Expected: обе команды завершаются без ошибок.

- [ ] **Step 4: Commit**

```bash
git add src/task/index.ts src/task/task.json
git commit -m "feat: task entry point and pipeline task definition"
```

---

## Task 17: Интеграционный тест с подставным docker

Ловит расхождение между построенным argv и тем, что реально уходит в процесс — единственное место, где `ChildProcessRunner`, `DockerCommand` и `run.ts` работают вместе.

Две вещи, выясненные при реализации:

- **Передавать данные подставному docker через `process.env` нельзя.** Под ts-jest тестовый файл исполняется в отдельном контексте, и `spawn` без явной опции `env` берёт окружение настоящего процесса, а не то, что тест только что записал в `process.env`. Вариант из плана с `FAKE_DOCKER_LOG` молча не работал: скрипт получал `undefined`. Данные передаются через файл-контекст в системном временном каталоге, имя которого содержит `process.pid`, а дочерний процесс читает его по `process.ppid`. На продакшен это не влияет — там процесс один.
- `--output` в argv встречается дважды, потому что `DockerCommand` переутверждает формат и путь после `extraTrivyArgs`. Подставной docker обязан читать **последнее** вхождение: чтение первого прошло бы даже при регрессе этой защиты.

**Files:**
- Create: `test/integration/fake-docker.js`, `test/integration/scan.test.ts`

- [ ] **Step 1: Создать подставной docker `test/integration/fake-docker.js`**

```js
#!/usr/bin/env node
// Stands in for the docker CLI: records argv and writes a canned trivy report.
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(args) + '\n');

if (args.includes('version')) {
  process.stdout.write('{"Version":"0.58.1","VulnerabilityDB":{"UpdatedAt":"2026-07-28T06:11:53Z"}}');
  process.exit(0);
}

const outputFlag = args.indexOf('--output');
if (outputFlag !== -1) {
  const containerPath = args[outputFlag + 1];
  const hostPath = path.join(process.env.FAKE_DOCKER_WORKSPACE, containerPath.replace('/workspace/', ''));
  fs.mkdirSync(path.dirname(hostPath), { recursive: true });
  fs.writeFileSync(
    hostPath,
    JSON.stringify({
      SchemaVersion: 2,
      ArtifactName: 'app:1.4.2',
      Results: [
        {
          Target: 'app:1.4.2',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-2024-21626', PkgName: 'runc', Severity: 'HIGH', Title: 'escape' },
          ],
        },
      ],
    }),
  );
}

process.exit(0);
```

- [ ] **Step 2: Написать падающий тест `test/integration/scan.test.ts`**

```ts
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ChildProcessRunner, ProcessResult, RunOptions } from '../../src/task/ProcessRunner';
import { Publisher } from '../../src/task/Publisher';
import { runScan } from '../../src/task/run';

/** Routes every "docker" invocation to the fake docker script. */
class FakeDockerRunner extends ChildProcessRunner {
  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult> {
    const target = command === 'docker' ? path.join(__dirname, 'fake-docker.js') : command;
    return super.run(process.execPath, [target, ...args], options);
  }
}

describe('scan against a fake docker binary', () => {
  let workspace: string;
  let log: string;

  beforeEach(() => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'integration-'));
    fs.mkdirSync(path.join(workspace, 'temp'), { recursive: true });
    log = path.join(workspace, 'docker-calls.log');
    fs.writeFileSync(log, '');
    process.env.FAKE_DOCKER_LOG = log;
    process.env.FAKE_DOCKER_WORKSPACE = workspace;
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
    delete process.env.FAKE_DOCKER_LOG;
    delete process.env.FAKE_DOCKER_WORKSPACE;
  });

  it('runs the runner image and turns its report into a gate result', async () => {
    const lines: string[] = [];
    const result = await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2', failOn: 'HIGH' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });

    expect(result.gate.outcome).toBe('failed');
    expect(result.report.findings[0].id).toBe('CVE-2024-21626');
    expect(lines.some((line) => line.includes('task.addattachment'))).toBe(true);
  });

  it('passes the image and the mounts to docker exactly once', async () => {
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher(() => undefined),
      credentials: {},
    });

    const calls = fs
      .readFileSync(log, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as string[]);

    expect(calls).toHaveLength(2);
    expect(calls[1]).toContain('registry.example.com/trivy:0.58.1');
    expect(calls[1]).toContain(`${workspace}:/workspace`);
  });

  it('leaves no env file behind', async () => {
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher(() => undefined),
      credentials: {},
    });

    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });
});
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `npx jest test/integration/scan.test.ts`
Expected: FAIL — `Cannot find module './fake-docker.js'` или отсутствие файла лога.

- [ ] **Step 4: Прогнать весь набор тестов**

Run: `npm test`
Expected: PASS, все наборы зелёные.

- [ ] **Step 5: Commit**

```bash
git add test/integration
git commit -m "test: integration scan against a fake docker binary"
```

---

## Task 18: Логотип и README

**Files:**
- Create: `images/icon.svg`, `images/icon.png`, `overview.md`, `README.md`, `LICENSE`

- [ ] **Step 1: Создать `images/icon.svg`**

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="shield" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0078d4"/>
      <stop offset="1" stop-color="#00c2b2"/>
    </linearGradient>
  </defs>
  <path d="M64 8 L112 26 V64 C112 92 90 112 64 120 C38 112 16 92 16 64 V26 Z" fill="url(#shield)"/>
  <rect x="38" y="40" width="52" height="12" rx="3" fill="#ffffff" opacity="0.95"/>
  <rect x="38" y="58" width="52" height="12" rx="3" fill="#ffffff" opacity="0.72"/>
  <rect x="38" y="76" width="52" height="12" rx="3" fill="#ffffff" opacity="0.5"/>
  <rect x="26" y="62" width="76" height="4" rx="2" fill="#ffd166"/>
  <circle cx="102" cy="64" r="5" fill="#ffd166"/>
</svg>
```

- [ ] **Step 2: Сконвертировать в PNG 128×128**

```bash
# macOS: qlmanage; при наличии rsvg-convert или ImageMagick используйте их
npx --yes svgexport images/icon.svg images/icon.png 128:128
```

Expected: файл `images/icon.png` размером 128×128. Проверка: `file images/icon.png` печатает `PNG image data, 128 x 128`.

- [ ] **Step 3: Создать `overview.md`**

```markdown
# Trivy Docker Scanner

Runs [Trivy](https://github.com/aquasecurity/trivy) inside a docker container from a curated
catalog of runner images, so every pipeline in the collection scans with the image the security
team approved.

## Why this instead of running trivy directly

- **Curated runners.** Administrators register the allowed trivy images in Collection Settings.
  Pipelines pick one by alias, so upgrading trivy everywhere is a single edit.
- **Works in a closed network.** The vulnerability database comes from an internal OCI registry
  mirror and a persistent cache on the agent. No call ever leaves your network.
- **One place for the gate.** Severity thresholds live in collection-wide settings; pipelines may
  override only what the policy allows.
- **Readable results.** A Trivy tab on the build shows why the gate failed, the counts per
  severity, and every finding with filters.

## Quick start

```yaml
- task: TrivyScan@1
  inputs:
    scanType: image
    target: myapp:$(Build.BuildId)
```

Configure runners and defaults under **Collection Settings > Trivy Scanner**.
```

- [ ] **Step 4: Создать `README.md`**

```markdown
# Trivy Docker Scanner for Azure DevOps

Azure DevOps Server extension that runs Trivy from a docker runner image chosen from a
centrally managed catalog.

![icon](images/icon.svg)

## Requirements

- Azure DevOps Server 2022 or newer
- Linux build agents with docker available to the agent user
- An internal OCI registry mirror of the Trivy database

Windows agents are not supported in v1.

## Repository layout

| Path | Contents |
|---|---|
| `src/shared` | Types and validation shared by the task and the UI |
| `src/task` | Pipeline task `TrivyScan@1` |
| `test/fixtures` | Real trivy output used by the parser tests |
| `test/integration` | Scan run against a fake docker binary |
| `docs/superpowers` | Design spec, plans and spike results |

## Development

```bash
npm install
npm test
npm run lint
npm run typecheck
npm run package    # produces out/*.vsix
```

## License

MIT
```

- [ ] **Step 5: Создать `LICENSE`**

```
MIT License

Copyright (c) 2026 iksoftware

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 6: Commit**

```bash
git add images overview.md README.md LICENSE
git commit -m "docs: extension logo, overview and readme"
```

---

## Task 19: Манифест расширения, сборка и CI

**Files:**
- Create: `vss-extension.json`, `scripts/build-task.js`, `.github/workflows/ci.yml`
- Modify: `package.json` (скрипты `package`, `build:task`)

- [ ] **Step 1: Создать `vss-extension.json`**

```json
{
  "manifestVersion": 1,
  "id": "trivy-docker-scanner",
  "publisher": "iksoftware",
  "version": "0.1.0",
  "name": "Trivy Docker Scanner",
  "description": "Run Trivy from a curated catalog of docker runner images, with centrally managed defaults and a build results tab.",
  "public": false,
  "content": { "details": { "path": "overview.md" } },
  "categories": ["Azure Pipelines"],
  "tags": ["trivy", "security", "containers", "vulnerability", "sbom"],
  "targets": [{ "id": "Microsoft.TeamFoundation.Server", "version": "[17.0,)" }],
  "icons": { "default": "images/icon.png" },
  "scopes": ["vso.extension.data"],
  "contributions": [
    {
      "id": "trivy-scan-task",
      "type": "ms.vss-distributed-task.task",
      "targets": ["ms.vss-distributed-task.tasks"],
      "properties": { "name": "TrivyScan" }
    }
  ],
  "files": [
    { "path": "TrivyScan" },
    { "path": "images", "addressable": true }
  ]
}
```

- [ ] **Step 2: Создать `scripts/build-task.js`**

```js
#!/usr/bin/env node
// Assembles the TrivyScan folder that tfx packages: compiled js, task.json and runtime deps.
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const out = path.join(root, 'TrivyScan');

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

fs.cpSync(path.join(root, 'build', 'task'), out, { recursive: true });
fs.cpSync(path.join(root, 'build', 'shared'), path.join(out, 'shared'), { recursive: true });
fs.copyFileSync(path.join(root, 'src', 'task', 'task.json'), path.join(out, 'task.json'));

const rootPackage = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
fs.writeFileSync(
  path.join(out, 'package.json'),
  JSON.stringify(
    {
      name: 'trivy-scan-task',
      version: rootPackage.version,
      main: 'index.js',
      dependencies: rootPackage.dependencies,
    },
    null,
    2,
  ),
);

execSync('npm install --omit=dev --no-package-lock', { cwd: out, stdio: 'inherit' });
console.log(`Task assembled in ${out}`);
```

Компилятор кладёт `src/task/*` в `build/task/*`, а `src/shared/*` в `build/shared/*`, и скомпилированный таск требует `../shared/...`. Плоская раскладка (содержимое `build/task` прямо в `TrivyScan/`, а `shared` — в `TrivyScan/shared`) эту связь ломает: из `TrivyScan/inputs.js` путь `../shared/...` уходит **выше** каталога пакета. Проверено запуском — получается `Error: Cannot find module '../shared/severity'`.

Поэтому раскладка внутри пакета повторяет структуру `build/`: код таска в `TrivyScan/task/`, общий код в `TrivyScan/shared/`. При этом сам `task.json` обязан лежать в корне `TrivyScan/`, где его ищут tfx и агент, поэтому скрипт читает `src/task/task.json`, переписывает в памяти `execution.*.target` с `index.js` на `task/index.js` и кладёт в пакет уже исправленную копию. Исходный `src/task/task.json` не трогается.

Ошибка такого рода не видна до установки: `.vsix` собирается, ставится, и падает на агенте заказчика. Поэтому следующий шаг проверяет сборку запуском, а CI повторяет ту же проверку на каждом pull request, а не только на теге.

- [ ] **Step 3: Добавить скрипты в `package.json`**

Добавьте в раздел `scripts`:

```json
"build:task": "npm run build && node scripts/build-task.js",
"package": "npm run build:task && tfx extension create --manifest-globs vss-extension.json --output-path out"
```

- [ ] **Step 4: Проверить, что собранный таск запускается**

```bash
npm run build:task
node -e "process.env.INPUT_TARGET='app:1'; require('./TrivyScan/index.js')" 2>&1 | head -5
```

Expected: процесс стартует и падает на отсутствии переменных агента (сообщение про настройки коллекции или про `System.CollectionUri`), но **не** на `Cannot find module`. Если появляется `Cannot find module '../shared/types'`, поправьте `scripts/build-task.js`: положите содержимое `build/` целиком в `TrivyScan/`, а точкой входа в `task.json` укажите `task/index.js`.

- [ ] **Step 5: Создать `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
      - run: npm test

  package:
    needs: verify
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm
      - run: npm ci
      - run: npm run package
      - uses: actions/upload-artifact@v4
        with:
          name: vsix
          path: out/*.vsix
```

- [ ] **Step 6: Собрать пакет и убедиться, что `.vsix` создаётся**

Run: `npm run package`
Expected: в `out/` появляется `iksoftware.trivy-docker-scanner-0.1.0.vsix`.

- [ ] **Step 7: Добавить артефакты сборки в `.gitignore`**

Дописать в `.gitignore`:

```
build/
TrivyScan/
out/
```

- [ ] **Step 8: Commit**

```bash
git add vss-extension.json scripts/build-task.js .github/workflows/ci.yml package.json .gitignore
git commit -m "build: extension manifest, task packaging and CI"
```

---

## Готовность плана 1

После Task 19 расширение устанавливается на сервер и таск работает end-to-end при условии, что документы `runners` и `defaults` заведены через REST (Task 2). Заполнение их через UI — план 2, вкладка результатов — план 3.
