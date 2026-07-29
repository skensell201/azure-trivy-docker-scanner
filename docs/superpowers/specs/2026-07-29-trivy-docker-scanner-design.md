# Trivy Docker Scanner — дизайн расширения Azure DevOps

Дата: 2026-07-29
Статус: утверждён

## Задача

Расширение Azure DevOps Server (on-prem), которое запускает Trivy **только из docker-контейнера**
и управляется централизованно через админку. Отличия от официального `AquaSecurityOfficial.trivy-official`:
каталог разрешённых trivy-раннеров с настройками на уровне проекта, работоспособность в закрытом контуре
(зеркало БД в приватном OCI-registry), собственная вкладка результатов со сводкой.

## Целевая среда

- Azure DevOps Server 2022+ (`Microsoft.TeamFoundation.Server [17.0,)`), publisher `iksoftware`.
- Закрытый контур: интернета нет. БД уязвимостей — из внутреннего OCI-registry и/или кэша на агенте.
- Linux-агенты с установленным docker. Docker обязателен: без него таск падает с инструкцией,
  никакого fallback на локальный бинарник или скачивание с GitHub Releases.

## Состав расширения

| Юнит | Contribution | Среда выполнения |
|---|---|---|
| Таск `TrivyScan@1` | `ms.vss-distributed-task.task` | Node на агенте |
| Админка | `ms.vss-web.hub` → `ms.vss-web.project-admin-hub-group` | Браузер, React |
| Вкладка результатов | `ms.vss-build-web.build-results-tab` | Браузер, React |

Scopes манифеста: `vso.build_execute`, `vso.extension_data`.

## Поток данных

```
Админка ──пишет──> Extension Data Service (документы `runners`, `defaults`)
                              │
                              │ REST + System.AccessToken (vso.extension_data)
                              ▼
       inputs YAML ──> ConfigResolver ──> DockerCommand ──> docker run <runner> trivy …
                                                                    │ trivy JSON
                                                                    ▼
                                          ReportParser ──> GateEvaluator ──> pass / warn / fail
                                                    │
                                                    └──> build attachment ──> Вкладка результатов
```

Вкладка не обращается ни к trivy, ни к конфигу — только читает attachment через Build REST API,
поэтому работает и на давно завершённых сборках.

## Модули

`src/shared/` — типы конфигурации, `NormalizedReport`, правила валидации. Общий код для таска и обоих UI:
так вкладка и админка не могут разъехаться с таском по формату данных.

`src/task/`:

| Модуль | Ответственность | Зависимости |
|---|---|---|
| `inputs.ts` | Чтение inputs таска | единственное место, знающее `azure-pipelines-task-lib` |
| `ConfigClient.ts` | Чтение документов админки по REST + fallback | HTTP |
| `ConfigResolver.ts` | Слияние `defaults ← inputs` с учётом политики | чистая функция |
| `DockerCommand.ts` | `ResolvedScanConfig` → argv для docker | чистая функция, ноль I/O |
| `EnvFile.ts` | Временный `--env-file` с секретами (0600), удаление в `finally` | fs |
| `ProcessRunner.ts` | Интерфейс запуска процесса + реальная реализация | child_process |
| `ReportParser.ts` | trivy JSON → `NormalizedReport` | чистая функция |
| `GateEvaluator.ts` | `NormalizedReport` + политика → `GateResult` | чистая функция |
| `Publisher.ts` | Attachment, артефакты, `##vso[task.logissue]` | task-lib |
| `run.ts` | Оркестрация шагов | всё вышеперечисленное через интерфейсы |

`src/hub/` — админка (React), три вкладки: **Runners** (таблица раннеров, добавление и правка
в модалке `RunnerForm`), **Defaults** (`DefaultsForm`), **Policy** (`PolicyForm`).
`src/tab/` — вкладка: `SummaryHeader`, `SeverityCounters`, `FindingsTable`.

## Конфигурация

### Документ `runners` — каталог раннеров (1–10 записей)

| Поле | Обяз. | Значение |
|---|---|---|
| `alias` | да | Ключ для YAML (`runner: 'baseline'`), уникален, `^[a-z0-9][a-z0-9-]{1,30}$` |
| `image` | да | Полная ссылка на образ с trivy. Тег обязателен, `latest` запрещён валидацией |
| `displayName` | нет | Отображаемое имя |
| `description` | нет | Назначение раннера |
| `registryConnection` | нет | Docker Registry service connection для registry с раннером |
| `extraDockerArgs` | нет | `--network none`, `--user 1000:1000`, доп. монтирования |
| `isDefault` | нет | Ровно один в каталоге; используется, если в таске `runner` не указан |
| `enabled` | нет | По умолчанию `true`; выключенный нельзя выбрать, история сохраняется |

### Документ `defaults` — глобальные настройки

| Поле | Обяз. | Значение |
|---|---|---|
| `dbRepository` | да | OCI-зеркало БД → `TRIVY_DB_REPOSITORY` |
| `javaDbRepository` | нет | `TRIVY_JAVA_DB_REPOSITORY` |
| `dbRegistryConnection` | нет | Service connection, если зеркало БД требует авторизации |
| `cacheDir` | нет | Путь на агенте → `/root/.cache/trivy`. Дефолт `$(Agent.HomeDirectory)/_trivy-cache` |
| `skipDbUpdate` | нет | Дефолт `false` |
| `severities` | нет | Дефолт `CRITICAL,HIGH` |
| `scanners` | нет | Любые из `vuln,secret,misconfig,license`. Дефолт `vuln,secret` |
| `failOn` | нет | `LOW`…`CRITICAL`, дефолт `CRITICAL`; значение `none` — сканировать без гейта. `UNKNOWN` порогом быть не может: он ниже всех и заблокировал бы всё, хотя читается как «только неоценённые» |
| `ignoreUnfixed` | нет | Дефолт `false` |
| `timeoutMinutes` | нет | Дефолт `10` |
| `allowOverrides` | нет | Поля, доступные для переопределения из пайплайна: `runner`, `severities`, `scanners`, `failOn`, `ignoreUnfixed`, `timeoutMinutes`, `skipDbUpdate`, `useDockerSocket`, `extraTrivyArgs`, `ignoreFile`. Отсутствие поля означает «можно всё», пустой массив — «нельзя ничего» |

### Inputs таска `TrivyScan@1`

Обязательные:

- `scanType` — `image` \| `filesystem` \| `repository` \| `config` \| `sbom`, дефолт `image`
- `target` — ссылка на образ или путь

Опциональные: `runner`, `severities`, `scanners`, `failOn`, `ignoreUnfixed`, `ignoreFile`,
`timeoutMinutes`, `skipDbUpdate`, `targetRegistryConnection`, `useDockerSocket`, `formats`
(дефолт `table,json`), `generateSbom` (`off` \| `cyclonedx` \| `spdx-json`), `publishArtifact`,
`extraTrivyArgs`, `workingDirectory`.

### Приоритет значений

`defaults` → `inputs` (только для полей из `allowOverrides`) → жёсткие инварианты
(`--exit-code 0`, `--format json` для attachment), которые не переопределяются никогда.

Попытка переопределить запрещённое политикой поле — ошибка таска с явным сообщением.
Тихое игнорирование политики хуже красной сборки: пользователь считает, что его настройка применилась.

Под политику обязательно попадают `extraTrivyArgs`, `ignoreFile` и `useDockerSocket`, иначе она обходится
через боковую дверь: trivy построен на cobra, где из двух одинаковых флагов выигрывает последний, поэтому
`extraTrivyArgs: '--severity LOW --ignore-unfixed'` отменяет запертые админом `severities` и `ignoreUnfixed`;
`.trivyignore` глушит находки целиком и тем самым обходит `failOn`; а `useDockerSocket` монтирует docker-сокет,
что равносильно root на агенте сборки.

`scanType` и `target` политике не подчиняются намеренно — это и есть сам скан, а не настройка политики.
`formats`, `generateSbom`, `publishArtifact` и `workingDirectory` тоже остаются свободными: это вывод и
обвязка, запирать их нечего.

Валидация живёт в `shared/validation.ts` и используется и админкой (не даёт сохранить мусор),
и таском (переживает вручную испорченный документ).

## Исполнение скана

```
docker run --rm --name trivyscan-$(Build.BuildId)-<n>
  --env-file <tmp>/trivy.env
  -v <cacheDir>:/root/.cache/trivy
  -v <sourcesDir>:/workspace -w /workspace
  [-v /var/run/docker.sock:/var/run/docker.sock]   # только при useDockerSocket
  <extraDockerArgs> <runner.image>
  <scanType> <target> --format json --output /workspace/.trivy/report.json --exit-code 0 …
```

Секреты (`TRIVY_USERNAME`, `TRIVY_PASSWORD`) передаются только через `--env-file` с правами 0600,
файл удаляется в `finally`. `docker login` — через `--password-stdin`. В argv секретов нет никогда:
argv виден в `ps` на агенте и в отладочных логах.

Trivy всегда запускается с `--exit-code 0`, гейт считается по распарсенному JSON.
Иначе порог падения живёт в двух местах (флаги trivy и наша вкладка) и они неизбежно разойдутся;
дополнительно это позволяет тестировать гейт без запуска trivy.

Этот инвариант защищён двумя способами, потому что в cobra из двух одинаковых флагов выигрывает последний,
а `extraTrivyArgs` дописывается в конец. Во-первых, `--format json`, `--output` и `--exit-code 0`
переутверждаются после пользовательских аргументов — позиционной остаётся только цель скана. Во-вторых,
`extraTrivyArgs` с зарезервированным флагом (`--format`, `--output`, `--exit-code`, `--severity`,
`--scanners`, `--ignore-unfixed`, `--skip-db-update`, `--ignorefile`, `--timeout` и их короткие формы)
отвергается с указанием, каким input или настройкой проекта это управляется. Молчаливое игнорирование
написанного пользователем флага здесь так же плохо, как молчаливое игнорирование политики.

`workingDirectory` и `ignoreFile` после подстановки в `/workspace` нормализуются и обязаны остаться внутри
него. Побег через `..` не достаёт до хоста — вне монтирований находится только файловая система самого
образа-раннера, — но даёт тихий ложный негатив: скан `filesystem` с целью `.` уходит смотреть образ вместо
исходников, ничего не находит и проходит гейт.

`cacheDir` проверяется в `validateDefaults`: это значение попадает в `-v` и при `cacheDir: "/"` смонтировало
бы корень хоста в контейнер на запись.

Ненулевой код возврата docker трактуется как инфраструктурная ошибка, а не как «найдены уязвимости».

### Ошибки

Каждый класс отказа даёт конкретное сообщение, а не «command failed»:

- docker недоступен → что раннер требует агента с docker и как это проверить;
- `runner` не найден → перечень доступных алиасов;
- БД не скачалась → какой `dbRepository` использовался и с какой авторизацией;
- таймаут → `docker rm -f` контейнера и указание на `timeoutMinutes`.

### Гейт

| Условие | Исход сборки |
|---|---|
| `failOn: none` | Succeeded |
| Находки ниже порога | SucceededWithIssues |
| Есть находки ≥ `failOn` | Failed, с текстом вида «2 CRITICAL ≥ порога CRITICAL» |

### Публикация результатов

- JSON-отчёт — build attachment (`##vso[task.addattachment]`), тип `trivy.report`.
- SARIF — артефакт `CodeAnalysisLogs` (совместимость с существующими SARIF-вьюерами).
- SBOM — отдельный артефакт при `generateSbom != off`.

Несколько тасков в одной сборке дают несколько attachment'ов; вкладка показывает все цели
с переключателем.

## Вкладка результатов

Шапка с причиной падения (сработавший порог, раннер и его образ, дата БД), счётчики по severity
и по типам находок (secrets, misconfig), список целей скана, кнопки выгрузки SARIF и SBOM,
ниже — таблица находок с фильтрами по severity, пакету и наличию исправления.

## Логотип

Щит с горизонтальным градиентом Azure DevOps `#0078d4` → Trivy `#00c2b2`, внутри три полосы
(слои образа) убывающей прозрачности, поверх — жёлтая линия сканера `#ffd166`.
Артефакты: `images/icon.svg` (исходник), `images/icon.png` 128×128 (маркетплейс), баннер для README.
Силуэт проверен на читаемость в 32×32.

## Тестирование (TDD)

Ядро состоит из чистых функций, поэтому основное покрытие — юнит-тесты без docker и без Azure DevOps.

| Что | Как |
|---|---|
| `DockerCommand` | Монтирования, отсутствие секретов в argv, `useDockerSocket`, `extraDockerArgs` |
| `ConfigResolver` | Приоритет значений, отказ при нарушении `allowOverrides` |
| `GateEvaluator` | Три исхода и текст причины |
| `ReportParser` | Фикстуры реального вывода trivy: находки, пустой отчёт, secrets, misconfig, битый JSON |
| `validation` | Один набор тестов гоняется и за админку, и за таск |
| `run.ts` | Подставной `ProcessRunner`: порядок шагов, удаление env-файла в `finally` |
| Интеграция | Подставной скрипт `docker` в `PATH`: записывает argv, отдаёт фикстуру. Ловит расхождение между построенной и реально запущенной командой, не требуя docker в CI |
| UI | `@testing-library/react`: форма раннера (валидация, единственность `isDefault`), вкладка (фильтры, пустое состояние, несколько целей) |

Фикстуры — настоящий вывод trivy в `test/fixtures/`, не выдуманный вручную JSON.
Тесты пишутся по-английски, каждый проверяет одно поведение.

## Структура репозитория

```
azure-trivy-docker-scanner/
  src/shared/        types.ts  validation.ts  severity.ts
  src/task/          index.ts  run.ts  inputs.ts  ConfigClient.ts  ConfigResolver.ts
                     DockerCommand.ts  EnvFile.ts  ProcessRunner.ts
                     ReportParser.ts  GateEvaluator.ts  Publisher.ts  task.json
  src/hub/           hub.tsx  hub.html  components/
  src/tab/           tab.tsx  tab.html  components/
  images/            icon.png  icon.svg  banner.png
  test/fixtures/     trivy/*.json
  docs/superpowers/specs/
  vss-extension.json  webpack.config.js  jest.config.js  tsconfig.json
  .github/workflows/ci.yml
```

Стек как в остальных расширениях этого автора: TypeScript, React 16, `azure-devops-extension-sdk`,
`azure-devops-ui`, webpack, jest + ts-jest, `tfx-cli` для упаковки. У таска отдельная сборка
(Node-таргет, `azure-pipelines-task-lib`), у хаба и вкладки — свои webpack-энтрипоинты.

CI (GitHub Actions): `lint`, `typecheck`, `test` на каждый push; сборка `.vsix` через `tfx` на теге.

## Риски

1. **Чтение Extension Data с агента сборки** — не проверено, что `System.AccessToken` на on-prem
   имеет доступ к `_apis/ExtensionManagement/.../Documents`. На этом держится связка «админка → таск».
   Снимается спайком первой задачей плана: одноразовый таск, дёргающий эндпоинт и печатающий результат.
   Fallback при неудаче — service connection с PAT отдельным полем таска; меняется только `ConfigClient`.
2. **Windows-агенты** — v1 поддерживает Linux-агенты. Windows-агент с Linux-контейнерами вероятно
   заработает, но монтирование путей требует отдельной проверки; ограничение документируется в README.
3. **Версия Node на агенте** — в `task.json` объявляются оба таргета: `Node16` и `Node20_1`.

## Вне области v1

- Каталог целей сканирования и расписание регулярных сканов (админка задаёт только раннеров).
- Fallback на локальный бинарник trivy или его скачивание.
- Azure DevOps Services (облако) как отдельный target манифеста.
- Тренды и история находок между сборками.
