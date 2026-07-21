# Notion Local MCP Easy 1.5.0 (Universal)

One-click Windows MCP-сервер для личного использования с Notion Agent. Агент получает инструменты для чтения, поиска и изменения файлов в выбранной рабочей папке. При необходимости можно отдельно включить доверенный developer-режим с Python, Git, Node и тестами.

Начиная с 1.5.0 сервер универсальный: помимо статического Bearer-токена для Notion он умеет OAuth 2.1 поверх Streamable HTTP для Hyperagent и других MCP-клиентов. Режим авторизации выбирается отдельно (`legacy` по умолчанию — поведение 1.4.x без изменений). Подробности: раздел «Universal OAuth».

> Проект предназначен для собственного компьютера и доверенного агента. Это не многопользовательский публичный сервис.

## Запуск за несколько минут

1. Распакуйте архив в любую папку.
2. Дважды кликните `START.bat`.
3. При первом запуске выберите рабочую папку.
4. Оставьте **trusted developer mode выключенным**, если нужны только файловые инструменты. Для написания и запуска кода его можно включить ответом `y`.
5. Скопируйте показанные `URL` и `Bearer token` в Custom MCP вашего Notion Agent.
6. Не закрывайте окно запуска во время работы.

При последующих запусках повторная настройка не требуется. Конфигурация хранится в `%LOCALAPPDATA%\NotionMcpEasy` и не входит в архив проекта. Начиная с 1.4.2 список быстрых переключений между рабочими областями хранится в `%LOCALAPPDATA%\NotionMcpEasy\connections.cfg`: при `MENU = on` сервер показывает сохранённые пути и меняет только текущий `workspace` в `config.json`, не пересоздавая токен. При stable Serveo hostname адрес MCP сохраняется; в temporary mode после перезапуска URL меняется и его нужно обновить в Notion.

## Управление

- `START.bat` — создать локальное `.venv`, установить зависимости и запустить сервер с туннелем. Если `connections.cfg` содержит `MENU = on`, перед стартом появится меню сохранённых рабочих областей.
- `STOP.bat` — остановить только процессы этого MCP после проверки их идентичности.
- `SETUP.bat` — заново пройти мастер настройки; токен при повторном setup сохраняется, а выбранная рабочая область попадает в `connections.cfg`.
- `SHOW_CONNECTION.bat` — показать текущие URL, workspace и режимы; токен и OAuth owner code маскируются, `--full` показывает их полностью.
- `OAUTH_SETUP.bat` — выбрать режим авторизации `legacy / oauth / dual` и сгенерировать OAuth owner code.
- `REGISTER_OAUTH_CLIENT.bat` — заранее зарегистрировать OAuth-клиент для режима «Bring my own OAuth app».

## connections.cfg

Пользовательский файл `%LOCALAPPDATA%\NotionMcpEasy\connections.cfg` создаётся автоматически и содержит:

- `MENU = on/off` — показывать ли меню выбора рабочей области при старте;
- `PATH[1] ... PATH[9]` — стартовые слоты для сохранённых путей;
- дополнительные слоты `PATH[10]`, `PATH[11]` и дальше можно добавлять вручную или через меню, если базовые места заняты.

Когда меню включено, запуск показывает только занятые слоты и предлагает:

- выбрать сохранённую рабочую область по номеру;
- нажать `0`, чтобы задать новую папку и сохранить её в свободный слот;
- нажать `q`, чтобы отключить меню и оставить последнюю выбранную область в `config.json`.

Все подсказки во время запуска сообщают точные пути к `connections.cfg` и `config.json`. Файл `connections.example.cfg` в архиве служит только шаблоном и не содержит пользовательских путей.

## Режимы

### File-only mode — по умолчанию

Файловые инструменты разрешены только внутри выбранного workspace. Пути нормализуются, а выход через `..`, абсолютные пути и ссылки наружу отклоняется.

### Trusted developer mode — опционально

Добавляет запуск разрешённых программ без `cmd.exe` и PowerShell:

```text
python, py, pip, git, node, npm, npx, pytest, ruff, make, uv
```

Это **не песочница**. Python, Node, Git hooks, npm scripts и другие инструменты могут обращаться ко всей системе и сети с правами текущего пользователя Windows. Включайте режим только для личного доверенного агента. Git через MCP теперь проходит через отдельный setup-flow: без local repo context (`agent-repo-config.local.json`) обычные git-команды блокируются, а агент должен сначала либо привязать существующий репозиторий, либо инициализировать новый, либо явно отключить git для этой папки. Если сервер собирается принять значения по умолчанию или изменить уже сохранённую git-привязку, агент обязан запросить явное подтверждение пользователя.

## Архитектура

```text
Notion ─────── static Bearer ─┐
                              ├─ /mcp → общий набор MCP-инструментов
Hyperagent ── OAuth 2.1 ──────┘
    -> HTTPS (Serveo SSH reverse tunnel)
    -> 127.0.0.1:8765
FastMCP server
    -> выбранный workspace
```

Сервер слушает только localhost. В режиме `legacy` все HTTP-маршруты, включая `/health`, требуют токен — поведение 1.4.x без изменений. В режимах `oauth`/`dual` endpoint `/mcp` защищён проверкой токена per-request (legacy и/или OAuth), discovery-маршруты OAuth публичны по спецификации, а `/health` принимает операторский токен запуска. FastMCP Host-проверка отключена намеренно: Serveo выдаёт случайное публичное имя, которое иначе приводило бы к HTTP 421; вместо неё работает собственный Host-allowlist.

Serveo — сторонний туннель. В быстром анонимном режиме URL меняется после перезапуска. Если в Serveo зарезервировать hostname и добавить SSH-ключ, мастер включает stable mode: адрес вида `https://my-name.serveousercontent.com/mcp` сохраняется после перезапусков и добавляется в Notion один раз. Для OAuth-режимов зарезервированный hostname обязателен.

## Universal OAuth (Hyperagent и другие MCP-клиенты)

### Режимы авторизации

```text
legacy  — только статический Bearer token (по умолчанию; Notion, как в 1.4.x)
oauth   — только OAuth 2.1 (Hyperagent); Bearer-токен работает лишь на /health
dual    — Bearer token И OAuth одновременно на одном /mcp
```

Режим выбирается через `OAUTH_SETUP.bat` и хранится в `config.json`. Набор MCP-инструментов, границы workspace, chunking и git-политика общие для всех режимов — меняется только слой авторизации.

### Быстрое подключение Hyperagent

1. В `SETUP.bat` настройте **зарезервированный Serveo hostname** (обязательно для OAuth).
2. Запустите `OAUTH_SETUP.bat`, выберите `dual` (Notion + Hyperagent) или `oauth`. Мастер сгенерирует **OAuth owner code** — код владельца для подтверждения подключений.
3. Запустите `START.bat`.
4. В Hyperagent: `Add MCP server` → Streamable HTTP → URL `https://<hostname>.serveousercontent.com/mcp`. Поле `Advanced` заполнять не нужно — сервер публикует discovery metadata.
5. Если `Bring my own OAuth app` **выключен**, Hyperagent зарегистрируется сам через Dynamic Client Registration и откроет страницу подтверждения `/consent`.
6. На странице `/consent` проверьте имя клиента и запрошенные права, введите OAuth owner code (показывается в окне запуска и через `SHOW_CONNECTION.bat --full`) и нажмите **Approve**.
7. Если `Bring my own OAuth app` **включен**, сначала выполните `REGISTER_OAUTH_CLIENT.bat`: введите redirect URL из Hyperagent, получите `client_id` (для public PKCE-клиента secret не нужен) и внесите значения в Hyperagent. Дальше тот же `/consent`-флоу.

### Что реализовано

- OAuth 2.1 Authorization Code Flow + PKCE (`S256`, единственный поддерживаемый метод);
- Dynamic Client Registration (`POST /register`) и заранее зарегистрированные клиенты;
- строгая проверка `redirect_uri` (https или локальный loopback) и передача `state`;
- короткоживущие access-токены (1 час по умолчанию) с audience-привязкой к `/mcp` (RFC 8707);
- refresh-токены с ротацией: старый refresh и связанные access-токены гаснут при каждом обновлении;
- одноразовые authorization codes: повторное использование кода отзывает выданные по нему токены;
- `POST /revoke` для отзыва токенов;
- discovery: `/.well-known/oauth-authorization-server` (RFC 8414), `/.well-known/oauth-protected-resource/mcp` (RFC 9728, плюс root-алиас) и `WWW-Authenticate` с `resource_metadata` при 401.

### Scopes

| Scope | Инструменты |
| --- | --- |
| `mcp:files:read` | `workspace_info`, `list_dir`, `file_info`, `read_file`, `glob_files`, `grep_files` |
| `mcp:files:write` | `write_file`, `append_file`, `edit_file`, `create_dir`, `delete_file`, `copy_file`, `move_file` |
| `mcp:commands:run` | `run_command` (дополнительно требуется trusted developer mode) |
| `mcp:git` | `repo_context_status`, `inspect_git_repository`, `configure_repo_context`, `setup_git_context` |

Проверка scope выполняется перед каждым вызовом инструмента (deny-by-default: инструмент без известного scope не регистрируется). Токен только с `mcp:files:read` не может изменять файлы, запускать команды или трогать git. **Легаси Bearer-токен остаётся мастер-токеном с полным доступом** — это осознанное решение для личного сервера, учитывайте его при передаче токена.

Ограниченный клиент создаётся через `REGISTER_OAUTH_CLIENT.bat` (укажите поднабор scopes) или когда клиент сам запрашивает узкий `scope` при регистрации/авторизации.

### Стабильный URL обязателен

При смене публичного URL меняются issuer, discovery-ссылки, redirect-конфигурация и audience уже выданных токенов, поэтому launcher **блокирует** запуск `oauth`/`dual` на временном Serveo URL. Разрешённые варианты: зарезервированный Serveo hostname (или свой стабильный https-домен через `MCP_PUBLIC_URL`). Для локальных экспериментов существует переменная `MCP_OAUTH_ALLOW_TEMPORARY_URL=1` — с ней сервер работает на `http://127.0.0.1:<port>` без туннеля.

### Хранение OAuth-состояния

Файл `%LOCALAPPDATA%\NotionMcpEasy\oauth_state.json` содержит зарегистрированных клиентов и **SHA-256 хеши** access/refresh-токенов — сырые значения токенов на диск не пишутся. Файл не входит ни в git, ни в release-архив. Благодаря нему клиенты и refresh-токены переживают перезапуск сервера: при stable hostname Hyperagent переподключается без повторного подтверждения.

Переменные тонкой настройки: `MCP_OAUTH_ACCESS_TTL` (сек, по умолчанию 3600), `MCP_OAUTH_REFRESH_TTL` (по умолчанию 30 дней), `MCP_OAUTH_CONSENT_MAX_ATTEMPTS` (5), `MCP_OAUTH_CONSENT_LOCKOUT_SECONDS` (900).

## Инструменты

- `workspace_info` — workspace, активный режим, root repo и краткий обзор nested repo;
- `repo_context_status`, `inspect_git_repository` — диагностика git и следующего безопасного шага;
- `setup_git_context`, `configure_repo_context` — инициализация, привязка, перепривязка или отключение git для конкретной папки с обязательным выбором branch policy;
- `list_dir`, `file_info`, `read_file`;
- `write_file`, `append_file`, `edit_file`;
- `create_dir`, безопасное нерекурсивное `delete_file`;
- `copy_file`, `move_file` — только отдельные файлы;
- `glob_files`, ограниченный текстовый `grep_files`;
- `run_command` — только в trusted developer mode.

`read_file()` теперь читает длинные файлы частями: показывает диапазон строк, общее число строк и `next offset` для продолжения. Если `run_command()`, `grep_files()` или `list_dir()` возвращают слишком большой результат, MCP сохраняет полный вывод во временный файл и отдаёт первую безопасную часть с путём вида `@temp/...` для продолжения через `read_file()`.

Regex-поиск отключён, чтобы исключить зависание на патологических выражениях. Обычный регистронезависимый поиск остаётся доступен.

## Ограничения

- текстовый файл для чтения и итогового append/edit: до 5 МБ;
- один write/append: до 2 МБ;
- `read_file()` по умолчанию выдаёт до 400 строк, но в первую очередь ограничивается безопасным бюджетом около 9 500 символов, сохраняя целые строки;
- небольшие результаты команд отдаются напрямую, а большие автоматически сохраняются во временный файл и продолжаются через `read_file()`;
- `git` через MCP запрещён, пока не завершён local setup-flow: при отсутствии `.git` агент должен спросить пользователя, создаём новый репозиторий, подключаемся к существующему или временно отключаем git;
- при настройке repo context пользователь теперь должен явно выбрать branch policy: коммит в ветку по умолчанию (`default_branch`) или в явно заданную ветку (`commit_branch`);
- после настройки MCP сверяет `remote.origin.url` с сохранённой локальной привязкой и блокирует git при несовпадении, а commit/push/merge/rebase блокирует вне выбранной ветки;
- если настройка git уже сохранена, её нельзя молча менять: для default-значений и для перепривязки требуются отдельные явные подтверждения пользователя;
- обычные mutating git-команды вроде `reset`, `checkout -B`, `tag`, `config` и `remote set-url` теперь дополнительно фильтруются политикой MCP и не должны обходить setup-flow.
- временные MCP-файлы используют путь вида `@temp/...`, лежат в `temp/` рядом с `server.py`, удаляются после финального чтения и дополнительно очищаются при старте;
- timeout команды по-прежнему останавливает дерево процесса;
- рекурсивное удаление и перемещение каталогов через MCP отсутствуют;
- `node_modules`, `.venv`, `.git` и кэши пропускаются при рекурсивном просмотре.

## Требования

- Windows 10/11;
- Python 3.11+ с опцией `Add Python to PATH`;
- встроенный OpenSSH Client (`ssh.exe`);
- интернет при первой установке и для Serveo.

## Проверка

```bat
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\ruff check .
```

Тесты покрывают path traversal, allowlist, занятый порт, PID-проверку, правильный и неправильный токены, Serveo Host без HTTP 421, chunked-выдачу, repo bootstrap / disable / mismatch guard и timeout процесса. OAuth-набор дополнительно проверяет discovery, DCR, PKCE (включая неверный verifier), state, consent с owner-кодом и lockout, scope-ограничения per tool, ротацию refresh-токенов, replay authorization code, отзыв токенов, dual-режим (Bearer + X-API-Key + OAuth параллельно) и переживание перезапуска сервера выданными токенами.

## Что улучшено относительно оригинала

- автоматический setup без ручного редактирования BAT-файлов;
- токен и runtime вне проекта;
- localhost-only bind и обязательная Bearer-авторизация;
- правильная проверка границ workspace;
- файловый режим безопаснее и включён по умолчанию;
- команды вынесены в явно доверенный режим;
- нет shell, фоновых команд, HTTP downloader и чтения env через MCP;
- автоматический перевод больших результатов в temp-файлы с продолжением через `read_file()` вместо попытки отправить всё модели одним ответом;
- обязательный setup-flow для git: bind existing / init new / attach existing remote / disable git with persisted local policy;
- локальная repo-привязка для Git с проверкой `origin` после перезапуска MCP;
- проверка занятого порта до создания туннеля;
- проверка идентичности PID перед остановкой;
- фиксированные зависимости, тесты, changelog и security model.

Подробная модель безопасности: `SECURITY.md`. История версий: `CHANGELOG.md`.

## Git setup-flow для агента

Если обычная git-команда вызывается впервые для этой папки, MCP больше не пытается угадывать репозиторий. Вместо этого агент должен сначала вызвать `repo_context_status()` и, при необходимости, предложить пользователю выбор:

1. `setup_git_context(mode="init_new_repo", repository_url="...", fork_status="fork|not_fork", branch_mode="default_branch|specified_branch", default_branch="main", commit_branch="stablefix")`
2. `setup_git_context(mode="attach_to_remote", repository_url="...", fork_status="fork|not_fork", branch_mode="default_branch|specified_branch", default_branch="main", commit_branch="stablefix")`
3. `setup_git_context(mode="bind_existing_repo", repository_url="...", fork_status="fork|not_fork", branch_mode="default_branch|specified_branch", default_branch="main", commit_branch="stablefix")`
4. `setup_git_context(mode="disable_git")`

Это состояние сохраняется в `agent-repo-config.local.json` в корне workspace и переживает перезапуск MCP. Вместе с repo URL там хранится branch policy: либо коммиты разрешены только в ветку по умолчанию, либо только в явно заданную ветку. Файл intentionally local-only: он исключён из Git и release-архивов.

## Сборка архива для отправки

Запустите `BUILD_RELEASE.bat`. Архив `notion-mcp-easy-<версия>.zip` появится в папке `release/` внутри проекта. Эта папка создаётся автоматически, исключена из Git и не попадает в сам release-архив. Сборщик автоматически исключает `.venv`, кэши, логи, ZIP-файлы, временную папку `temp/`, папку `release/`, локальные repo-файлы и файлы конфигурации/токенов.

## Полный гайд Serveo

Подробная инструкция по временному и постоянному URL, созданию аккаунта, SSH-ключа, резервированию hostname, настройке Notion и устранению ошибок находится в `SERVEO_SETUP.md`.
