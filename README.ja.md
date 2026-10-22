# agent-web-memory

[English](README.md) | 日本語

Claude Code のエージェントのためのローカルメモリです。WebSearch と WebFetch の呼び出しをすべて 1 つのローカルの SQLite ファイルに記録し、エージェントが同じ Web リサーチを繰り返すときには、以前の調査結果を見せます。データはどこにも送信しません。

## インストール

### 1. バイナリをインストールする

```bash
curl -fsSL https://github.com/Asugawara/agent-web-memory/releases/latest/download/install.sh | sh
```

このスクリプトは、お使いの OS と CPU に合ったアーカイブを GitHub の最新リリースからダウンロードし、その SHA-256 をリリースの `SHA256SUMS` と照合したうえで、`awm` を `~/.local/bin/awm` にインストールします。Claude Code の設定やデータには触れません。実行前にスクリプトを読むことができます: [scripts/install.sh](scripts/install.sh)。チェックサムで分かるのは、ダウンロードの破損や取り違えです。リリース自体が侵害されている場合には守れません。

動作環境: macOS または Linux（Linux は glibc 2.35 以降が必要です。バイナリは Ubuntu 22.04 でビルドしています）、x86_64 または aarch64、`curl` または `wget`、`tar`。Rust も Node.js も不要です。Windows は非対応です。

`~/.local/bin` が PATH に含まれている必要があります。スクリプトが、お使いのシェルに追加する行を表示します。

| オプション | 意味 |
|--------|---------|
| `--version vX.Y.Z` | このバージョンをインストールします。例: `curl -fsSL <url> \| sh -s -- --version v0.1.0` |
| `--force` | そのバージョンがすでにインストールされていても、再インストールします |

| 環境変数 | 意味 |
|-------------|---------|
| `AWM_INSTALL_PREFIX` | バイナリは `$AWM_INSTALL_PREFIX/bin` に置かれます。既定は `~/.local` |
| `AWM_INSTALL_VERSION` | インストールするバージョン。既定は最新リリース |
| `AWM_INSTALL_BASE_URL` | リリースのダウンロード元。既定は `https://github.com/Asugawara/agent-web-memory/releases` |
| `AWM_INSTALL_DOWNLOADER` | `curl` または `wget` |

**ソースからビルドする**（Rust が必要です）:

```bash
git clone https://github.com/Asugawara/agent-web-memory.git
cd agent-web-memory
bash scripts/install-local.sh
```

`awm` バイナリをビルドし、`~/.local/bin/awm` にインストールします。必要に応じて、そのディレクトリを PATH に追加してください。

既存のデータベースの上に、より新しいデータベーススキーマを持つビルドをインストールしたときは、一度 `awm doctor` を実行してください。hook はマイグレーションを行わないため、実行するまでは hook は何も出力せず、キャプチャしたスプールもそのままです（`awm doctor`、`awm import`、`awm init` がマイグレーションを行い、そのあと `awm doctor` がスプールを取り込みます）。

### 2. プラグインを Claude Code に追加する

```bash
claude plugin marketplace add Asugawara/agent-web-memory
claude plugin install agent-web-memory@agent-web-memory
```

### 3. データベースを初期化する

```bash
awm init
```

今後のリサーチを記録するかどうかと、過去のリサーチをトランスクリプトファイルからインポートするかどうかを聞かれます。両方に `y` と答えると、リサーチ履歴をすべて持った状態で始められます。以降は、Claude Code でのすべての WebSearch と WebFetch の呼び出し（メインのエージェントもサブエージェントも）が記録されます。

## 保存されるもの

**Claude Code でのすべての WebSearch と WebFetch の呼び出しについて記録されるもの:**
- 検索クエリまたは fetch のプロンプト（プロンプト内の URL と照合するとき、ログには先頭の 200 文字が残ります）
- 取得した URL、クエリの語、結果のタイトルと URL、HTTP ステータス
- 時刻、セッション ID、呼び出したエージェント（メインのエージェント、またはサブエージェント名）
- 作業ディレクトリのハッシュ

**記録されないもの:**
- プロンプトの全文やコード
- ファイルの内容
- API キー（保存前に伏せ字にします）
- プライベートネットワークの URL

**保存先:**
- データディレクトリ（macOS では ~/Library/Application Support/agent-web-memory/、Linux では ~/.local/share/agent-web-memory/）: データベース awm.db
- このマシンのみ。チームに参加した場合は別です。hook がネットワークリクエストを行うことはありません

**いつでもすべて削除できます:**
```bash
awm purge --all
```

## コマンド

| コマンド | 内容 |
|---------|------|
| `awm init` | ローカルデータベースを作成し、過去のリサーチをインポートします |
| `awm import` | トランスクリプトファイルから再度インポートします |
| `awm search {query}` | 保存されたレコードを検索します |
| `awm log` | エージェントに注入された最近のノートを表示します |
| `awm stats` | 統計を表示します（ツール別・エージェント別のレコード数、隔離されたレコード数） |
| `awm stats --savings` | 表示したノートが節約した時間とトークンを見積もります（`--since YYYY-MM-DD`、`--json`） |
| `awm stats --by repo` | 同じ主要な数値をリポジトリごとに表示します: レコード、注入したノート（`notes`）、拒否（deny）、拒否後の再取得（`--by dir` ならディレクトリごと。`--since YYYY-MM-DD` で集計を絞り込みます。`--savings` と併用すると、グループごとの節約の列が付き、`shown` はノートと拒否の両方を数えます） |
| `awm stats --repo .` | 1 つのリポジトリ（そのワークツリーを含む）だけについて、すべてのセクションを表示します（`--dir PATH` ならディレクトリとその配下すべて） |
| `awm review` | 表示されたノートを確認してラベルを付けます |
| `awm forget` | レコードを削除します: `awm forget last`、`awm forget <url>`、`awm forget --id N`、`awm forget --ref REF`（先に確認を求めます。`--yes` で確認を省略します） |
| `awm purge` | `awm purge --before YYYY-MM-DD` はその日付より古いレコードを削除し、`awm purge --all` はデータディレクトリ全体を削除します |
| `awm quarantine` | レコードを信頼できないものとして印を付けます |
| `awm unquarantine` | 隔離を解除します |
| `awm calibrate` | マッチングのしきい値を調整します |
| `awm setup` | プラグインの連携をセットアップします |
| `awm export` | レコードをエクスポートします |
| `awm reindex` | 検索インデックスを再構築します |
| `awm config` | 設定（モード、チャネル、カットオフ）を表示・変更します |
| `awm doctor` | インストールを点検します |
| `awm where` | データディレクトリとデータベースのパスを表示します |
| `awm report` | バグ報告用の要約を書き出します（個人データは含まれません） |

### 節約の見積もり方

`awm stats --by repo|dir` と `--repo [PATH]` / `--dir [PATH]`（既定は `.`）は、エージェントが作業していた場所で数値を分割、または絞り込みます。リポジトリとは、そのディレクトリを含むメインのチェックアウトのことで、`.git` が見つかるまで上へたどって決めます（リンクされたワークツリーは、作成元のチェックアウトに数えます）。git の外にあるディレクトリは、`(no repository) PATH` として単独で一覧に出ます。`--dir PATH` は、そのディレクトリとその配下すべてを対象にします。`--by` はグループごとに 1 行と `total` 行を出力します（JSON では `by_repo` / `by_dir` で、最後の要素が `total`）。`notes` は注入したノート、`denied` は拒否の数で、`--savings` と併用すると `shown` は両方を数えます。`--repo` と `--dir` は 1 つの範囲についてすべてのセクションを出力し、最初に `scope:` の行が付きます（JSON では、`kind`、`path`、`directories` を持つトップレベルの `scope` オブジェクト）。また `--savings`、`--status`、`--value`、`--followups` と併用できます。awm が作業ディレクトリを覚える前の行は、これらのフラグのどれかを最初に実行したときにトランスクリプトから割り当てます（以降の実行では、変わった分を補います）。注入は、そのトランスクリプトで最も近い行のディレクトリを使い、トランスクリプトがなくなっているときは、そのセッションの最初のレコードのディレクトリを使います（セッションは 1 つのディレクトリにとどまるものと仮定していますが、検証はしていません）。レコードは、`~/.claude/projects` または `~/.codex/sessions` 以下のトランスクリプトが開始されたディレクトリを使います。**この処理はデータベースに書き込みます**（`cwd` テーブルと `injection.cwd_hash`）。どのトランスクリプトにも名前がない分は `(unknown)` として一覧に出し、stderr に報告します。git の外で初めて見つかり、その後チェックアウトになったディレクトリは、同じ実行でそのチェックアウトに割り当てます。存在しなくなったワークツリーのディレクトリ（`.../worktrees/REPO/BRANCH`）は、同名のリポジトリがちょうど 1 つあるときに、そのリポジトリに割り当てます。節約の計算に使う呼び出しコストの中央値は全体のままです（呼び出しのコストはディレクトリによって変わらないため）。上限（繰り返しの呼び出し）は範囲内に限られます。パスはこのマシンにのみ保存・表示され、同期もエクスポートもされません。

`awm stats --savings` は、表示したノートについて、そのあと同じセッションと同じエージェントがその URL やクエリを再び呼び出さなかった場合に、回避できたものとして数えます。見積もりには、同じ URL やクエリの以前の呼び出しの所要時間と要約の長さ（文字数 / 4）の中央値を使います。これは起きなかったことの見積もりなので、`awm review`（ラベル 2）で確認済みの部分、ノートのトークンのオーバーヘッド、履歴にある繰り返しの呼び出しの上限も併せて表示します。また別の行として、取得せずに済んだページのバイト数も表示します。回避した fetch ごとに、その URL の以前の fetch のサイズの中央値を取り、要約器のトークン = バイト数 / 4 とします。これは上限です。ページを読むのは Claude Code の fetch 要約器で、メインのモデルはそのトークンを見ないため、表では専用の列に分けています。API 課金ではコスト、サブスクリプションでは使用量であり、金額ではありません。検索には 0 を加えます。最初の要約行では、要約器のトークンとメインモデルの正味を 1 つの正味にまとめ、両方の内訳を表示します。要約器を動かさずに済むことが、回避した fetch の節約の大部分だからです。

`cost` 列は、これらの数値を金額で見積もります。回避した fetch ごとに、要約器のトークンを入力レートで、その要約を出力レートで計算し、回避した検索ごとに Web 検索の料金を計算します。レートは `config.toml` にあり（`awm config set pricing.<key> <value>` で変更します。負の値はエラーです）、既定は Claude Haiku 4.5 の価格です:

```toml
[pricing]
currency = "USD"
summariser_input_per_mtok = 1.0    # Claude Haiku 4.5 input, USD per million tokens
summariser_output_per_mtok = 5.0   # Claude Haiku 4.5 output (the summary it returns)
search_fee_per_call = 0.01         # Anthropic web search: USD 10 per 1,000 searches
main_input_per_mtok = 0.0          # your main model's input price; 0 = not priced
```

メインモデルのトークンは、`main_input_per_mtok` を設定したときだけ金額に換算します。その場合、最初の要約行には、ノートのオーバーヘッドを引いた正味のコストも表示されます。サブスクリプションでは呼び出しごとの支払いは発生しないので、このコストは、同じ呼び出しを API 課金で行った場合にかかる金額として読んでください。

### 繰り返しの遮断（ショートサーキット）

awm がすでに持っている URL の fetch は、代わりにレコードから答えます。**WebFetch は URL ごとのキャッシュです**。既定でオンで、期間は 7 日です。以前のリサーチがすでに答えている検索も、同じように 1 回だけ拒否（deny）されます。拒否の理由は 1 行です（Claude Code の TUI では hook のエラーとして表示されます）。以前の答えは、その隣に追加コンテキストとして届き（Claude Code）、Codex ではその行の下に届きます。誰が、いつ、何を聞いたかは含まれません。このエージェントが以前の `<awm-notes>` ブロックでそのレコードをすでに見せられている場合、拒否は呼び出しをブロックしますが、その 1 行はテキストを繰り返さず、答えはすでにエージェントのコンテキストにあることだけを（ノートの ref とともに）伝えます。シャドウモードはありません。設定はオンかオフかのどちらかです。

| キー | 既定 | 値 | 意味 |
|-----|---------|--------|---------|
| `short_circuit.mode` | `on` | on, off | awm が使える以前の fetch を持っている URL への WebFetch を拒否します |
| `short_circuit.window_days` | 7 | 1-365 | 以前の fetch を何日前まで有効とするか（日数） |
| `short_circuit.query` | `on` | on, off | 以前のリサーチと一致する WebSearch（Claude Code）または `webrun`（Codex）を拒否します |
| `short_circuit.query_window_days` | 7 | 1-365 | クエリの拒否がさかのぼる日数 |
| `short_circuit.query_min_score` | `auto` | 0-1000, `auto` | クエリの拒否で、調整済みのカットオフの代わりに使う固定のスコアカットオフ |

**URL の拒否**には、期間内に、あなた側の誰かが同じ URL を fetch した記録が必要です。同じエージェント、兄弟のサブエージェント、別のセッションやプロジェクト、別のマシンのいずれでも構いません。以前の fetch は、ステータスが ok で HTTP コードが 200 であるか、HTTP コード 202、3xx、または 429 以外の 4xx を伴う行き止まりである必要があります（403、404、または内容を返さないリダイレクトを返した URL は、繰り返しても成功しなかったものとして扱います。その場合、理由は "this URL returned HTTP 404 when fetched earlier and gave no usable content" となり、本文はありません）。隔離または削除されていてはならず、チームメイトのレコードは数えません。タイムアウトなどコードのない失敗、429、5xx、拒否応答では、拒否は行いません。拒否の種類は、使える最新のレコードで決まります。1 つの URL に以前の答えが複数あるときは、保存された質問と答えに対して BM25 があなたの質問に最も近いと評価したものを渡します（同点なら最新）。スコアは Rust で、その URL の最新 20 件の答えだけを対象に、それらの答えから取った idf と平均長で計算するので、データベースが大きくなってもコストは増えません。サブエージェントにも適用されます。理由は 1 行で、"agent-web-memory: an earlier answer for this URL is attached as additional context. If it does not answer your prompt, call WebFetch again with the same URL; it will not be blocked again." です。以前の答え（答えのテキストのみ。最大 8,000 文字、誰がいつ得たかは含みません）は、エラーの隣に追加コンテキストとして渡されます。ただし、エージェントがすでにそのレコードを持っている場合（セッションの前の方で `<awm-notes>` ブロックとして見せられた、または自分でその URL を fetch した）は別です。その場合も呼び出しは拒否されますが、1 行はその旨だけを伝え（"the earlier answer for this URL is already in your context (agent-web-memory note ref ...)" または "you fetched this URL earlier in this session and its result is already in your context"）、本文はありません。サブエージェントは自分のコンテキストを持つので、答えを受け取ります。同じ呼び出しをもう一度行うと必ず通ります。拒否はセッション、エージェント、URL ごとに 1 回なので、同じページへの新しい質問は 1 回やり直すだけです。

**クエリの拒否**は類似度に基づきます。awm は、検索後にノートを追加するのと同じ BM25 マッチ（`matching::query_channel`、読み取り専用）を検索テキストに対して実行します。拒否のカットオフ以上のスコアの以前のレコードがあると、検索は 1 回だけ拒否され、1 行の理由（"agent-web-memory: earlier research matching this search is attached as additional context. If it does not answer your question, call WebSearch again with the same query; it will not be blocked again."）とともに、最大 `inject.max_notes` 件が追加コンテキストとして届きます。各レコードの URL と見つかったテキストだけで、それ以外は含みません（Codex ではその行の下に届きます）。`short_circuit.query_window_days` の期間内にある、使える以前のレコードはすべて対象です（同じエージェント、兄弟、別のセッションやプロジェクト、別のマシン。チームメイトのものは対象外）。ステータスが ok で、見つかった内容が空でないことが条件です。そのエージェントにすでに表示したノートは、再び渡しません。エージェントがすでにコンテキストに持っているレコード（同じセッションの前の方で渡されたノート、または自分で fetch や検索をした結果）も繰り返しません。その場合も呼び出しは拒否され、1 行はエージェントが持っているものを指します（"earlier research matching this search is already in your context (agent-web-memory note ref ...; your own WebSearch "..." earlier in this session)"）。`allowed_domains` / `blocked_domains` を指定した検索と、通常の検索以外の Codex の呼び出しは拒否しません。同じ検索テキストをもう一度行うと必ず通ります（セッション、エージェント、テキストごとに 1 回）。検索の拒否には、ノートより厳しい調整済みカットオフを使います（上位スコアの 75 パーセンタイル、`cutoff.query_deny`。`awm calibrate` で表示されます）。`short_circuit.query_min_score` で上書きできます。BM25 は類似度のマッチであり、一致の判定ではありません。測定した厳密な適合率は、中央値のカットオフで 0.52 でした。そのため、拒否のなかには、質問に答えていないノートを渡してしまうものがあります。`awm stats` の `query_deny.research_after_deny` は、エージェントが 2 分以内にもう一度検索した頻度を示します。オフにするには `awm config set short_circuit.query off` を実行します。

URL の拒否をオフにするには `awm config set short_circuit.mode off` を実行します。ノートにエージェントごとの上限はありません。`inject.max_notes`（3）が 1 回の注入の上限です。

以前のバージョンの設定も引き続き使えます: `shadow` は、`mode` では `inject`、`short_circuit.mode` では `on`、`short_circuit.query` と `channels.prompt_bm25` では `off` として読み取られます。`short_circuit.subagents`、`short_circuit.window_minutes`（`short_circuit.window_days` を使ってください）、`short_circuit.query_window_minutes`（`short_circuit.query_window_days` を使ってください）、`inject.max_per_agent` は無視されます。`awm doctor` が、それぞれを置き換え先とともに一覧にし、`awm config set` は受け付けません。

`awm stats` は `query_deny` オブジェクトを出力します。内容は、`denied` の件数、エージェントの種類別（main、subagent）、関係別（同じエージェント、兄弟、同じプロジェクトの別のセッションまたは別のプロジェクト、別のコーディングエージェント）、経過時間別（30 分以内、24 時間以内、累計）、`awm review` のラベル 2 / 1 / 0 / h、`per_100_searches`、`research_after_deny`（拒否のあと 2 分以内に同じエージェントが同じ検索を繰り返した件数と、その割合）、`cutoff_used`（拒否のカットオフと、それが `calibrated` か `config` 由来か）、`by_top_score`（最良のノートのスコア別の拒否と再試行された拒否: `<30`、`30-40`、`40-60`、`60+`）です。`injections.refetch_after_deny` は、URL の拒否のあと、同じエージェントが同じ URL をもう一度 fetch した件数を数えます。`awm stats --followups` は、ノートのあとに同じ URL の fetch が続いたものを、間隔（`by_age`）と、以前の fetch を行った人（`by_who`: 同じエージェント、兄弟、別のセッション）で分けます。`awm review` では、クエリの拒否に、以前の検索の関係と経過時間、そして付けられた理由が表示されます（ラベル 2: 以前の見つかった内容が、エージェントの次の行動をカバーしていた。1: 関連はあるが、エージェントには新しい結果が必要だった。0: 同じ必要ではない。h: 以前の見つかった内容が誤っていた、または古かった）。`injections.deny_by_kind` は URL の拒否を `cached`（答えを渡した）、`cached_shown`（すでにエージェントのコンテキストにあった）、`dead_url` に分けます。

## Codex

Codex のサポートは実験的です（2026-10-02 に開始、Codex CLI 0.159.3 で動作確認しています）。

**できること**
- 以前のリサーチについてのノートが、プロンプトとともに表示されます（`UserPromptSubmit`）。ノートには、以前の結果が全文で入ります（無害化済み、最大 8,000 文字）。ノートのブロックは最大 9,500 文字、約 2,400 トークンです。
- Codex の `webrun` ツールによる Web 検索のあとにノートが表示され、現行のモデルでは検索が完全な結果とともにキャプチャされます。

**できないこと**
- 古いホスト型の Web 検索は、ロールアウトにクエリと URL しか残さず、結果のテキストがありません。hook がまったく動作しない場合もあります（未検証）。
- Codex には fetch ツールがないため、fetch のノートはありません。
- プロジェクトレベルの `.codex/hooks.json` は読み込まれません。hook は `~/.codex/hooks.json` に置く必要があります。

**有効にする**
```bash
awm setup --codex-hooks
```
エントリを表示し、先に確認を求め（`--yes` で確認を省略します）、バックアップ `hooks.json.awm-backup` を残し、ほかの hook には手を加えません。Codex が PATH を引き継がないことがあるため、`awm` バイナリの絶対パスを書き込みます。そのあと `codex` を実行し、`/hooks` と入力して、awm のエントリを一度だけ信頼してください。`$CODEX_HOME` が設定されていれば、それに従います。

**無効にする**
```bash
awm setup --remove-codex-hooks
```

## プライバシー

- **ローカルファースト**: リサーチはお使いのマシンにとどまります。チームに参加した場合は、バックグラウンドの `awm sync` が、共有するプロジェクトのレコードをエンドツーエンドで暗号化して送信します。hook がネットワークを待つことはありません。
- **伏せ字**: API キーとシークレットは、保存前に伏せ字にします。
- **削除可能**: `awm forget` と `awm purge` は、レコードを完全に削除します。`awm config set mode off` は、何も削除せずに記録を一時停止します。
- **自分で管理できる**: `awm config` で、チャネルをオフにしたり、マッチングのしきい値を調整したり、記録を一時停止したりできます。

## アップデート

インストールコマンドをもう一度実行してください。より新しいリリースがあれば、バイナリを置き換えます。`--force` を付けると、同じバージョンを再インストールします。

```bash
curl -fsSL https://github.com/Asugawara/agent-web-memory/releases/latest/download/install.sh | sh
```

そのあと、一度 `awm doctor` を実行してください。hook はデータベースをマイグレーションしないためです。

## アンインストール

何も削除せずに一時停止するには:
```bash
awm config set mode off
```

すべて削除するには:

1. **データベースを削除する:**
   ```bash
   awm uninstall
   ```
   データディレクトリのサイズとレコード数を表示し、確認後に削除します。

2. **Claude Code からプラグインを削除する:**
   ```bash
   claude plugin uninstall agent-web-memory@agent-web-memory
   claude plugin marketplace remove agent-web-memory
   ```

3. **バイナリを削除する:**

   スクリプトでインストールした場合:
   ```bash
   rm ~/.local/bin/awm
   ```
   （`$AWM_INSTALL_PREFIX/bin/awm` を設定していた場合は、そちらを削除します）

   チェックアウトからビルドした場合:
   ```bash
   bash scripts/uninstall-local.sh
   ```

## FAQ

### なぜキャッシュではないのですか？

awm がすでに持っている URL の fetch については、キャッシュとして働きます。呼び出しは 1 行の理由とともに 1 回だけ拒否され、以前の答えの全文が追加コンテキストとして渡されます（「繰り返しの遮断」を参照）。同じ呼び出しをもう一度行うと必ず通るので、エージェントは新しいページを取得でき、ページが変わっていても、やり直しは 1 回で済みます。以前のリサーチが答えている検索も、同じように 1 回だけ拒否されます。それ以外の場合（新しい URL、以前の検索に似ているだけの検索）は、awm が呼び出しをブロックすることはありません。以前の質問、URL、見つかった内容を、新しい結果の*隣に*表示し、どうするかはエージェントが決めます。拒否をオフにするには、`awm config set short_circuit.mode off` と `short_circuit.query off` を実行します。

### なぜローカルファーストなのですか？

リサーチをアップロードすると、自分では管理できなくなるプライバシーの境界ができてしまいます。ローカルファーストなら、自分でコピーしない限り、データがマシンの外に出ることはありません。チーム同期は任意です。チームに参加する場合、セルフホストの選択肢は `docs/self-host.md`、共有されるフィールドは `docs/sync-v1.md` を参照してください（プロンプト、トランスクリプト、ファイルパスがマシンの外に出ることはありません。要約は既定で 1,000 文字に切り詰められ、認証が必要な SaaS のページで共有されるのは URL とタイトルだけです）。

### サブエージェントでも動きますか？

はい。agent-web-memory は、各サブエージェントに、*同じセッション内*（ほかのサブエージェント）*と、セッションをまたいだ*（過去のリサーチ）以前のリサーチのノートを見せます。サブエージェントだけが行ったリサーチは、メインのエージェントには伝わりません。そのため、セッションのコンテキストが軽く保たれます。

## バグ報告・フィードバック

GitHub で issue を作成するか、`awm report` を実行して issue テンプレート用の要約を取得してください。何か壊れている場合は、`awm doctor` の出力も添えてください。
