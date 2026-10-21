# Sigil Proxy 작업 상태

갱신: 2026-10-21 · Claude Code orchestrator 세션 (기준 커밋 `6a90e5f`)

## 현재 상태

- **P0 종료(2026-10-11, 계약 수준, 사용자 결정).** 잔여 항목과 담당 P1 작업은 [decisions.md "P0 종료"](decisions.md).
  계약 종료는 구현·실기 검증 완료가 아니다.
- P1 착수. 사용자 창구: 이 대화의 orchestrator. 하위 모델은 orchestrator가 작업별로 지정한다(판단 sonnet, 기계적 검증 haiku).
- 이전 회차 작업자 16명은 2026-10-11 모두 종료했다.

## 2026-10-11 P1 1회차 배정 (기준 `2120415`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| P0-exit-audit | sonnet (spec auditor, 읽기 전용) | P0 종료 조건·잔여 분류·추적성 | 전체 | 없음 | — |
| P1-plan | sonnet (planner, 읽기 전용) | T-10/T-11 구현 계획·슬라이스 | T-10/T-11 | 없음 | — |
| PR0 | sonnet (coder, worktree) | `sigil-proxy-api` wire DTO crate + golden 테스트 | PX-005/006/010/011/016, AC-05/06 | `crates/sigil-proxy-api/**`, workspace `members` | #244 |
| T-10 A–D | sonnet (coder, worktree, PR0 브랜치 기반) | `sigil-proxy` 골격·bootstrap·limits·state_dir·rpm/systemd | PX-001/013/016, AC-07/12/14 | `crates/sigil-proxy/**`, `packaging/` proxy 파일 | #245 |
| T-11 S1 | sonnet (coder, worktree, PR0 브랜치 기반) | server proxy 신원·등록, 404 `proxy_unknown` 선검사 | PX-008/009, AC-04 | `crates/sigil-server/src/proxy/**` 외 배정 시 명시 | #246 |

진행: P0-exit-audit completed(코딩 착수 차단 항목 없음, 문서 gate 문구만 남음 → P0 종료 문서 반영). P1-plan completed(PR0 → T-10 갈래 A와 T-11 S1 병렬 → S2–S5 순차; app.rs·config.rs는 한 작성자). fixture 14 tests orchestrator 재실행 통과. PR0 coder completed → 독립 리뷰 needs_changes(M-1 serde 오류의 값 echo, M-2 validate 비재귀, L-1–L-4) → fix → 재확인 **approve**(차등 298건·canary 18건) → PR #248. T-10 A–D(#245): coder → 리뷰 accept with fixes(M1 origin 정규화·http 정책, M2 fd 기반 파일 검사) → fix(공유 verifier를 sigil-proxy-api로) → 재확인 accept → PR #249(#248 위 stacked). T-11 S1(#246): coder → 보안 리뷰 approve-with-fixes(M1 판정 불가 issuer, M2 e2e 격리, M3 registry 로드) → fix → 재확인 approve(release 빌드에 test seeding 없음 확인) → PR #250(#248 위 stacked). T-10 E 패키징(#245): coder → 리뷰 request changes(H1 CI 포트 상수 오류, H2 릴리스가 미완성 binary 공개) → fix(전용 `sigil-proxy` 사용자, 릴리스 제외) → 재확인 approve → PR #253 머지. T-11 S2a(#251): coder → 보안 리뷰 approve with changes(M1 fsync 중 registry 잠금, M2 승격 감사 트랜잭션 밖) → fix → 재확인 approve → PR #255 머지(Windows 빌드 import 수정 포함). 후속 이슈 #252(deb sysusers 공유 파일 충돌), #254(감사 체인 helper 공유).

### 1회차 머지 결과 (2026-10-11)

| PR | 작업 | 이슈 |
|---|---|---|
| #247 | P0 종료 문서 | — |
| #248 | PR0 `sigil-proxy-api` | #244 |
| #249 | T-10 A–D `sigil-proxy` 골격 | #245 |
| #250 | T-11 S1 신원·등록·404 guard | #246 |
| #253 | T-10 E 패키징(설치만, 비활성, 릴리스 제외) | #245 |
| #255 | T-11 S2a 관리 인증·감사·lifecycle·운영자 CLI | #251 |

남은 P1: T-11 S2b(CSR 서명), S3(config·status), S4(ledger·ingest), S5(projection·조회), T-12 relay, T-13, T-14, T-15(manager, sigil-manager#37), T-16.
실기 미검증: Rocky 9 SELinux enforcing·systemd `is-enabled`(컨테이너에 systemctl 없음), x86_64 baseline.
교훈: unix 전용 코드의 import도 `cfg(unix)`로 막는다(Windows CI 실패 2회). 후속: `parse_entry_view`, ParseError 분류 marker 위조(T-11 S4), upload proxy_id 대조(server).

## 2026-10-12 P1 3회차 배정 (기준 `bbe48c8`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| T-12c1 | sonnet (coder, worktree) | proxy config fetch·apply, #260 한도 min·verifier `not_after`·origin 공유 | PX-005/008/012/016, AC-04/12 | `crates/sigil-proxy/**`, `crates/sigil-proxy-api/**` | #263 |
| T-12c2 | sonnet (coder, worktree, T-12c1 뒤) | proxy status 보고, #260 503 `storage_limit`·422 처리 | PX-012/016, AC-12 | 같음 | #265 |
| 통합 e2e | sonnet (coder, worktree) | 실제 server + proxy, loopback mTLS 수명주기 | PX-005/008/009/012, AC-04 | `crates/sigil-proxy-e2e/**`, `lifecycle.rs` test-util | #267 |
| 리뷰 | sonnet (reviewer, 읽기 전용) | 세 작업 독립 리뷰·재확인 | 해당 ID | 없음 | — |

진행:
- T-12c1: 리뷰 approve with fixes(M1 만료를 한 task에만 의존 → `TableHandle::current()`가 deadline 검사, M2 진행 중 fetch 만료 테스트, M3 재시작 rollback → `applied.json`에 `{revision, config_hash}`만 저장, M4 semaphore 이월, M5 테스트) → 재확인에서 M4가 적용 경로에 연결되지 않음 발견(R1) → 수정 → orchestrator 확인 → PR #264. control-plane §6.2에 applied mark와 복구 절차 추가.
- T-12c2: 리뷰 approve with fixes(M1 재시작 후 `status_sequence` 정체 → `sequence.json` 상한 저장·`accepted_snapshot_ignored`, M2 항목 없는 422의 gap 전체 격리 → snapshot-only 판별 후 단건 격리, L1·L3) → 재확인 approve → PR #266. §6.2에 sequence 행 추가.
- 통합 e2e: server·proxy 불일치 없음. 리뷰 approve(M1 disable 단계 주장 과장 → 주석·로컬 상태 assert, knob을 `test-util` feature로, 포트 경쟁 → pre-bound listener) → PR #268. 릴리스 workspace 빌드에서 `test-util` 비활성 확인(`cargo tree -e normal`).

### 3회차 머지 결과 (2026-10-12 ~ 10-14)

| PR | 작업 | 이슈 |
|---|---|---|
| #262 | 2회차 상태 문서 | — |
| #264 | T-12c1 config fetch·apply | #263 |
| #266 | T-12c2 status 보고 | #265 |
| #268 | server–proxy 통합 e2e | #267 |

후속: #260(T-11 S4 gap producer·queue 영속·placeholder 상태 필드·F1 연속 `state_applied=false` 경고·F2 단건 격리 모드 처리량), #269(e2e 미커버: TTL 만료·server 재시작·gap·`fp_next`·retire·TLS·503 boot gate·read API).
남은 P1: T-11 S4(ledger·ingest), S5(projection·조회, server 프록시별 read API 없음), S2b(CSR 서명), T-12b(MCP protocol), T-13–T-16.
실기 미검증: 변화 없음(Rocky 9 SELinux·systemd·x86_64 baseline). 통합 e2e는 로컬 프로세스 검증이며 실기가 아니다.
교훈: 작업자의 "연결했다" 보고는 production 경로 호출을 직접 확인한다(T-12c1 R1). 테스트 전용 진입점은 feature 뒤에 두고 릴리스 빌드에서 꺼져 있는지 확인한다.

## 2026-10-14 P1 4회차 배정: T-11 S4 ledger·ingest (기준 `4cea9de`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| S4-plan | sonnet (planner, 읽기 전용) | S4 범위·슬라이스·미결 계약 | PX-010/011, AC-05/06 | 없음 | — |
| S4 A | sonnet (coder, worktree) | parse 오류 분류를 typed 신호로(marker 위조 차단), 413/429/503 code | PX-010/011, AC-05/06 | `crates/sigil-proxy-api/**`, server `status.rs` 호출부 | #271 |
| S4 B1 | sonnet (coder, worktree, A 뒤) | server SQLite ledger: 중복·tombstone·gap·보존·한도·SV-1 | PX-010/011, AC-05/06 | `proxy/ledger.rs`, `proxy/mod.rs`, `config.rs`, `config_api.rs`(PUT 검사) | #274 |
| S4 C | sonnet (coder, worktree, B1과 병렬) | proxy ingest client·gap queue 영속·#260 F1/F2·상태 필드 | PX-011/012/016, AC-06/12 | `crates/sigil-proxy/**` | #275 |
| S4 B2 | sonnet (coder, worktree, B1 뒤) | `POST /v1/proxy-events`·`/v1/proxy-metadata`·SV-2–5·sweep 예약 | PX-005/010/011, AC-05/06 | `proxy/{ingest,metadata,guard,mod,store}.rs`, `main.rs`(sweep spawn) | #278 |
| 리뷰 | sonnet (reviewer, 읽기 전용) | 각 갈래 독립 리뷰·재확인 | 해당 ID | 없음 | — |

결정(사용자, 2026-10-14): planner 추천안 전부 채택 — [decisions.md "T-11 S4 범위", "오류 code"](decisions.md).

진행:
- A: 리뷰 approve with fixes(L만: `storage_unavailable` 호출부, 진짜 Limit 유지 테스트, 테스트 이름) → PR #273. 오류 code 표는 PR #272.
- B1: 리뷰 approve with fixes(M1 PUT이 T ≥ R+M 미검사 → 다음 부팅 거부, M2 gap 닫기 range COUNT → 이차 비용·전 proxy 정체, M3 닫힌 gap까지 cap 집계 → 장기 backpressure, L 파일 크기 backstop·tombstone 별도 한도·NOFOLLOW·WAL TRUNCATE) → 재확인 approve(+단일 index 조회) → PR #276.
- C: 리뷰 approve with fixes(H1 닫힌 `central_outage` 재전송이 원본과 달라 409 → 서버에서 영구 open, M1 전송 중 갱신된 gap 삭제, M2 재시작 시 open outage 소실, M3 424 재전송 루프, M4 `persist_failed` 미표시, M5 서버 한도로 정상 이벤트 단건 격리 소진) → 재확인 approve(+marker 선기록) → PR #277. `run_ingest`는 producer(T-13/T-14) 전까지 production에서 시작하지 않음을 orchestrator가 확인.
- B2: 리뷰 approve with fixes(M1 body 읽기 timeout 없음 → slot 고갈, M2 재전송 중복에 SV-5 적용 → 422·격리, M3 flaky 테스트, M4 metadata 한도 전역·definition만 집계) → 재확인 approve → PR #280. 본문 `proxy_id` 불일치는 404 `proxy_unknown`(L5), 100개 초과는 413, body 읽기 timeout은 429 `rate_limited`.

### 4회차 머지 결과 (2026-10-14 ~ 10-15)

| PR | 작업 | 이슈 |
|---|---|---|
| #270 | 3회차 상태 문서 | — |
| #272 | S4 결정·오류 code 표 | — |
| #273 | S4 A parse 분류·오류 code | #271 |
| #276 | S4 B1 ledger store | #274 |
| #277 | S4 C ingest client·gap queue | #275 |
| #280 | S4 B2 ingest route·metadata·sweep | #278 |

후속: #279(registry 409 `metadata_ref`, metadata 보존, ingest `last_seen`, status 기반 tail gap→S5), #269(e2e 미커버), #260 남은 항목(상태 저장소 DB 이전, T-12b 항목, hardening).
남은 P1: S5(projection·조회), S2b(CSR 서명), T-12b(MCP protocol), T-13(registry entry 생성)·T-14(spool·이벤트 생성), T-15, T-16. 통합 e2e로 ingest 경로(이벤트 fixture → server ledger) 확인 필요.
실기 미검증: 변화 없음. ledger의 `synchronous=FULL` 내구성은 실제 전원 차단으로 검증하지 않았다.
교훈: 계약상 "같은 것의 재전송"은 원본과 바이트 단위로 같아야 한다(C H1, B2 M2). 공유 자원(slot·mutex·전역 한도)은 한 proxy가 독점할 수 없게 proxy별 상한을 함께 둔다(B1 M2, B2 M1·M4).

## 2026-10-17 P1 5회차 배정: T-11 S5 projection·조회 (기준 `37a3761`)

4회차 마무리: #283(ingest 403 문구), #285(ingest 통합 e2e, #282) 머지. #285는 로컬 rustc가 CI stable보다 오래되어 deprecated `fetch_update` 경고를 놓쳤다가 수정했다.

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| S5-plan | sonnet (planner, 읽기 전용) | S5 범위·슬라이스·미결 계약 | PX-006/010/011/012/016, AC-05/06/12 | 없음 | — |
| S5 A | sonnet (coder, worktree) | ledger v2·저장 projection·invocation 단위 보존 정리·읽기 API | PX-006/010/011/012/016, AC-05/06/12 | `proxy/ledger.rs`, `proxy/projection.rs` | #286 |
| S5 B | sonnet (coder, worktree, A 뒤) | status 기반 tail gap·ingest `last_seen` | PX-011/012, AC-06/12 | `proxy/{status,store,ingest}.rs`(+ledger tail 경로) | #289 |
| S5 C | sonnet (coder, worktree, B와 병렬) | 조회 API 4개·cursor·필터·인증·`route_of` 수정 | PX-006/010/016, AC-05/06/12 | `proxy/query.rs`, `app.rs`, `mgmt.rs`, `registry.rs`(+B 머지 뒤 ledger·store·status 일부) | #290 |
| S5 e2e | sonnet (coder, worktree) | 실제 mTLS로 ingest→projection→조회 | AC-05/06/12 | `crates/sigil-proxy-e2e/tests/server_proxy_query_e2e.rs` | #293 |
| 리뷰 | sonnet (reviewer, 읽기 전용) | 각 갈래 독립 리뷰·재확인 | 해당 ID | 없음 | — |

결정(사용자, 2026-10-17): planner 추천안 전부 채택 — [decisions.md "T-11 S5 범위"](decisions.md). 계약 [OPEN] 정리: `proxy.read` P1 모델, `limit` 범위 밖 422, 서버 시각 `status_as_of`, gap endpoint 없음, `invalid_cursor`·`invalid_filter` 확정, flag `event_limit`(P-8).

진행:
- A: 리뷰 approve with fixes(M1 invocation당 재계산 이차 비용 → writer 정체, M2 다중 proxy 범위 불가, M3 tail 닫힘 기록이 빠진 범위를 닫힘으로 표시, M4/M5 필터·gap 조회 전체 scan·단일 읽기 mutex) → 수정(256개 상한·`event_limit`, 읽기 pool 4·조회 5 s 제한, index) → 재확인(R1 cancel이 완료를 밀어냄, R2 batch마다 O(k) COUNT, 필수 scope) → approve → PR #288.
- B: 리뷰 approve with fixes(M1 ledger에 없는 epoch로 닫힐 수 없는 tail gap 반복 생성 → 자기 gap 한도 소진, L1 `last_seen` 수 ms 역행) → 수정(모르는 epoch tail은 proxy당 하나) → approve → PR #291.
- C: 보안 리뷰 approve with comments(M1 `status_as_of`가 proxy 시계, M2 목록 행마다 ledger 호출, M3 단건 조회가 proxy 수만큼 조회) → B 머지 뒤 rebase하여 수정(서버 시각 `status_received_at`, 일괄 gap 수, 단일 owner 조회, 요청당 ledger 호출 상한 테스트) → approve → PR #292.
- e2e: 리뷰 approve with fixes(M1 AC-05 검사가 header 미포함, L1 양성 대조 약함, L3 재시작 rebind, L4 고정 날짜의 gap이 보존 기간 뒤 사라질 시한폭탄) → 수정 → PR(아래).

### 5회차 머지 결과 (2026-10-17 ~ 10-18)

| PR | 작업 | 이슈 |
|---|---|---|
| #283 | ingest 403 문구 | — |
| #285 | S4 ingest 통합 e2e | #282 |
| #287 | S5 결정·`event_limit` | — |
| #288 | S5 A ledger v2·projection·읽기 API | #286 |
| #291 | S5 B tail gap·`last_seen` | #289 |
| #292 | S5 C 조회 API | #290 |

후속: #279(registry 409 `metadata_ref`→T-13, metadata 보존, `stale_after` 설정값화), #260(proxy status 보고의 `last_assigned_sequence`·spool이 T-13/T-14 전까지 고정값 → 실제 proxy로는 tail gap이 아직 생기지 않음), #284(e2e helper 공유), #269.
남은 P1: S2b(CSR 서명), T-12b(MCP protocol), T-13(registry entry 생성)·T-14(spool·이벤트 생성), T-15(manager, sigil-manager#37), T-16.
실기 미검증: 변화 없음. 조회 API의 실제 TLS 검증은 e2e(macOS 로컬·CI)까지이며 Rocky 실기·SELinux·systemd는 하지 않았다.
교훈: 병렬 갈래가 같은 파일을 필요로 하면 먼저 끝난 갈래를 머지하고 rebase한 뒤 소유권을 넘긴다(C 2단계). 고정 날짜 fixture는 보존 정리가 있는 경로에서 시간이 지나면 깨진다(e2e L4).

## 2026-10-20 P1 6회차 배정: T-12b1·T-13·T-14 (기준 `ad63551`)

결정(사용자, 2026-10-20·10-21): [decisions.md "T-13/T-14 범위"·"T-13a/T-13b 후속 결정"](decisions.md).

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| 골격 | orchestrator | `mcp`·`spool` 모듈 자리, 결정 기록 | — | `lib.rs`, `Cargo.toml`, decisions.md | — |
| API DTO | sonnet (coder, worktree) | inventory 보고 DTO, `ErrorItem.metadata_ref` | PX-005/016, AC-02 | `crates/sigil-proxy-api/**` | #298 |
| T-14a | sonnet (coder, worktree) | SQLite WAL spool, fsync 뒤 ack, 한도·격리 | PX-011/012, AC-06/12 | `sigil-proxy/src/spool.rs` | #297 |
| T-12b1 | sonnet (coder, worktree) | MCP 요청·응답 분류, `ObservationSink`, cancel | PX-003/004, AC-07 | `sigil-proxy/src/mcp/**` | #299 |
| T-14b | sonnet (coder, worktree) | spool을 lifecycle·status 보고에 연결 | PX-011/012, AC-06/12 | `lifecycle.rs`, `status_report.rs`, `ingest_client.rs`, `state_dir.rs`, e2e | #305 |
| T-13a-server | sonnet (coder, worktree) | inventory 수신·snapshot/drift projection·조회 | PX-005/006, AC-02 | `sigil-server/src/proxy/inventory*.rs`, `ledger*.rs`, `query.rs`, e2e | #304 |
| T-13b | sonnet (coder, worktree) | registry key·JCS·registry 저장소·inventory 엔진·upload client | PX-005, AC-02/05 | `sigil-proxy/src/{jcs,registry_key,registry_store,inventory,registry_client}.rs` | #306 |
| 리뷰 | sonnet (reviewer, 읽기 전용) | 각 갈래 독립 리뷰·재확인 | 해당 ID | 없음 | — |

진행:
- T-14a·T-12b1·DTO: 리뷰 지적(spool 유지보수 굶주림·조용한 재생성·용량 계산, id 없는 요청 미관측·중복 key·중복 in-flight id) 수정 뒤 재확인 → 머지.
- T-14b: 리뷰 지적(gap 인계 overflow, set-aside 충돌 구간, 쓸 수 없는 URL은 시작 오류) 수정. Rocky CI에서 일시적 tail gap으로 e2e가 실패해 "열린 gap 없음"으로 고침 → 머지.
- T-13a-server: 리뷰 지적(이차 비용 resolve, gap 한도가 snapshot을 막음, 대기 노화, 멱등 table) 수정. 후속 결정 1·2 반영 뒤 rebase하면서 #308의 e2e가 이전 tail 규칙을 기대해 고쳐 씀.
- T-13b: 리뷰 지적(discard 뒤 chain 끊김, 단일 413/422 정체, 충돌 gap 충돌 안전, cursor 정체성, 424 반복, poison은 일시 정지, 결정적 `gap_id`) 수정. 후속 결정 3·4 반영.

### 6회차 머지 결과 (2026-10-20 ~ )

| PR | 작업 | 이슈 |
|---|---|---|
| #296 | 골격·T-13/T-14 결정 | — |
| #300 | inventory DTO | #298 |
| #301 | T-14a spool | #297 |
| #303 | T-12b1 MCP 분류 | #299 |
| #308 | T-14b spool 연결 | #305, #260 |

후속: #302(spool 만료 시계·NOFOLLOW·격리 한도), #307(registry entry 보존·보고 backlog).
T-12b2로 넘김: cancel key에 session 포함, upstream initialize 판정, m5 version header 누락 규칙.
T-13c로 넘김: `StatusBuilder::set_registry(client.health_probe())` 연결, `sync_stalled`에 ingest 424 보류 정체 합산, probe를 `spawn_blocking`으로.
T-13d로 넘김: `Admission`을 `Proxy`에 전달, 비울 수 없는 spool은 fail closed.
실기 미검증: spool fsync·재시작 복구, inventory 수신은 macOS 로컬·CI e2e까지. Rocky 실기·SELinux·systemd는 하지 않았다.
교훈: stacked PR의 base를 `--delete-branch`로 머지하면 위 PR이 자동으로 닫힌다. base를 지우기 전에 위 PR의 base를 main으로 바꾼다. 규칙을 바꾸는 갈래는 rebase 뒤 전체 workspace 테스트를 돌린다(다른 갈래의 e2e가 이전 규칙을 기대했다).

## 2026-10-11 P1 2회차 배정 (기준 `f656b5c`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| T-12a | sonnet (coder, worktree) | raw relay·목적지 검사·한도·listener TLS | PX-003/004/008/014/015, AC-07 | `crates/sigil-proxy/**` | #258 |
| T-11 S3 | sonnet (coder, worktree) | server config 발급·status 수신 | PX-005/008/012, AC-04/12 | `crates/sigil-server/src/proxy/**` 외 배정 시 명시 | #257 |

진행: 두 작업 모두 coder → 독립 리뷰(sonnet) → fix → 재확인 blocker 없음 → PR. CI 1차 실패 2건은 orchestrator가 수정했다.
- #261(ubuntu): verifiers 파일 stamp가 ctime만으로 권한 변경을 감지해, 한 timestamp tick 안의 chmod 두 번이 구분되지 않았다(실제 결함). stamp에 mode·uid 추가.
- #259(macOS): TLS 테스트 인증서를 runner의 PATH `openssl`이 만들면 webpki가 `ExtensionValueInvalid`로 거부. server e2e와 같은 openssl 탐색 순서·`OPENSSL_CONF` 제거·CA 서명 leaf(RSA, 고정 serial)로 수정. runner openssl의 정확한 원인은 미확정.

### 2회차 머지 결과 (2026-10-12)

| PR | 작업 | 이슈 |
|---|---|---|
| #259 | T-12a proxy relay | #258 |
| #261 | T-11 S3 config·status | #257 |

후속 #260: 한도 min(local, remote), verifier `not_after`, origin 함수 공유, SV-5 이전 scope id 허용, 503 storage_limit, 인코딩된 body 관측 불가, T-12b(session·DELETE·GET·cancel·batch), 대역폭·IP별 한도, https upstream 테스트.
남은 P1: T-12c(proxy 측 config 적용), T-12b, T-11 S2b(CSR 서명), S4(ledger·ingest), S5, T-13–T-16.
교훈: 테스트용 인증서는 openssl 구현(LibreSSL/OpenSSL)마다 결과가 다르다. 기존 server e2e helper 방식을 따른다.

## 2026-10-10 3회차 배정 (기준 `46cc990`, 브랜치 `docs/proxy-p0-round3`)

orchestrator가 작업별로 하위 모델을 직접 지정한다(판단 작업 sonnet, 기계적 검증 haiku). 하위 에이전트는 추가 위임하지 않는다.

| 작업 | 모델 | 목표 | Spec | 소유 파일 |
|---|---|---|---|---|
| W1 | sonnet (researcher) | server·manager 인증 표면 재조사, D-02 선택지 | PX-008/009/012/014/016, AC-04/08/13, D-02 | `docs/research/sigil-proxy-auth-surfaces-2026-10-10.md` |
| W2 | sonnet (coder) | D-03 retention·projection·query DTO·semantic validation·m6 집계, D-05 registry DTO·key rotation·drift 이벤트, status DTO | PX-005/006/010/011/012/016, AC-02/05/06/12, D-03/05 | `contracts/{ledger-and-query.md, registry.md, registry-entry.schema.json, proxy-status.schema.json, check_schema.py}` |
| W4 | sonnet (coder) | PX-001·PX-004 인수 시나리오, P1 support matrix, AC-12 P1 범위, 추적표 | PX-001/004/013, AC-12 | `spec.md`, `validation.md`, `support-matrix.md` |
| W3 | sonnet (coder) | D-02 control-plane 계약 (W1 이후) | PX-008/009/012/014, AC-04/08/13, D-02 | `contracts/control-plane.md` |
| 리뷰 | sonnet (reviewer) | W2·W3·W4 독립 리뷰 | 해당 ID | 없음 |
| 검증 | haiku (verifier) | checker 재실행·위생 스캔·링크 검사 | — | 없음 |
| W5 | sonnet (researcher, 읽기 전용) | support-matrix undecided 7개 기능의 P1 범위 권고 → completed, decisions.md "P1 기능 범위"로 확정(subscribe·GET은 사용자 결정) | PX-003/004, AC-07/15, D-01 | 없음 |

진행: W4 completed (AC-14·AC-15 추가, support-matrix 신규, orchestrator가 plan.md AC 연결·기타 OS=P1 미지원 반영) → 리뷰(sonnet) 진행 중. W1 completed ([인증 표면](../../research/sigil-proxy-auth-surfaces-2026-10-10.md)) → W3 배정. W4 리뷰 F1–F8 반영 + support-matrix 7개 행 결정 반영(남은 undecided: D-04 한도 수치 1개). W2·W3 completed → 독립 리뷰(sonnet). W3 리뷰 needs_changes(H1–H3, M-1–M-10, L1–L5; W1 소스 주장 전부 확인) → W3-fix completed(control-plane v0.2, status endpoint `POST /v1/proxy-status`로 통일) → 재확인: 기존 지적 전부 해결, 신규 N-1(high: config 범위로 upstream 자격증명 유출)·N-2·N-3 → W3-fix-2·3 completed → 재확인 **approve**(control-plane, D-02 자체는 사용자 결정 대기). W2 리뷰 needs_changes(F1 high + F2–F14) → W2-fix completed(+status 정렬: config_hash·apply_failed·config_hash_mismatch·disabled) → 재확인 **approve**(checker 독립 재실행 exit 0, F1 회귀 시 exit 1 확인). flag-not-reject 결정 decisions.md 기록. W6 contracts README 통합(sonnet, v0.4) → 독립 리뷰 needs_changes(H1: 404 proxy_unknown을 규칙화 → 후보로 환원, 동결 403 기준 유지; M1–M5, L1–L4) → W6-fix·fix-2 → 재확인 blocker 없음. W2-fix-2(invocation GET 범위 밖 404, 존재 oracle 제거), W3-fix-4(404를 recommended/candidate로 표기). haiku 검증: checker exit 0·`-O` exit 2, JSON 4/4, 링크 75/0 broken, 경로·IP·토큰·금지 용어 없음. **사용자 결정(2026-10-10): 추천안 전부 채택** — D-02 항목 1–8(contract 수준 확정), 404 `proxy_unknown`(D-03 ingest 403 대체), O-1 A, D-04 한도=P1 초기 기본값. W2-fix-3·W3-fix-5/6·W6-fix-3/4로 전파, 최종 교차 일관성 검사 stale 문구 5건 정리. 남은 [OPEN]: 경로 이름, message 문구, disabled/retired HTTP status, batch client 응답, legacy 헤더 감사 reason 상수, SV-1/3/5.

## 2026-10-10 배정

| 작업 | 역할/인스턴스 | 목표 | Spec | 소유 파일 |
|---|---|---|---|---|
| P0-spec-audit | spec-auditor (읽기 전용) | 추적성·P0 종료 조건·배정 적합성·선행 가능한 P1 작업 점검 | 전체 PX/AC, D-01–05 | 없음 (orchestrator에 보고) |
| P0-targeted-rereview | review-lead (reviewer) | R1–R3 수정·lifecycle·fixture 독립 재리뷰 | PX-003/006/007/010/011/015, AC-03/05/06, D-02/03 | `review-p0-followup.md` |
| T-01 resume | coding-lead (coder, probe 한정) | SDK vs raw relay, MSRV 빌드, 실제 client HTTP 왕복 | PX-003/004/008/015, AC-07, D-01/02 | `scripts/proxy-p0/probes/**`, `docs/research/sigil-proxy-t01-probe-2026-10-10.md` |

## 작업 보드

| 작업 | 상태 | 산출물/증거 | 남은 조건 |
|---|---|---|---|
| T-00 | done: source survey | [저장소 조사](../../research/sigil-proxy-repository-survey-2026-09-27.md) | 실기 결과를 뜻하지 않음 |
| T-01 | done: evidence + 독립 리뷰 + fix (2026-10-10) | [T-01 probe](../../research/sigil-proxy-t01-probe-2026-10-10.md): rmcp 0.16 typed 경로는 unknown field 유실·version allowlist 없음; raw hyper relay 10/10 byte 동일; Claude Code 2.1.296·codex 0.162.0 실제 HTTP 왕복(macOS loopback) | 프록시 경유 재측정·Linux는 P1 실측(decisions.md "P0 종료"). MSRV #240 해결(PR #241) |
| T-02 | done: contracts v0.4 + control-plane·ledger·registry (독립 리뷰 approve, PR #243) | [계약](contracts/README.md), checker PASS 53/271 + W2 | 남은 [OPEN]은 P1 담당 작업에서 확정 |
| T-03 | done: fixture preparation | [검증 계획](validation.md), smoke + 14 self-tests 통과 | T-01 revision 정합성, 실제 proxy benchmark/E2E |
| P0-review | done: needs_changes | [초기 리뷰](review-p0.md), R1–R3 | 후속 수정 독립 검토 |
| T-02-fix | done: coder report + tests | contracts/만 수정, coordinator checker 재실행 통과 | 독립 승인 아님 |
| P0-targeted-rereview | done: needs_changes (2026-10-10 review-lead) | [재리뷰](review-p0-followup.md): R1–R3 해결, 신규 major N1–N4·N9(metadata registry offline 모순), minor N5–N8. checker 24/60, smoke, 14 tests 통과 (승인 아님) | contract owner가 N1–N4·N9 수정 → 표적 독립 재확인. D-02는 N3, D-05는 N9 결정 전 종료 불가. N4·revision 고정은 D-01 결과와 함께 처리 |

## 결정과 다음 작업

[결정 기록](decisions.md)의 "P0 종료" 절이 잔여 항목과 담당 작업을 기록한다.

1. PR0 `sigil-proxy-api`(#244): coder → 독립 리뷰 → 검증 → PR.
2. PR0 뒤 병렬: T-10 `sigil-proxy` 골격(#245), T-11 S1 신원·등록(#246). 파일 소유가 겹치지 않게 배정한다.
3. 이후 T-11 S2(관리 인증·운영자 CLI) → S3(config·status) → S4(ledger·ingest) → S5(projection·조회). app.rs·config.rs는 한 작성자.
4. T-12 relay는 T-10 골격 뒤. T-15 manager는 sigil-manager#37과 그 저장소 지침에 따른다.

## 실행 이력

| 역할/작업 | Task | Dispatch | 결과/정리 |
|---|---|---|---|
| T-00 | task_8effdc8ddb34 | ctx_7cca1b7a0087 | succeeded, released |
| T-01 | task_8a942cd9d0a2 | ctx_3e7856e537a5 | session restore failure, stopped |
| T-01 retry | task_8a942cd9d0a2 | ctx_64bc0eeaa75a | session restore failure, stopped |
| T-03 | task_8ef4195c1ee4 | ctx_913145acde55 | tests written, session restore failure, stopped |
| T-03 retry | task_8ef4195c1ee4 | ctx_d26b47a10bb9 | docs completed, succeeded/released |
| review | task_e8c5761b056a | ctx_ae5cff21b3e8 | findings delivered, succeeded/released |
| fixes | task_3fd3cf9f0136 | ctx_6f6279a00c6f | fixes delivered, succeeded/released |
| re-review | task_019b8018bdcc | ctx_ced4fae98e2a | observed shell parse failure, stopped |
| re-review retry | task_019b8018bdcc | ctx_4876e7ff14cd | session restore failure, stopped |
| spec-audit | 2026-10-10 | spec-auditor | needs_changes 보고 (D-01 MSRV 모순, 추적성·stale 문서, 배정 보정), completed |
| re-review (resume) | 2026-10-10 | review-lead | needs_changes 보고, completed. 기존 체크포인트를 덮어썼다가 정정 지시 후 원문을 맨 위로 복원 |
| T-01 (resume) | 2026-10-10 | coding-lead | completed; 하위 위임 sonnet(raw relay)·haiku(MSRV 빌드). toolchain 1.78/1.85/1.88/1.89.0 추가 설치 |
| T-01-review | 2026-10-10 | review-lead | needs_changes 보고 (B1 blocker, M1–M4, m1–m8), completed. 핵심 측정 3종 재현 일치 |
| T-01-fix | 2026-10-10 | coding-lead | completed: B1/M1–M4/m1–m8 반영, compare.py·server_probe.py 재실행 통과, client 재실행 없음 |
| T-02-fix-2 re-check | 2026-10-10 | review-lead | completed: N1–N4·N7–N9 계약 범위 해결(주장 전부 재현), 신규 major M1(state loss)·M2(batch/registry liveness)·M3(cancel 순서), minor m1–m6. D-03/D-05 종료 불가 권고 |
| D-01 후속 결정안 + T-01 정정본 리뷰 | 2026-10-10 | review-lead | completed: B1·m5 승인(m5 근거 정정), M3 보완 후 승인, M4 수정(dispatch 안 함), M2는 codex 2025-06-18 결과 명시 필요, tasks는 route 단위 거절 권고. T-01 정정 전부 반영 확인. R1은 keyed ref에서도 유지 |
| T-02-fix-3 (M1–M3, m1–m5) | 2026-10-10 | contract-coder (소유: contracts/**) | completed: contract v0.3, checker PASS 43/196 (+dedup 10, batch 4, registry 4, ref 5), -O/-OO·no-format exit 2. 중간 정정 2–5 미반영 |
| T-02-fix-3b (tasks route 거절, upstream_version_unsupported, modern 요청 감사, key_id 고유성) | 2026-10-10 | contract-coder | completed: checker PASS 48/234, -O·no-format exit 2 |
| v0.3 + fix-3b 표적 재확인 | 2026-10-10 | review-lead | completed: M1·M2a·M2b·M3·m1–m5 해결, 신규 major N10(params.task 거절이 2025-11-25 tasks 규칙 위반), minor N11–N14. D-03/D-05 종료 불가 |
| T-02-fix-4 (N10–N14, task handle route 표시, entry hash 검사) | 2026-10-10 | contract-coder | completed: checker PASS 53/271 (+model 35), -O·no-format exit 2 |
| T-02-fix-4 최종 재확인 | 2026-10-10 | review-lead | completed: 신규 finding 없음, D-03 ingest 하위 계약 동결 권고 |
| T-02-fix-2 (N1–N4·N7–N9) | 2026-10-10 | contract-coder (소유: contracts/**, design.md:47) | completed: schema 후보 v0.2, checker PASS 40/169 (+dedup 7, ref 5), format 미설치 시 exit 2 |

복구 중 파일을 덮거나 작업을 성공으로 재분류하지 않았다. P0 산출물은 `97db268`로
main에 커밋·push되었다. 외부 배포·manager 변경·사용자 MCP 설정 변경은 하지 않았다.
