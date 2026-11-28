# T-03 검증 준비와 D-04 한도

2026-09-27 · verifier/coder · 기준 HEAD `24eddb2` 위에서 작성, `97db268`로 커밋. fixture revision 2025-11-25는 D-01 잠정 지원 revision과 일치(2026-10-10).
상태: **독립 fixture 준비 검증 완료; protocol 후보는 T-01 대기**.
Production proxy, 실제 vendor client, server/manager E2E 및 성능 측정은 미실행이다.
D-04 한도는 P1 초기 기본값으로 채택했다(2026-10-10, decisions.md "D-02 결정"). 성능 보장이 아니며 측정 후 조정한다. 출시 승인이나 P1 인수 통과 선언이 아니다.
복구 dispatch에서는 기존 Python 파일을 보존하고 README와 본 문서만 작성했다.

## 후보와 근거

선택한 fixture revision은 MCP `2025-11-25` Streamable HTTP이다.
2026-09-27에 공식 [transport 명세](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)와
[tools 명세](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)를 확인했다.
JSON/SSE 응답, initialized 알림의 빈 202, 세션/버전 헤더, 페이지 도구 목록과
`isError` 결과를 좁은 fixture 범위로 구현했다. 명세 열람은 제품 실기 검증이 아니다.
현재 제품/SDK 지원 표와 최신 revision 선택, 설정·권한·hook·무인 실행·OS 동작은
T-01 조사 책임이며 여기서 추정하거나 compatibility gate를 변경하지 않는다.

## 재현과 실제 결과

[fixture README](../../../scripts/proxy-p0/README.md)에 실행/종료 절차가 있다.
Python stdlib만 사용하고 매 실행 `127.0.0.1:0`에 bind한다. smoke는 외부 endpoint를
받지 않으며 환경 proxy, credentials 또는 실제 MCP를 사용하지 않는다.

실행 환경: macOS 26.6.2 build 25G83, Darwin 25.6.0, arm64, Python 3.14.6.
측정 일자: 2026-09-27. 실제 실행 명령과 stdout:

```text
$ python3 -B scripts/proxy-p0/smoke.py
PASS initialize + initialized notification; candidate=2025-11-25
PASS tools/list: pages=2 tools=4 complete=true
PASS tools/call: JSON, SSE multiline/CRLF, deliberate isError=true
PASS accepted-call drop: outcome=unknown client_attempts=1 fixture_invocations=1
PASS total_invocations=4; no automatic retry in this runner
ENV Python=3.14.6 system=Darwin release=25.6.0 machine=arm64
LIMIT fixture-only; no proxy, vendor client, throughput measurement, or release acceptance
```

Exit 0. 독립 self-test 명령:

```text
$ python3 -B -m unittest discover -s scripts/proxy-p0 -p 'test_*.py' -v
Ran 14 tests in 6.123s
OK
```

Exit 0, 14개 모두 통과. 위 시간은 unittest 실행 시간이며 처리량 벤치마크가 아니다.
테스트는 JSON/SSE/도구 오류, 두 페이지/잘못된 cursor, drop과 중복 계수,
잘못된 인자·메시지·크기·헤더, 세션 삭제/초기화, 지원하지 않는 기능,
SSE comment/CRLF/multiline 및 잘린/과대 stream을 확인했다.

## AC 추적 및 판정 경계

| 요구사항 / AC | 이번 fixture 증거 | Proxy 인수 상태 / 남은 검증 |
|---|---|---|
| PX-001 / AC-14 | 관련 production 경로 없음(fixture는 별도 Python 스크립트이며 설치 경로가 아님) | not_run: 개인 설치 기본 옵션에서 proxy 미활성·미listen, 명시적 `--config` 없이는 미기동 |
| PX-002–004 / AC-01 | initialize, tools capability, JSON/SSE 왕복 PASS | not_run: 실제 client → proxy → MCP → server → manager 호출 ID 연결 |
| PX-005 / AC-02 | 두 페이지 전체 목록과 잘못된 cursor PASS | not_run: baseline/drift, 접근 scope 차이, 중간 page 실패 시 삭제 방지 |
| PX-006,015 / AC-03 | 수락 후 socket drop, unknown 분류, client 1회/fixture 1회 PASS | not_run: proxy 전달/감사 상태와 자동 재실행 금지 |
| PX-003,013 / AC-07 | 세션/버전, finite SSE, fixture 크기 제한 PASS | not_run: 취소, resume, 서버 요청, 큰 응답, 동시성 및 production 한도 |
| PX-002,014 / AC-08 | loopback bind, Host/Origin 거절 PASS | not_run: 요청의 upstream 지정 무시, proxy SSRF, IPv6, DNS rebinding, redirect 목적지 정책 |
| PX-003–004 / AC-15 | fixture가 지원하지 않는 기능을 거절하는 시험만 PASS(proxy 아님) | not_run: support-matrix.md §5 각 행의 응답·upstream 호출 수·감사 기록; undecided 행 해소 |
| PX-007–011,016 / AC-04–06,12 (PX-008 원격 설정 TTL 만료 포함) | 관련 production 경로 없음 | not_run: principal 격리, canary, spool/중앙 단절·복구·재시작 |
| PX-013 / AC-12 | fixture 크기 제한 PASS(AC-07과 공유, production 한도 아님) | not_run: spool 용량·디스크 가득 참·재시작·backpressure·정상 종료 |
| PX-012 / AC-01,13 | 관리 API 없음 | not_run: server/manager 권한과 관리 변경 감사 |

counter는 drop 도구를 수락한 직후 lock 안에서 증가하며 응답 전 연결을 끊는다.
동일 request ID를 다시 전송해도 계수하므로 deduplication으로 retry를 숨기지 않는다.
이 증거는 **이번 smoke runner의 자동 retry 없음**만 입증한다. 외부 부작용의 실행,
지연된 vendor retry, proxy의 at-most-once 또는 exactly-once를 입증하지 않는다.
직접 fixture 접근과 별도 counter는 테스트 oracle이며 제품 감사 API가 아니다.

## Proxy 결과 (a1619c89)

위 표는 fixture(Python) 증거다. 이 절은 제품 proxy(`lodeline-proxy`와 `lodeline-server`)의 시험 결과다.

- 기준 커밋: origin/main `a1619c89d88ae70f3155bd704f8398bd1845880e`. PXDOC1(#783, `2dc95fa0`), PXCFG1(#785, `dd9b8a87`)과 운영 가이드(#788, `docs/install-proxy.md`)가 이 커밋에 들어 있다. 이 절의 행은 그 커밋 기준이다.
- 실행: 2026-11-27, macOS arm64, `CI` 미설정, `openssl` 4.0.3 설치됨. 명령은 `cargo +1.100.0 test -p lodeline-proxy -p lodeline-proxy-api -p lodeline-proxy-e2e -p lodeline-server`이고 종료 코드 0, 1386 passed, 0 failed, 2 ignored다. ignored 2건은 `lodeline-proxy-e2e`의 `loadgen_e2e::alternating_rounds_at_the_validation_rate`와 `lodeline-server`의 `enroll_token_cli`(root 필요) 1건이며 아래 표는 둘 다 인용하지 않는다.
- 구성: `lodeline-proxy-e2e`는 `lodeline-proxy`의 `test-util`과 `lodeline-server`의 `test-support` 기능을 켠다(`crates/lodeline-proxy-e2e/Cargo.toml:14-18`). 일부 시험은 이 기능 없이 만든 실제 `lodeline-proxy` 바이너리를 띄운다(`crates/lodeline-proxy-e2e/tests/common/mod.rs:407-425`).
- 인용 확인: 아래 표가 인용한 시험 100개는 각각 `-- --list`에서 정확히 한 줄로 선택됐고, `-- --exact <이름> --nocapture`에서 `1 passed`를 냈으며, `skipped:` 출력이 없었다. 인용한 시험 중 ignored, 조기 반환으로 건너뜀, cfg로 제외된 것은 0개다(`server_proxy_e2e`는 unix 전용이고 이 호스트는 macOS라 실행됐다). `openssl`이 없고 `CI`가 없으면 일부 시험이 건너뛰므로(`crates/lodeline-proxy-e2e/tests/common/mod.rs:141-153`), 그런 환경의 결과는 이 표와 다르다.
- 판정: `pass`는 oracle의 각 절을 인용한 시험이 실행했다는 뜻이고, 한 절이라도 시험이 없으면 `partial`, 실행하지 못했으면 `not run`이다. 시험은 loopback에서 돌고 upstream은 stub이며 인증서는 시험용 PKI가 만든다. 서버와 proxy를 같은 프로세스에서 돌리는 시험과 proxy 바이너리를 따로 띄우는 시험이 섞여 있다.
- 표기: 시험은 `crate/target::이름`이다. crate는 `p`=`lodeline-proxy`, `pa`=`lodeline-proxy-api`, `e`=`lodeline-proxy-e2e`, `s`=`lodeline-server`이고, `lib`은 그 crate의 단위 시험이다. 이전 실행은 [aws-smoke-test.md](aws-smoke-test.md) 18절(실행 H, workspace 0.9.1, `b17b2d2`, 2026-10-25)과 19절(실행 I, `3500adb`, proxy 0.13.0, 2026-11-06)이며 현재 버전의 결과가 아니다.

| AC | oracle (spec.md) | 시험 | 이 실행의 결과 | 판정 | 이 증거가 보이지 않는 것 | 이전 실행 |
|---|---|---|---|---|---|---|
| AC-01 | 등록된 시험 MCP와 인증 클라이언트가 조회 도구를 호출하면 정상 응답과 manager 기록이 같은 호출 ID로 확인된다 | `e/server_proxy_e2e::server_and_proxy_walk_the_whole_lifecycle`; `e/spool_ingest_e2e::real_lodeline_proxy_process_drains_the_spool_to_the_server`; `e/server_proxy_query_e2e::projection_lifecycles_filters_and_detail`; `p/mcp_relay::started_precedes_completion`; `p/mcp_relay::json_outcomes`; `p/lib::invocation_sink::tests::event_ids_are_v7_and_sort_in_start_order` | 6개 실행, 6 pass | partial | 서버와 proxy가 한 프로세스에서 돌고 upstream은 stub이다(`crates/lodeline-proxy-e2e/tests/server_proxy_e2e.rs:2-13`). manager 쪽은 시드한 이벤트(`apps/manager/src/fleet/tests/proxies.rs:217`)와 mock fleet 브라우저 설정(`apps/manager/web/playwright.config.ts:72`)이다. 실제 서버에 붙는 브라우저 설정(`apps/manager/web/playwright.real.config.ts`)도 계약 시험의 seed를 읽고 이번에 실행하지 않았다. proxy 호출의 호출 ID를 manager 화면에서 확인한 시험은 없다. vendor client 없음 | H, I: server ledger까지 확인, manager 화면은 측정하지 않음 |
| AC-02 | 완전한 도구 목록 관찰 후 도구가 추가, 변경, 삭제되면 차이가 표시된다. 페이지 누락, 접근 권한 차이, 오류를 삭제로 오인하지 않는다 | `e/inventory_e2e::a_listing_through_the_relay_becomes_a_baseline_and_then_drift`; `e/inventory_e2e::an_unfinished_listing_never_becomes_a_snapshot`; `e/inventory_e2e::a_forged_cursor_never_completes_a_listing`; `p/inventory_wiring::relay_page_errors_map_to_incomplete_reasons`; `p/inventory_wiring::a_failed_page_leaves_the_latest_snapshot_in_place`; `p/inventory_wiring::a_call_without_a_capture_is_a_page_error_or_access_denied`; `s/proxy_inventory::case_other_credential_scope_is_a_separate_chain_with_no_marker_and_no_removals`; `e/server_proxy_inventory_e2e::inventory_over_mtls_ingest_projection_and_read`; `p/registry_inventory::second_listing_yields_one_added_one_changed_one_removed`; `s/proxy_inventory::case_second_listing_with_one_added_one_changed_one_removed_gives_three_drift_records` | 10개 실행, 10 pass | pass | 삭제 비교는 두 시험으로 나뉜다. proxy 쪽 시험은 완전한 두 목록에서 추가 1, 변경 1, 삭제 1건의 보고서를 만들고, server 쪽 시험은 시험이 만든 보고서를 올려 read API의 드리프트 3건을 확인한다. 릴레이 입력에서 삭제가 만들어지는 종단 시험은 없다(릴레이 시험은 추가와 변경까지). 접근 범위 입력은 upstream과 credential scope를 둘 다 UP1/CS1에서 UP2/CS2로 바꾼 보고서이며 둘 중 하나만 바꾼 경우는 시험하지 않았다. 차이의 표시는 서버 read API까지다. manager 화면의 표시는 실행하지 않았다(`apps/manager/web/tests/e2e-real/03-proxy-inventory.spec.ts`는 시드 데이터를 읽는다). stub upstream, vendor client 없음 | H, I: 드리프트 `added` 뒤 `removed`, 스냅샷 member_count 5(I는 5, 6, 5) |
| AC-03 | upstream이 작업을 받은 뒤 응답 연결이 끊기면 결과 불명으로 남고 proxy가 재실행하지 않는다 | `p/mcp_relay::lost_response_is_unknown_and_not_retried`; `p/mcp_relay::aborted_sse_is_unknown`; `p/relay_bytes::failed_exchange_is_not_retried` | 3개 실행, 3 pass | pass | stub upstream의 연결 끊김이다. vendor client가 스스로 다시 보내는 호출은 proxy 밖이라 보이지 않는다. 외부 부작용의 실행 여부는 보이지 않는다 | H, I: 일반 smoke 시나리오(27/27)와 fixture 호출 수 기록이며 도구 호출을 받은 뒤 연결을 끊는 시나리오는 아니었다 |
| AC-04 | 에이전트가 human=true를 보내거나 타 주체 세션이나 라우트를 사용하면 인간 인증으로 인정하지 않고 무권한 접근을 거절한다 | `p/relay_auth::principals_cannot_cross_routes`; `p/relay_auth::bad_credentials_are_401`; `p/relay_auth::unknown_route_is_indistinguishable_from_auth_failure`; `p/sessions_http::proxy_session_is_private_bound_and_protocol_is_checked_after_auth`; `pa/lib::config::tests::route_and_principal_rules`; `e/server_proxy_query_e2e::isolation_between_proxies_and_byte_equal_404`; `e/server_proxy_query_e2e::auth_matrix_over_tls` | 7개 실행, 7 pass | partial | 다른 principal의 세션과 다른 라우트의 거절은 시험한다. `human=true`를 요청에 실어 보내는 시험은 없다. 설정에서 `actor_kind: human`이 거절되는 것(`pa` 단위 시험)과 이벤트의 actor가 설정에서만 오는 것은 구조로 보이지만 요청 쪽 입력으로는 시험하지 않았다 | H, I: §9 시나리오 27/27 |
| AC-05 | 인자, 응답, 오류에 canary 비밀값을 넣어도 기본 로그, spool, server API, manager에 원문이 없다 | `p/mcp_relay::observations_carry_no_content`; `p/relay_bytes::upstream_401_403_map_to_a_fixed_error`; `p/registry_client::definitions_and_keys_never_reach_logs_errors_reports_or_gaps`; `e/server_proxy_query_e2e::canary_is_absent_from_every_response`; `s/proxy_management_e2e::audit_records_carry_no_secrets_and_label_requested_by_as_asserted` | 6개 실행, 6 pass | partial | 위치로만 인용한 실제 호출 시험(`crates/lodeline-proxy-e2e/tests/inventory_e2e.rs:863`)은 다시 연 durable spool의 디코드된 이벤트(`:914-935`)와 invocation API(`:997-1012`)에서 호출 canary를 확인한다. 이는 디코드된 이벤트와 API 응답의 검사이며 원본 spool 바이트, proxy 로그, manager 화면의 훑기와 다르다. 첫 시험은 관찰 단위가 받는 값을 훑는다. 원본 spool 파일과 proxy 로그를 호출의 canary로 훑는 시험은 없다. server API 시험의 canary는 실제 proxy 호출이 아니라 시험이 만든 이벤트와 설정 필드에 넣은 값이다(`crates/lodeline-proxy-e2e/tests/server_proxy_query_e2e.rs:1185-1192`). manager 화면을 훑는 시험은 없다 | H, I: §10 훑기 B 15개, A 12개 파일에서 0건, 대조군 FOUND. I는 패키지 proxy의 journal 포함 16개 파일. manager 화면은 훑지 않음 |
| AC-06 | server 단절 중 호출을 기록하고 재연결하면 이벤트를 재전송한다. 중복은 합쳐지고 수집 공백은 숨겨지지 않는다 | `e/spool_ingest_e2e::central_outage_then_recovery_loses_nothing`; `e/spool_ingest_e2e::events_the_server_already_has_are_deduplicated_after_restart`; `e/spool_ingest_e2e::proxy_restart_during_an_outage_recovers_from_the_spool`; `e/spool_ingest_e2e::unsent_backlog_is_not_a_tail_gap_end_to_end`; `e/server_proxy_ingest_e2e::outage_opens_after_three_failures_and_closes_after_restart`; `e/server_proxy_ingest_e2e::happy_path_ack_after_200_and_duplicate_on_resend`; `e/server_proxy_query_e2e::sequence_and_tail_gaps_open_close_and_stay_listed`; `p/spool_crash::kill_mid_append_loses_no_acked_event` | 8개 실행, 8 pass | partial | 단절 시험의 이벤트는 시험이 spool에 직접 넣은 이벤트(`crates/lodeline-proxy-e2e/tests/spool_ingest_e2e.rs:390-394`)나 ingest 원천에 시험이 밀어 넣은 fixture 이벤트다. 서버가 내려간 동안 릴레이로 한 호출이 복구 뒤 같은 호출의 기록으로 도착하는 시험은 없다. 단절은 in-process 서버의 중지나 시험 fetcher의 오류이며 네트워크 분할이 아니다. 공백이 manager 화면에 보이는지는 실행하지 않았다 | H, I: §11 오프라인 뒤 정확히 6건 완료, 중복 없음. I는 systemd에서도 같음 |
| AC-07 | SSE, 취소, 버전별 세션 또는 요청 메타데이터, 큰 응답과 동시 호출에서 의미가 보존되고 자원 사용이 설정 한도를 지킨다 | `p/mcp_relay::sse_bytes_and_boundaries_survive_observation`; `p/mcp_relay::cancel_after_dispatch_is_forwarded`; `p/mcp_relay::cancel_before_the_request_arrives_prevents_dispatch`; `p/relay_bytes::sse_is_flushed_incrementally_and_boundaries_survive`; `p/relay_bytes::json_round_trip_is_byte_identical`; `p/relay_limits::request_body_limit`; `p/relay_limits::json_response_limit`; `p/relay_limits::sse_event_limit`; `p/relay_limits::route_concurrency_limit`; `p/relay_limits::principal_concurrency_limit`; `p/relay_limits::total_concurrency_limit`; `e/inventory_e2e::sustained_concurrent_calls_are_not_refused` | 12개 실행, 12 pass | partial | 세션 종료(DELETE) 요청에 대한 동시성과 시간 한도 시험은 없다. 한도 값은 시험 값이며 목표 환경의 값이나 측정한 처리량이 아니다. 요청 메타데이터 규칙은 AC-15 행의 시험이 다룬다 | H, I: §9 시나리오 27/27, `cancels_matched` 1 |
| AC-08 | localhost와 metadata 주소, IPv6, redirect, DNS 변경으로 허용 목적지를 벗어나거나 Origin을 속여도 접근 정책이 유지된다. 요청 URL, 헤더, 본문으로 upstream을 지정해도 등록된 고정 라우트의 upstream만 쓴다 | `p/relay_dest::name_resolving_to_loopback_relays`; `p/relay_dest::http_name_resolving_to_non_loopback_is_refused`; `p/relay_dest::rebinding_is_checked_per_request`; `p/relay_dest::ip_literal_skips_dns`; `p/relay_pool::pooled_connection_to_an_address_outside_this_check_is_not_taken`; `p/relay_auth::request_cannot_name_the_upstream`; `p/relay_auth::origin_check`; `p/relay_auth::foreign_host_is_rejected_on_loopback`; `p/relay_bytes::redirects_are_not_followed_or_relayed`; `p/lib::dest::tests::classification_table`; `p/lib::dest::tests::http_requires_all_loopback`; `p/lib::dest::tests::https_policy`; `e/server_proxy_dest_e2e::https_upstream_on_loopback_is_refused_before_any_connection`; `e/server_proxy_dest_e2e::https_upstream_name_resolving_to_loopback_is_refused`; `e/server_proxy_dest_e2e::server_refuses_a_config_with_a_private_or_metadata_upstream_literal` | 15개 실행, 15 pass | partial | 요청 본문으로 목적지를 지정하는 입력에 대해 고정 목표와 대체 연결 0건을 확인하는 시험이 없다. `request_cannot_name_the_upstream`의 쿼리와 헤더 입력은 `tools/list`(`crates/lodeline-proxy/tests/relay_auth.rs:9`, `:374-383`), 절대 URI 입력은 `ping`(`:391-403`)을 보내며 두 본문 모두 목적지를 지정하지 않는다. DNS 변경 시험의 답은 시험용 resolver가 돌려준 주소이며 실제 DNS 응답이 아니다(`crates/lodeline-proxy/tests/relay_dest.rs:21-31`, `:88-120`). HTTPS `localhost` 시험은 시스템 resolver를 쓴다(`crates/lodeline-proxy-e2e/tests/server_proxy_dest_e2e.rs:213-222`, `:286-295`). 클라우드 metadata 주소에 실제로 접속하는 시험은 없다. 공개 HTTPS(D2) 목적지는 실행하지 않았다 | H, I: D1(loopback fixture)만. D2는 측정하지 않음(19.5절) |
| AC-12 (P1 부분) | 재시작, 디스크 가득 참, 중앙 단절 주입 시 PX-011, PX-013, PX-016이 장애 표와 일치하고, 원격 설정 TTL이 만료되면 새 호출을 전달하지 않는다(spec.md:71-75) | `e/spool_ingest_e2e::full_spool_blocks_admission_and_reopens_after_draining`; `e/spool_ingest_e2e::expired_events_reach_the_server_as_a_spool_expired_gap`; `e/server_proxy_e2e::proxy_fails_closed_at_the_config_ttl_when_the_server_stays_down`; `e/server_proxy_e2e::proxy_fails_closed_at_the_config_ttl_while_a_config_fetch_is_in_flight`; `e/server_proxy_e2e::a_rolled_back_revision_is_refused_after_a_proxy_restart`; `e/server_proxy_e2e::proxy_serves_the_last_config_while_the_server_is_down_and_recovers`; `e/shutdown_stall_e2e::shutdown_does_not_wait_for_a_stalled_control_plane`; `e/server_proxy_ingest_e2e::storage_limit_backs_off_without_outage_and_resumes_after_sweep`; `e/server_proxy_query_e2e::projection_survives_restart_and_connection_goes_stale`; `p/lib::spool::tests::full_purges_acked_rows_before_refusing`; `p/lib::spool::tests::admission_maps_storage_failure_to_unavailable`; `p/lib::lifecycle::tests::restart_is_fail_closed`; `p/lib::config_sync::tests::poll_loop_enforces_the_ttl`; `p/lib::invocation_sink::tests::a_full_or_broken_spool_refuses_the_start` | 14개 실행, 14 pass | partial | TTL 시험은 시계를 앞으로 보내는 방식(`skip_clock`, 멈춘 tokio 시계)이다. TTL 기한은 단조 시계로 재며 호스트 일시중지를 세지 않는다고 코드가 적는데(`crates/lodeline-proxy/src/config_sync.rs:12-14`) 그 경우의 시험은 없다. 디스크 가득 참은 저장 실패 주입이며 실제 파일시스템의 가득 참 시험은 없다. 유효 정책 만료(PX-019)는 P2 부분이다 | H, I: §11 TTL 안의 서버 단절과 서버가 내려간 채 재시작해 `Expired`로 보고된 경우(TTL 만료를 기다리지 않음), §12 spool 가득 참(200 32회, 503 48회). I는 systemd에서도 같음 |
| AC-13 (P1 부분) | 조회자나 에이전트가 설정 변경 API를 호출하면 거절되고, 권한 있는 작업도 감사 기록을 남긴다(spec.md:76-77) | `s/proxy_config_e2e::put_requires_config_scope_and_management_cert`; `s/proxy_config_e2e::an_enroll_scope_entry_in_the_proxy_file_gets_403_on_management_routes`; `s/proxy_config_e2e::audit_failure_is_503_and_nothing_is_stored`; `s/proxy_management_e2e::check_order_404_401_binding_403_expired`; `s/proxy_management_e2e::management_cert_is_a_separate_class_in_both_directions`; `s/proxy_management_e2e::audit_is_written_before_the_effect_and_failure_is_503`; `s/proxy_management_e2e::operator_cli_end_to_end` | 7개 실행, 7 pass | pass | P1 부분만이다. PX-012 전체는 CSR 경로가 라우터에 없어(`crates/lodeline-server/src/proxy/mgmt.rs:666-690`) partial이다. 승인 API(PX-023)는 P3 부분이다. 인증서와 토큰은 시험용이고 manager 화면은 아니다 | H, I: 관리 감사 seq 0-4 `ok`. I의 패키지 실행은 seq 5-9 `ok` |
| AC-14 | 개인 설치(install.sh, install.ps1)와 Rocky rpm을 기본 옵션으로 설치하면 proxy가 활성화되거나 listen하지 않고, `--config` 없이는 기동하지 않으며, 기존 lodeline 동작이 같다 | `p/cli::run_without_config_fails_and_binds_nothing` | 1개 실행, 1 pass | partial | 이 시험은 `--config` 없이 종료 코드가 0이 아님만 확인하고 listener를 직접 확인하지 않는다(`crates/lodeline-proxy/tests/cli.rs:63-67`). 패키지 확인은 `.github/workflows/packages.yml`의 rocky9 rpm과 debian12 deb 단계에 정의되어 있고(`:72-94`, `:296-318`), 이 커밋의 Packages 실행은 성공으로 끝났다고 GitHub Actions에서 읽었다. 이번에 다시 돌리지 않았고 로그를 읽지 않았다. 컨테이너는 systemd가 없어 symlink 검사로 대신한다. macOS와 Windows의 설치 경로, 설치 전후 `lodeline doctor`와 `lodeline scan` 비교, Rocky 9 VM, SELinux 도메인은 실행하지 않았다 | I: 패키지 rpm을 systemd와 SELinux Enforcing에서 설치해 unit `disabled`와 listener 없음 확인(19.3절). 실행 환경은 Amazon Linux |
| AC-15 | support-matrix.md의 각 행을 §5 oracle대로 시험하면 지원 행은 표대로 동작하고 미지원 행은 행마다 정해진 응답과 감사 기록으로 거절된다. undecided 행이 남아 있으면 통과하지 않는다 | `p/mcp_relay::refusals_do_not_reach_upstream`; `p/mcp_relay::unauthenticated_modern_request_is_401`; `p/mcp_relay::duplicate_meta_cannot_hide_a_modern_request`; `p/mcp_relay::initialize_proposing_a_legacy_version_is_forwarded`; `p/mcp_relay::notifications_and_client_responses_are_relayed_without_events`; `p/mcp_relay::sse_outcomes`; `p/relay_auth::non_post_methods_are_405_after_auth`; `p/sessions_http::unsupported_initialize_and_unreadable_answers_cleanup_without_a_session`; `p/sessions_http::stateful_delete_preserves_on_errors_then_ends_once`; `p/sessions_health::an_unsupported_binding_refuses_the_next_initialize_locally_until_repointed`; `p/lib::mcp::classify::tests::method_vocabulary_and_unknown` | 11개 실행, 11 pass | partial | 지원 표에 [OPEN] 4행이 남아 있어(`docs/specs/lodeline-proxy/support-matrix.md:27`, `:30`, `:87`, `:95`) 표의 방침대로 부분 충족이다. `resources/list`, `resources/read`, `prompts/list`, `prompts/get`의 중계와 `tools/call`의 `params.task` 전달은 분류 단위 시험만 있고 중계 시험이 없다. 감사 reason 값은 [OPEN]이라 시험하지 않았다. vendor client 없음 | H, I: §9 시나리오 27/27이 AC-15를 추적 대상에 두지만(`aws-smoke-test.md` 5행) 행별 oracle 결과는 기록하지 않음 |

### 판정 (a1619c89)

a1619c89에서 P1 AC 행 AC-02, AC-03과 AC-13(P1 부분)은 위 시험 범위에서 pass이고, AC-01, AC-04, AC-05, AC-06, AC-07, AC-08, AC-12(P1 부분), AC-14, AC-15는 열려 있다. 이 절은 시험 결과의 기록이며 출시 판단이 아니다.

- partial 행의 남은 부분은 각 행의 "이 증거가 보이지 않는 것" 칸에 적었다.
- 실행하지 않은 것: vendor client(proxy 경유), 목표 환경의 성능 측정, 공개 HTTPS, 목표 환경 하드웨어(x86_64)에서의 검증, Rocky 9 VM, SELinux 도메인, 실제 proxy 호출을 manager 화면에서 확인하는 시험. 이들은 `not run`이며 이 절의 pass로 대신하지 않는다.
- 현재 버전(0.22.0)에서 AWS를 다시 돌리지 않았다. 이전 실행 칸은 해당 버전의 기록이다.
- 지원 표의 [OPEN] 행이 남아 있는 동안 AC-15는 pass가 아니다.

### 2026-11-28 이후 (소유자 결정 Q10)

위 표와 판정은 a1619c89에서 실행한 기록이며 다시 실행하지 않았다. 2026-11-28 소유자 결정 Q10([decisions.md](decisions.md))으로 지원 표의 [OPEN] 4행이 닫혔다. 그 계약을 고정하는 시험 3개를 추가했고 86e52851에서 실행해 모두 pass였다: `p/mcp_relay::batch_refusal_is_a_fixed_invalid_request`, `p/mcp_relay::missing_or_legacy_version_header_after_initialize_is_an_empty_400`, `p/lib::invocation_sink::tests::a_version_header_refusal_is_stored_as_protocol_error_not_sent_without_a_reason`. AC-15는 위 AC-15 행의 다른 이유(vendor client 없음 등)로 여전히 partial이다. 지원 표에 undecided 행은 없다.

## D-04: 첫 배포와 수치 한도 (P1 초기 기본값)

첫 production 검증 대상은 **Rocky Linux 9 단일 proxy 프로세스**로 확정했다(2026-10-10 사용자 결정, [decisions.md](decisions.md) D-04).
RHEL 계열 기준으로 SELinux enforcing과 rpm 배포를 포함해 검증한다. 초기 권고안(Ubuntu 24.04 LTS x86_64)은 대체되었다.
macOS arm64는 현재 fixture 개발 환경일 뿐 production 검증 대상 확정 근거가 아니다.
아래 값은 P1 초기 기본값으로 채택했다(2026-10-10). 구현/측정 전이며 성능 보장이 아니다. 설정 이름은 T-02 계약에 맞춘다.
단위 MiB/GiB는 2진 단위이며 압축 사용 시 decoded 크기도 제한한다.

| 대상 | 기본 한도 | 초과/장애 시 동작 |
|---|---|---|
| HTTP request body / header | 1 MiB / 32 KiB | upstream 전달 전 413 / 431; 원문 로그 금지 |
| 단일 JSON 응답 / SSE event | 8 MiB / 1 MiB | bounded parser로 종료; 이미 전달한 호출은 outcome unknown 가능 |
| 호출별 응답 누적 / 대역폭 | 64 MiB / 4 MiB/s | 누적 초과 종료, 속도는 backpressure; 무한 buffer 금지 |
| 프로세스 응답 대역폭 | 32 MiB/s | 공유 제한; 느린 reader도 bounded buffer 유지 |
| 동시 호출 | 전체 64, route 16, principal 8 | 새 호출 429, 자동 tool retry 없음; 활성 SSE도 1개로 계수 |
| 활성 세션 | 전체 256, principal 32; idle 15분 | 초기화 거절/idle 만료; 활성 호출을 idle로 보지 않음 |
| 대기 queue | 기본 0 | 과부하 즉시 거절; 숨은 무제한 대기 금지 |
| connect / response idle / 호출 전체 | 5초 / 30초 / 120초 | 단계별 timeout; upstream 전송 후에는 미실행으로 단정 금지 |
| 종료 grace | 30초 | 새 수락 중단, 진행 호출 drain; 잔여 호출 불명/감사 복구 |
| tool inventory | 100 page, 10,000 tool, 총 16 MiB | 불완전 snapshot 표시; baseline 삭제 판단 금지 |
| 감사 event / spool | event 16 KiB, spool 1 GiB + 별도 gap reserve 16 MiB | 80% degraded (ingest가 멈춘 동안(`central.ingest_stopped`, ledger L5)은 80% 미만이어도 degraded로 보고), 100% 기본 새 호출 중단; 기존 in-flight 완료 기록용 여유 설계 |
| spool 보관 | 미전송 event는 최대 재시도 기간 R 경과 후 quarantine으로 이동하고 `spool_expired` gap 보고(O-1 A, 2026-10-10 결정, 삭제 없음); ack 이후 24시간 보관 상한 | 공간 부족 시 ack된 자료부터 정리, 미전송 자료 삭제로 정상처럼 보이지 않음 |
| 프로세스 resource budget | steady RSS 256 MiB 목표, cgroup memory.max 512 MiB, CPU 2 core | hard kill 복구 시험 필수; 상한 도달 전에 admission/backpressure |

fixture 자체의 64 KiB/3초 제한과 위 production 후보를 혼동하지 않는다.
스풀 reservation은 동시 in-flight 호출의 terminal event 수용까지 계산해야 한다.
시간/응답 한도 종료는 upstream 부작용을 취소하지 않으며 감사 전송 retry와 도구
실행 retry를 분리한다. 실측 전에 이 값을 지원 보장으로 게시하지 않는다.

## P1 성능 시험 환경과 합격 목표 제안 (미측정)

고정 환경: Rocky Linux 9(SELinux enforcing), 4 vCPU/8 GiB RAM/40 GiB SSD VM, 아키텍처를 결과에 명시(aarch64·x86_64는 서로 다른 baseline),
proxy에 2 vCPU/512 MiB cgroup, release build, 동일 host의 합성 upstream과 load driver.
upstream과 driver는 남은 CPU에 배치하고 CPU 모델/주파수 정책, hypervisor,
kernel, Rust/compiler/dependency lock, commit, filesystem, TLS 설정과 모든 limits를
결과에 기록한다. 가용 환경이 다르면 같은 표의 새 baseline으로 명시하고 섞지 않는다.
성능용 synthetic load server/driver는 별도 준비가 필요하며 이 Python smoke를
성능 서버로 사용하지 않는다. Proxy hot path 비교와 TLS 배포 비교를 별도 측정한다.

1. direct client → fixture와 client → proxy → 같은 fixture를 교대로 실행한다.
   P1 audit/spool은 켜고 local control-plane collector를 붙인다. 중앙 단절은 별도 run이다.
2. synthetic 1 KiB request/4 KiB JSON response로 concurrency 1/8/32/64,
   30초 warm-up + 300초 측정, 각 조건 3회 수행한다. 100 calls/s 고정 offered load도
   측정하고 최대 sustainable throughput은 별도 sweep으로 관찰한다.
3. 1 MiB request/8 MiB JSON response 경계와 limit+1 거절, 32개 SSE 각 60초,
   초당 1 KiB event, slow reader, 65개 동시 호출 및 principal별 포화를 시험한다.
   동일 부하의 direct baseline을 함께 기록한다.
4. 중앙 10분 단절, spool fill, grace 종료/강제 재시작, accepted-call drop을 별도 수행한다.
   spool은 시험용 임시 디렉터리에 한정하고 운영 디스크나 실제 credentials를 쓰지 않는다.
5. 요청별 latency 분포와 p50/p95/p99, 실패/거절율, completion rate, CPU,
   최대 RSS, 열린 FD, 활성 연결, queue/buffer, spool bytes/event를 기록한다.
   direct/proxied 분위수 차이는 비교 지표이며 개별 요청 지연 차이로 해석하지 않는다.

후보 합격 목표: 작은 JSON 100 calls/s, concurrency 32에서 direct 대비 추가
p50 ≤ 2 ms / p95 ≤ 10 ms / p99 ≤ 25 ms, 예상 밖 오류 0, 정상 부하 거절 0,
steady RSS ≤ 256 MiB, 모든 run RSS < 512 MiB. 32개 SSE의 event delivery 추가
p95 ≤ 20 ms, 종료 후 연결/메모리 증가가 누적되지 않을 것. 최대 처리량 값은
측정 결과로 보고하며 이 목표를 현재 throughput으로 주장하지 않는다.
한도/장애 run의 예상 거절은 정상 부하 오류율과 분리해 보고한다.

D-04는 OS(Rocky Linux 9)와 limits를 P1 초기 기본값으로 채택했다(2026-10-10). 위 성능 목표는 미측정이다. P1 출시에는 위 측정 결과, 실제 vendor client 1종 이상,
proxy/server/manager E2E, 독립 리뷰, AC 전체 결과가 추가로 필요하다.

## 성능 측정 도구 (2026-11-07)

위 "별도 준비가 필요한" synthetic load server와 driver는 `crates/lodeline-proxy-loadgen`이다. 사용법, 출력 형식,
proxy cgroup 명령은 [그 README](../../../crates/lodeline-proxy-loadgen/README.md)에 있다. 단일 호스트 stack
(시험 PKI, local collector인 `lodeline-server`, proxy, load server)은 `crates/lodeline-proxy-loadgen/stack.sh`가 만든다.
release 산출물과 OS 패키지에는 들어가지 않는다.

위 절차와의 대응:

- 1단계: 같은 round 안에서 direct와 proxied를 차례로 돌리고 round를 반복한다. 홀수 round는 direct, 짝수 round는 proxied가
  먼저이고 순서는 report의 `round_order`에 남는다. audit/spool과 local collector는 켠 채다.
  추가 지연은 같은 round의 proxied 분위수에서 direct 분위수를 뺀 값이고, round별 중앙값과 범위를 함께 낸다.
- 2단계: 1 KiB 요청, 4 KiB JSON 응답이 기본값이다. 100 calls/s 고정 부하는 open loop(`--rate 100 --concurrency 32`)다.
  concurrency 1/8/32/64와 최대 처리량은 closed loop(`--concurrency C`)로 잰다. warm-up 30초, 측정 300초, 3 round가 기본값이다.
- principal 하나는 동시 호출 8, route 하나는 16을 넘을 수 없으므로(D-04, 429), concurrency C에는 principal C/8개 이상과
  route C/16개 이상이 필요하다. `principals` 하위 명령이 token, verifier가 든 config, driver용 targets를 만든다. 기본값
  principal 8개, route 4개는 concurrency 32까지 모든 한도 아래다. 64에서는 principal마다 정확히 8, route마다 16으로 한도와
  같으므로 principal 16개, route 8개를 쓴다. 64는 그래도 proxy 전체 한도와 같다.
- 5단계 판정: 측정 구간에 오류가 하나라도 있거나 load server 호출 수가 성공 응답 수(`ok_all`)와 다르면 `run`은 0이 아닌
  값으로 끝난다(report는 남긴다). 429를 일부러 내는 run은 `--allow-errors`로 오류만 허용하고, 호출 수 불일치는 늘 실패다.
- 5단계: 요청별 분포, p50/p95/p99/max, 오류 종류별 개수, 처리량, load server가 실제로 받은 호출 수를 JSON으로 남긴다.
  proxy의 최대 RSS(`VmHWM`), CPU 시간, 열린 FD, cgroup `memory.peak`, spool 크기는 `stack.sh stats`로 읽는다.

절차와 다른 점:

- `latency_ms`의 시작점은 호출 task가 실행된 시각이다. 그 뒤 lane 슬롯을 기다린 시간은 latency에 들어간다. 예정 시각부터 task
  실행까지 driver 자신의 timer 지연은 `send_lag_ms`로 따로 낸다. macOS에서는 이 지연이 p50 약 2.5 ms라 예정 시각을
  시작점으로 쓰면 direct 쪽 값이 driver 지연으로 채워진다. 대신 예정 시각부터 잰 `latency_from_due_ms`와 그 추가 지연을
  함께 낸다. proxy와 CPU를 다투어 driver가 늦어지면 그 지연은 이쪽에 드러난다. send lag p99가 1 ms를 넘으면 요약이 경고한다.
- latency 분포에는 성공 호출과 timeout이 들어간다. timeout은 경과 시간(`--timeout` 이상)으로 기록하므로 timeout이 있으면
  p99와 max는 하한이고 요약이 경고한다. 그 밖의 오류(즉시 답하는 429 등)는 분포에 넣지 않고 따로 센다.
- 연결은 HTTP keep-alive pool을 쓴다. 2026-11-06 이전 Python harness는 호출마다 새 연결이었다.
- 3단계(큰 요청/응답, limit+1, SSE, slow reader)와 4단계(중앙 단절, spool fill, 재시작)는 아직 없다. TLS listener 비교도 없다.
- queue/buffer 깊이, 활성 연결 수, event당 spool bytes는 driver가 표본을 뜨지 않는다.
