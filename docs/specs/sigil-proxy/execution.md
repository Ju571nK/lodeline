# Sigil Proxy 작업 상태

갱신: 2026-10-11 · Claude Code orchestrator 세션 (기준 커밋 `2120415`)

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
