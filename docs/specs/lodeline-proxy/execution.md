# Lodeline Proxy 작업 상태

갱신: 2026-11-07 · 종료 뒤 join 상한 확인(`fix/proxy-shutdown-joins`), 종료 grace 하나로 묶기(`fix/proxy-shutdown-deadline`), spool group commit(`perf/proxy-group-commit`)과 AWS gp3 전후 측정, closed loop 꼬리 로컬 계측(`perf/proxy-gc-tail`), upstream 연결 재사용(`fix/proxy-upstream-pool`), 성능 측정 도구(`feat/proxy-loadgen`), 지속 부하 503 수정(`fix/proxy-writer-queue`), spool 기록별 내구성(`perf/proxy-spool-sync`), registry lookup 슬롯 503 수정(`fix/proxy-lookup-503`), AWS 실기 run I (기준 커밋 `3500adb`)

## 현재 상태

- **이름 변경.** Sigil Proxy는 Lodeline Proxy가 됐다. 이 문서의 2026-10-31 이전 기록도 새 이름으로 읽는다(`sigil-proxy` → `lodeline-proxy`). hash·서명 domain, `canon` 값 `sigil-tooldef-fp-v1`, SAN `*.proxy.sigil.invalid`는 기존 데이터 호환을 위해 그대로다. 근거 커밋의 hash는 rename 전 기록이다. 절차는 [migrate-from-sigil.md](../../migrate-from-sigil.md).
- **P0 종료(2026-10-11, 계약 수준, 사용자 결정).** 잔여 항목과 담당 P1 작업은 [decisions.md "P0 종료"](decisions.md).
  계약 종료는 구현·실기 검증 완료가 아니다.
- P1 착수. 사용자 창구: 이 대화의 orchestrator. 하위 작업은 구체적인 파일 소유권과 인수 조건을 지정하고, 실행 provider/model 기본값을 유지한다.
- 이전 회차 작업자 16명은 2026-10-11 모두 종료했다.
- **실기 측정 범위(2026-11-06 run I 기준).** AWS(t4g.small 2대, AL2023 aarch64, D1)에서 측정됨: 상태 유지 §9–§13, `--stateless`·`--initialize-sse`·둘 다 변형(§9–§10), RPM 패키지 + systemd 유닛(SELinux Enforcing, AVC 0건). 아직 미측정: vendor client(R), D2 공개 HTTPS, x86_64, [validation.md](validation.md)의 성능 목표(목표 환경에서). 성능 측정 도구와 t4g.small 실측은 아래 `feat/proxy-loadgen` 절. 단일 호스트 패키지 시험은 호스트 사이 경로를 지나지 않았고, Rocky 9도 시험하지 않았다.
- **열린 항목: proxy SELinux 도메인.** `lodeline-proxy.service`는 `unconfined_service_t`로 실행된다. `packaging/selinux/`의 `lodeline.te`와 `lodeline.fc`에 proxy 규칙이 없고, 유닛 파일 주석과 `packaging/README.md`가 "proxy 도메인은 hardware verification 때까지 보류, 그동안 unconfined"라고 적는다. run I는 이 상태에서 Enforcing AVC 0건을 확인했을 뿐, 제한된 `lodeline_proxy_t` 도메인은 없고 따라서 측정하지 않았다.

## 2026-11-07 종료 뒤 join 상한 확인 (`fix/proxy-shutdown-joins`)

#509 리뷰 후속. 질문: blocking 작업 대기 앞의 `inventory_handle.shutdown()`, 일곱 task join, 뒤의 `spool.close()`는 deadline 없이 기다린다.
어느 하나가 멈추면 `TimeoutStopSec=45`를 넘을 수 있는가. 결론: 코드 변경 없음. 기다림은 모두 stop을 보고 끊기거나 한정된 로컬 디스크 작업이다.

| 기다림 | 지금 무엇이 끝을 정하나 |
|---|---|
| `inventory_handle.shutdown()` | 큐 최대 256개(`QUEUE_DEPTH`)와 열린 chain 최대 8개(`MAX_COLLECTORS`)의 registry SQLite commit |
| `sync_task` | `run_sync`가 대기와 fetch를 모두 stop과 `select!`한다. fetch 자체는 10초(`FETCH_TIMEOUT`) |
| `report_task` | `run_status_reporter`가 대기와 `send_once`를 stop과 `select!`한다. 요청 자체는 10초 |
| `ingest_task` | `run_ingest`가 `send_once`와 대기를 stop과 `select!`한다. 요청 자체는 10초 |
| `pump_task` | 진행 중인 gap hand-off 한 번(spool 읽기, gap queue 기록, spool 삭제). 그 뒤 대기는 `select!` |
| `retention_task` | 대기만 있고 `select!`한다 |
| `registry_task` | `RegistryClient::run`이 `sync_once`와 대기를 stop과 `select!`한다. 요청 자체는 20초 |
| `entry_retention_task` | 진행 중인 pass 한 번(최대 500행 삭제 transaction 하나). 그 뒤 대기는 `select!` |
| `spool.close()` | writer가 받은 명령을 끝내고 `Shutdown`에서 나온다. maintenance는 500행 단위 |

측정(로컬 macOS, 연결은 받고 응답하지 않는 control plane, 시험 전용 단계 시각 출력, 3회): 신호에서 relay drain 11 ms, 감사 drain까지 11 ms,
inventory 종료까지 25–27 ms, 일곱 join은 합쳐 1 ms 미만, `spool.close()` 2 ms, 전체 38–40 ms. 대조: `run_sync`의 fetch `select!`에서
stop 가지를 빼면 sync join이 9.6초를 기다렸다. 빠진 stop 하나가 요청 시간 제한만큼 종료를 잡는다는 뜻이고, 지금 코드에는 그런 기다림이 없다.

디스크 작업은 개수로 한정된다. 앞 절의 AWS gp3 fsync 중앙값 2.12 ms로 추정하면 inventory는 1초 미만이고, 나머지는 commit 몇 개다.
남은 여유(기본 약 9.5초) 안이다. 멈춘 디스크는 프로세스 안에서 끊을 수 없다. `spawn_blocking`은 취소되지 않고, tokio runtime drop은 blocking 작업을
끝까지 기다리며, `stopped` 기록도 같은 디스크에 쓴다. join에 시간 제한을 걸어도 결과는 SIGKILL과 같다(`stopping`에 머물고 spool WAL은 FULL commit까지
남는다). 그래서 제한을 추가하지 않았다.

시험: `lodeline-proxy-e2e` `shutdown_stall_e2e::shutdown_does_not_wait_for_a_stalled_control_plane`. config fetch, status report, event post 세 연결이
handshake에서 멈춘 상태로 종료하고 5초 안에 끝나는지 본다. sync, report, ingest 각각에서 stop 가지를 빼면 9.9–10.0초로 실패하고, 지금 코드는 0.3–0.5초(시험 전체)로 통과한다.

## 2026-11-07 종료 grace 하나로 묶기 (`fix/proxy-shutdown-deadline`)

#507 리뷰 후속 N1·N2. 문제: `run_inner`의 종료 단계가 grace를 각자 새로 받았다. relay drain(`serve`, grace), 감사 producer drain
(`InvocationHandle::shutdown(grace)`), #507의 blocking 작업 대기(grace)가 이어져 최악 약 3 × grace(기본 90초)였다. 배포 유닛의
`TimeoutStopSec=45`를 넘으면 systemd가 SIGKILL하고 `stopped`와 durable 집계가 기록되지 않는다.

수정(`lifecycle.rs`): shutdown future가 끝난 시각(신호)을 `OnceLock`에 남기고 `deadline = 신호 + grace`를 한 번 계산한다. 감사 drain은
남은 시간만 받되 최소 0.5초(`AUDIT_DRAIN_FLOOR`)를 받고, blocking 작업 대기도 같은 deadline에서 끝난다. 늦은 단계는 남은 시간만 받으므로
진행 중 completion이 spool 기록 대신 집계된 gap으로 끝나는 경우가 늘 수 있다. `stopped` 전에 SIGKILL되지 않는 대가다. 감사 producer의
gap handover 5초 상한은 grace 밖에 그대로 남는다(기본 30 + 0.5 + 5초 < 45초). blocking 작업 대기가 끝날 때 경고에
gap queue·registry handle 수를 남긴다(N2). 유닛 주석과 `config/proxy.example.yaml`에 grace를 올리면 `TimeoutStopSec`도 올리라고 적었다.

시험: `lifecycle::tests::shutdown_phases_share_one_grace`(grace 2초, 요청 head 중간에 멈춘 client가 relay drain을 잡고, 시험 전용
`RunTuning::gaps_out`으로 받은 gap queue 사본이 blocking 작업 대기를 잡음). 수정 전 4.05초(2 × grace)로 실패, 수정 후 통과(시험 전체 2.3초). 상한은 floor와 느린 CI를 감안해 grace + 1.5초.

## 2026-11-07 spool start 기록 group commit (`perf/proxy-group-commit`)

목표: AWS gp3에서 closed loop 처리량이 초당 약 400회(동시성 32에서 378, tmpfs 2,049)에 묶인 것을 푼다. 내구성 계약([decisions.md](decisions.md)
"spool 기록별 내구성", 2026-11-06)은 바꾸지 않는다.

변경 전 상한: spool writer는 `invocation.started` append 하나마다 FULL transaction 하나를 commit했다. 동시 호출의 start는 writer 채널에서 줄을 서고
fsync를 하나씩 기다렸다. #499의 `recv_many`는 completion을 넘기는 sink writer에 있고 spool writer에는 묶음이 없었다(코드 확인). 로컬 macOS에서
동시성 32 closed loop 중 `sample`로 본 spool writer 스레드 표본 3,070개 중 2,422개가 `fsync`, 약 500개가 `pwrite`였다(표본기가 느리게 만든
run이라 처리량은 쓰지 않음). 앞 절의 AWS strace(WAL fsync/저장된 start 1.01, fsync 중앙값 2.12 ms, CPU 80% idle)와 같은 상한이다.

수정(`spool.rs` `Writer::append_group`): writer가 append 명령을 받으면 채널에 이미 와 있는 append를 `try_recv`로 최대 64개(`APPEND_GROUP_MAX`)까지
더 꺼낸다. 기다리는 타이머는 없다. append가 아닌 명령이 나오면 묶음을 닫고 그 명령을 다음에 처리하므로 명령 순서는 그대로다. 묶음의 기록은 차례로
NORMAL commit하고, start가 하나라도 저장됐으면 바꾸는 값 없는 FULL commit(`PRAGMA user_version = 0`, page 1을 늘 씀) 하나로 WAL을 fsync한다.
그 뒤에야 묶음의 모든 응답을 보낸다. start는 그 fsync가 성공했을 때만 Ok를 받고, `durable_seq`도 그때 오른다. 혼자 온 start는 전처럼 자기 FULL
commit을 한다. 같은 행을 바꾸지 않는 `UPDATE`는 SQLite가 page를 쓰지 않아 fsync가 일어나지 않았다(첫 시험에서 확인).

계약이 지켜지는 이유: 전달은 start append의 Ok 뒤에만 일어나고(`invocation_sink.rs` `record_start`), Ok는 그 행을 덮는 fsync 뒤에만 나간다.
fsync 전 process crash는 행을 page cache에 남기지만 응답이 없었으므로 전달된 호출이 없다(start만 있는 기록). fsync 전 전원 손실은 그 행을 잃지만
역시 전달된 호출이 없고, 넘기지 않은 sequence라 다시 배정돼도 된다. fsync가 실패하면 묶음의 start는 모두 `Storage`로 거절되고 spool은 degraded다.
이미 commit된 행은 다음 fsync 때 start만 있는 기록이 될 수 있다(전달 없음, 과다 기록 방향). completion·cancel은 원래 NORMAL이라 결과가 그대로다.
completion은 자기 start가 Ok를 받은 뒤에만 queue에 들어가므로(`settle_start`) 앞 묶음에서 이미 durable한 start 뒤에 온다. checkpoint와
maintenance는 명령 사이에서 그대로 돌고, 묶음 하나는 checkpoint를 최대 63 명령 늦출 수 있다.

시험(`spool.rs`, 시험 전용 명령 `Cmd::Hold`로 writer를 잡아 명령을 쌓고, `sync_vfs.rs`에 `fail_syncs`를 더함):
`queued_starts_share_one_fsync`(start 9개와 completion 1개가 WAL fsync 1번, 그 fsync 뒤 전원 손실 사본에 Ok를 받은 start가 모두 있음),
`a_failed_group_fsync_refuses_every_start`(공유 fsync 실패: start 4개 모두 `Storage`, completion은 Ok, durable하지 않은 행은 넘기지 않음,
전원 손실 사본에는 묶음 전 행만 있음). mutation 2개(`APPEND_GROUP_MAX = 1`, fsync 실패를 무시)는 각 시험에서 실패했다.
`sustained_concurrent_calls_are_neither_refused_nor_lost`, `the_tail_a_status_names_survives_a_power_loss`, `only_a_start_commit_fsyncs`를
포함한 proxy·proxy-e2e 시험은 그대로 통과한다.

로컬 측정(macOS aarch64 12코어, APFS, `lodeline-proxy-loadgen`·`stack.sh`, principal 16 × route 8, run마다 warm-up 3초 + 15초, 기준 main
`9f85676`과 변경 바이너리를 stack 단위로 3번 교대, 오류 0, upstream 수 불일치 0). 같은 시간에 다른 작업이 CPU와 디스크를 크게 써서(load average
15–29) 절대값은 잡음이 크다. 양쪽이 같은 잡음을 보도록 교대했다. proxied 성공 호출/s, 중앙값(범위):

| 조건 | 기준 | 변경 |
|---|---|---|
| closed 동시성 1 | 120 (66–194) | 88 (54–470) |
| closed 동시성 8 | 171 (82–297) | 243 (184–298) |
| closed 동시성 32 | 202 (124–393) | 466 (336–662) |
| closed 동시성 64 | 222 (200–338) | 756 (736–861) |
| open 100 calls/s 동시성 32, p50 / p95 / p99 ms | 24.1 / 823 / 933 | 15.9 / 620 / 878 |

동시성 64는 3 round 모두 변경이 높았다(2.2–3.7배). 동시성 32는 2/3 round에서 높았다. 동시성 1은 묶을 start가 없으므로 차이가 없어야 하며,
범위가 겹쳐 측정된 차이는 없다. open loop 지연은 잡음 때문에 결론 없음이다. due 기준 지연도 같은 방향이다(보고서 `latency_from_due_ms`).

### AWS gp3 전후 측정 (2026-11-07)

환경: 노드 A만(t4g.small 2 vCPU, Neoverse-N1, AL2023 aarch64, kernel 6.18.54, rustc 1.99.1, CPU credit unlimited). state는 gp3 루트 볼륨
(xfs, 3,000 IOPS, 125 MB/s). 기준 `c24bd16`(merge의 부모)과 변경 `0fcacf6`을 노드에서 release로 빌드해 두 벌로 두었다. 한 호스트에
`lodeline-server`(local collector), proxy, load server, driver가 있다. proxy는 `systemd-run --scope`(MemoryMax 512M, AllowedCPUs 0)로
CPU 0, 나머지는 `taskset -c 1`. 모든 동시성에서 principal 16 × route 8. stack 하나에서 closed loop 동시성 1 → 8 → 32 → 64(각 warm-up
10초 + 30초)와 open loop 100 calls/s 동시성 32(warm-up 30초 + 300초)를 차례로 돌렸다. 바이너리는 stack 단위로 기준, 변경, 변경, 기준,
기준, 변경 순서로 교대했다(측정 3 round씩). 모든 run에서 오류 0, upstream 호출 수 = 성공 응답 수였다.

proxied 성공 호출/s, 3 round 중앙값(범위):

| 조건 | 기준 | 변경 |
|---|---|---|
| closed 동시성 1 | 355 (335–359) | 356 (354–359) |
| closed 동시성 8 | 432 (424–440) | 639 (638–643) |
| closed 동시성 32 | 468 (467–473) | 742 (737–748) |
| closed 동시성 64 | 471 (457–475) | 752 (743–756) |

추가 지연(proxied - direct), ms, p50 / p95 / p99, round 중앙값. closed loop는 due 기준 값도 같다. open loop는 양쪽 모두 proxied send lag p99가
1 ms를 넘어(4.0–5.8 ms) due 기준 값을 함께 적는다.

| 조건 | 기준 | 변경 |
|---|---|---|
| closed 동시성 1 | 2.24 / 4.18 / 10.8 | 2.24 / 4.05 / 10.3 |
| closed 동시성 8 | 16.0 / 25.9 / 43.9 | 7.31 / 40.0 / 77.7 |
| closed 동시성 32 | 58.8 / 92.6 / 124 | 15.8 / 157 / 338 |
| closed 동시성 64 | 117 / 178 / 212 | 27.0 / 340 / 557 |
| open, closed 뒤 같은 stack, 300초 × 3 round | 3.30 / 8.33 / 20.9 (due 3.09 / 9.01 / 17.1) | 3.40 / 31.6 / 115 (due 3.10 / 31.4 / 113) |
| open, 새 stack, 120초 × 2 round(변경, 기준, 기준, 변경 순) | 3.29 / 7.12–7.36 / 14.9–15.5 (due 2.61–2.98 / 7.08–7.59 / 14.2–14.8) | 3.25–3.29 / 7.06–7.11 / 13.9–15.0 (due 3.41–3.55 / 7.97–8.13 / 13.8–14.9) |

한계 요인(strace는 보고하지 않는 별도 run에서, `strace -f -T -y -e trace=fsync,fdatasync`):

- 동시성 1은 묶을 start가 없어 같다. WAL fsync/proxied 호출은 기준 1.01, 변경 1.01이고 처리량 범위가 겹친다.
- 기준은 start fsync 직렬이 상한이다. WAL fsync/proxied 호출이 동시성 1, 64, open 모두 1.01이고 fsync 중앙값은 1.3–2.5 ms다.
  fsync 하나가 호출 하나를 덮으므로 동시성 32·64의 평탄값 468–471 calls/s는 호출당 약 2.1 ms이고, 이 fsync 범위 안이다. 보고 run에서
  CPU 0 busy 35–37%, iowait 53–55%.
- 변경은 동시성 64에서 WAL fsync 335번에 호출 8,622회(0.039/호출, 묶음 평균 약 26)이고 fsync 시간 합은 run 약 25초 중 1.45초다.
  fsync는 더 이상 상한이 아니다. open 100 calls/s에서는 0.98/호출로 묶음이 거의 생기지 않는다. 보고 run(동시성 32·64)에서 CPU 0 busy 28–32%,
  iowait 58–65%, proxy CPU 0.43–0.45 ms/호출(기준 0.77–0.79), CPU 1(driver, load server, collector) busy 14–16%라 CPU도 driver도
  상한이 아니다. 0.1초 간격 thread 표본에서 proxy thread가 D 상태로 `rq_qos_wait`(block 계층 쓰기 throttle),
  `folio_wait_bit_common`(writeback 중인 page), `xlog_wait_on_iclog`(xfs log)에 있었다. 그래서 변경 뒤 상한은 gp3 쓰기 I/O로 본다
  (추정이다. 같은 볼륨을 collector도 쓰고, 한 자원으로 확정하지 못했다).
- 표의 closed 값은 앞 run이 남긴 쓰기 위에서 쟀다. 새 stack(빈 spool)에서 동시성 64 단일 run은 기준 502, 변경 1,415 calls/s였다
  (변경 CPU 0 busy 73%, 1 run씩이라 참고값).

closed loop의 꼬리: 변경은 p50이 줄고 p95·p99가 커졌다(동시성 64 p99 212 → 557 ms). 이 run에서는 원인을 계측하지 않았다. 로컬 계측은 아래 절.

open loop의 꼬리: closed 뒤 같은 stack에서는 변경의 p95·p99가 컸지만 run 순서 때문이다. 볼륨의 분당 VolumeWriteOps(CloudWatch)를
보면 open run의 direct 절반(proxy에 호출이 없음)에서도 디스크가 3,000 IOPS 한도에 붙어 있었다. 기준은 약 3.5분 뒤 풀려 proxied
절반이 약 2,120 IOPS였다. 변경은 closed 단계 네 개에서 upstream 호출을 약 48–50% 더 처리했고(warm-up 포함, 3 round, 이 stack의 spool이 더 커졌다) 330초 내내 약 3,015 IOPS였다. 호출이 없을 때 쓰는 프로세스는
local collector `lodeline-server`였다(write syscall 13,020/s, 26.6 MB/s, proxy는 314/s). 앞 run 없는 새 stack에서는 차이가 없다(위 표).

그 밖: proxy VmHWM 기준 16.3–16.7 MiB, 변경 18.6–19.2 MiB. cgroup memory.peak 172 MB → 221 MB(spool page cache 포함, 변경이 이 stack에서 호출을
더 처리함. closed 네 단계와 open 단계를 합친 upstream 호출이 3 round에서 33–34% 많았다). FD 25–26. 인스턴스 EBSIOBalance%는 100에서 57%로 줄었고(고갈 아님) EBSByteBalance%는 90% 이상이었다. 앞 절의
수치(281 / 313 / 378 / 416 calls/s)는 #503 전이고 principal 8 × route 4라 이 run과 직접 비교하지 않는다.

미검증: tmpfs 전후, closed loop 꼬리의 원인, collector를 다른 디스크나 호스트에 둔 구성, 실제 전원 차단(모사만 함), Rocky 9·목표 VM.

### closed loop 꼬리 로컬 계측 (2026-11-07, `perf/proxy-gc-tail`)

위 AWS run에서 커진 closed loop p95·p99의 원인을 로컬에서 찾으려 했다. 로컬에서는 그 꼬리 모양이 재현되지 않았고, AWS의 원인은
확정하지 못했다. 코드는 바꾸지 않았다.

환경: macOS arm64 12코어, APFS, release, `lodeline-proxy-loadgen`·`stack.sh`, principal 16 × route 8, round 1. 기준 `c24bd16`과
main `08a9167`의 proxy만 바꾸고 server와 driver는 같은 바이너리를 썼다. stack 단위로 교대했다. 모든 run에서 오류 0, upstream 호출 수 =
성공 응답 수였다. 다른 작업과 함께 돌아 load average가 6–13이었다. 절대값은 참고값이다.

기본 설정(warm-up 5초 + 20초, 기준, 변경, 변경, 기준, 기준, 변경 순서로 3 round씩). proxied 성공 호출/s와 전체 지연 ms, 중앙값(범위):

| 조건 | 기준 | 변경 |
|---|---|---|
| 동시성 32 calls/s | 6,124 (5,874–6,130) | 7,002 (6,860–7,113) |
| 동시성 32 p50 / p95 / p99 | 3.7 / 14.5 / 17.8 (17.0–23.0) | 3.0 / 15.7 / 17.9 (17.4–18.2) |
| 동시성 64 calls/s | 5,758 (5,652–5,832) | 6,460 (4,633–6,658) |
| 동시성 64 p50 / p95 / p99 | 7.6 / 21.2 / 29.0 (28.8–37.9) | 6.4 / 21.8 / 30.2 (27.3–48.8) |

p95·p99는 범위가 겹쳐 차이가 없다. 기준도 초당 약 6,000회라 fsync 직렬에 묶이지 않는다. macOS `fsync(2)`는 장치에 넘길 뿐 장치 cache를
비우지 않고(man page, 그 용도는 F_FULLFSYNC), 이 환경의 fsync는 gp3보다 훨씬 싸다. AWS 기준의 상한(fsync 직렬, 약 470
calls/s)과 다른 영역이다.

계측: 임시 계측(커밋하지 않음)을 기준과 변경 양쪽에 넣어 호출마다 start append의 spool 대기(호출부터 응답까지)와 그중 채널 대기,
`record_start` 전체, relay handler 전체를 기록했다. writer에서는 묶음 시간, 묶음 FULL commit, checkpoint 시간을 기록했다. 계측은 처리량을
낮추지 않았다(계측 빌드 동시성 64 7,567 calls/s, 1 run). 아래 수치는 warm-up을 포함한다. 변경, 동시성 64, 기본 설정 1 run(warm-up 3초 + 10초):

- client가 잰 지연 p50 / p90 / p99는 6.1 / 16.7 / 20.3 ms다. handler 시간은 5.2 / 15.1 / 19.0 ms, 그중 spool 대기가 4.3 / 14.1 /
  17.9 ms다. 지연의 거의 전부가 spool writer를 기다린 시간이다. registry lookup·admission·upstream(handler − spool 대기)과 proxy 밖
  (client − handler)은 분위마다 1–2 ms다.
- writer는 run 내내 바빴다. 묶음 시간 합 9.3초와 checkpoint 시간 합 3.5초가 proxied 약 13초를 채운다. 로컬 처리량의 상한은 writer
  thread다.
- 512 명령마다 하는 PASSIVE checkpoint가 writer thread에서 한 번에 약 10 ms(p50) 걸렸다. 그동안 대기열의 모든 append가 기다린다.
  start 채널 대기 p90 11.3 ms가 이 길이와 맞는다. 기준도 같은 주기로 checkpoint를 해서 같은 mode가 있다(기준 동시성 32 p90 13.1–13.7 ms,
  p50 3.7 ms).

비싼 fsync 모사: 계측 빌드에서 환경 변수로 `PRAGMA fullfsync`와 `checkpoint_fullfsync`를 켰다(F_FULLFSYNC, 묶음 FULL commit 약 4 ms).
gp3 fsync(약 2 ms)와 같은 차수지만 gp3의 IOPS·대역 한도는 모사하지 않는다. 동시성 64 1 run씩: 기준 233 calls/s, p50 / p99 273 / 301 ms,
변경 3,683 calls/s, 13.8 / 42.9 ms. 변경이 모든 분위에서 낮아 AWS 꼬리 모양은 여기서도 재현되지 않았다. 로컬에서는 group commit 뒤에도
writer thread가 상한이다. AWS에서는 변경 뒤 gp3 쓰기 I/O가 상한이었다(위 절).

같은 모사에서 변경만 바꿔 쟀다(warm-up 3초 + 15초, 변형을 round마다 차례로 돌려 3 round씩). 동시성 64, 중앙값:

| 변경 동시성 64 | calls/s (범위) | p50 | p90 | p99 |
|---|---|---|---|---|
| 묶음 상한 64(현재) | 3,838 (3,830–3,907) | 12.9 | 33.1 | 39.5 |
| 묶음 상한 1024 | 3,787 (3,768–3,833) | 13.1 | 32.5 | 39.5 |
| checkpoint 끔 | 3,642 (3,220–3,686) | 17.8 | 20.1 | 24.2 |
| 별도 세트: checkpoint 512 명령마다(현재) | 3,987 (3,946–4,001) | 12.8 | 30.6 | 37.9 |
| 별도 세트: checkpoint 128 명령마다 | 2,591 (2,399–2,623) | 23.1 | 32.1 | 43.6 |

- 묶음 상한(늦게 온 start가 묶음 여러 개를 기다린다는 가설, 묶음이 클수록 FULL commit이 길다는 가설): 차이가 없다. 상한 1024에서도 묶음
  길이 p90이 126이라 대기열이 두 묶음을 넘는 일이 드물다.
- checkpoint를 끄면 p90·p99가 준다. 로컬의 p90 위 mode는 writer thread에서 도는 checkpoint 대기다. 끄면 WAL이 run마다 약 5 GB로 커지고
  다음 maintenance checkpoint 하나가 약 0.55초 걸려(최대 지연 576 ms) 쓸 수 있는 설정이 아니다. 128 명령마다로 자주 하면 checkpoint마다
  fsync 2번이 붙어 처리량이 35% 줄고 p99도 커진다.

결론: 로컬에서 꼬리는 spool writer 대기에서 오고, 그중 p90 위 mode는 writer thread의 checkpoint다(측정). AWS p99 557 ms가 같은 원인인지는
측정하지 않았다. 같은 원인이라면 gp3에서 checkpoint 하나가 수백 ms 걸려야 한다. 변경 뒤 볼륨이 3,000 IOPS 한도에 붙어 checkpoint의 DB 쓰기와
fsync가 느려졌다는 설명과 맞지만 추정이다. checkpoint를 다른 연결로 옮겨 writer를 막지 않게 하는 수정은 `durable_seq` 갱신 규칙을 건드리는
작은 변경이 아니라서 AWS 측정 전에는 하지 않았다.

AWS 측정 계획(노드 A, 위 절과 같은 구성과 순서):

- 같은 계측을 넣은 기준·변경 빌드로 closed loop 동시성 32·64를 stack 단위로 교대해 3 round씩 잰다.
- checkpoint 시간 p50이 수백 ms이고 handler 시간의 p95 위가 그만큼 떨어져 있으면 writer thread의 checkpoint가 원인이다.
- 묶음 안 NORMAL commit 시간이 ms 단위로 튀면 writeback 중인 page를 기다리는 쓰기가 원인이다(위 절의 `folio_wait_bit_common`).
- handler 시간이 client 지연보다 크게 작으면 원인은 proxy 밖이다.
- 같은 시간에 `iostat -x 1`(w/s, w_await)과 CloudWatch VolumeWriteOps를 남긴다. collector state를 tmpfs에 둔 대조 run 1개로 collector 쓰기의
  영향을 가른다.

## 2026-11-07 upstream 연결 재사용 (`fix/proxy-upstream-pool`)

아래 loadgen 절의 관찰(macOS closed loop에서 TIME_WAIT가 ephemeral port를 채우고 502 `upstream_unavailable`)을 고쳤다.

원인: `server.rs`의 relay가 호출마다 `connect`로 TCP(https면 TLS도)를 새로 열고 `http1::handshake`를 했다. 응답이 끝나면
`SendRequest`가 버려져 proxy 쪽에서 연결을 닫았고, 닫은 쪽인 proxy의 local port가 TIME_WAIT(macOS MSL 15초, 30초)에 남았다.

수정:

- route마다 idle 연결 pool(`upstream_pool.rs`)을 둔다. pool은 `RouteTable::build_carrying`이 route를 만들 때 새로 만들므로
  config apply(새 revision)마다 비어서 시작한다. 같은 revision의 TTL refresh는 table을 다시 만들지 않으므로 pool이 유지된다.
- 연결은 hyper `SendRequest::ready()`가 끝난 뒤에만 pool에 돌아간다. 응답 body를 끝까지 읽은 뒤다. 끝까지 읽지 않은 응답,
  `Connection: close`, 오류는 연결을 닫고 pool에 넣지 않는다. route마다 idle 연결은 route 동시 호출 한도
  (`max_calls_per_route`, 기본 16) 이하로 두고, 넘으면 가장 오래된 것을 닫는다.
- DNS 해석과 목적지 검사는 지금처럼 호출마다 한다(AC-08). pool에서 꺼내는 연결은 이번 호출의 검사를 통과한 주소로 연결된
  것뿐이다. idle 1초가 지난 연결과 닫힌 연결은 버린다.
- 호출은 한 번만 보낸다(PX-015). pool 연결이 실패해도 새 연결로 다시 보내지 않는다. hyper가 요청을 한 byte도 쓰지 않고
  돌려준 경우(pool 연결이 먼저 닫힘)는 `not_sent`/`connect_failed`, 그 밖의 실패는 지금처럼 `unknown`/`send_failed`다.

pool을 route 단위로 둔 이유: 연결에 묶이는 값(scheme, host, port, TLS server name, 목적지 검사, `allow_private`)은 모두 route가
정한다. upstream TLS client 인증서는 없다. upstream credential, upstream `Mcp-Session-Id`, 나머지 header는 요청마다 넣는다.
HTTP/1.1이라 연결 하나에 동시에 한 요청만 있고, 다음 요청은 이전 응답이 끝난 뒤에만 쓴다. 그래서 같은 route의 principal끼리
연결을 나눠 써도 응답이나 session이 섞이지 않는다.

남은 한계:

- upstream이 idle 연결을 닫는 순간 proxy가 그 연결을 다시 쓰면 502다. 요청이 나갔을 수 있으면 `unknown`으로 남고 성공으로
  기록되지 않는다. idle 1초 상한은 gunicorn 2초, Node `http`와 uvicorn 5초보다 짧게 잡았다(기본값은 공식 문서로 재확인하지 않음).
- 응답이 끝나기 전에 연결이 pool로 돌아가는 경우는 없다(hyper 1.9.0 소스로 확인). `ready()`는 dispatcher가 다음 요청을
  queue에서 꺼내려다 비어 있을 때만 끝나고(`client/dispatch.rs` `Receiver::poll_recv`), dispatcher는 연결의 쓰기 상태가
  `Writing::Init`일 때만 꺼내려 한다(`proto/h1/dispatch.rs` `poll_write`, `proto/h1/conn.rs` `can_write_head`). 첫 요청 뒤
  `Writing::Init`으로 돌아가는 곳은 요청 쓰기와 응답 읽기가 모두 끝난 뒤의 `try_keep_alive`/`idle()`뿐이다.
- 남는 경우는 하나다. upstream이 응답 framing보다 긴 byte를 보내면, idle 상태에서 hyper가 그 byte를 보고 연결을 닫는다
  (`require_empty_read`: 이미 받은 byte는 `ready()` 전에, idle 중 도착한 byte는 `force_io_read`로). 그래서 그 byte가 다른
  호출(다른 principal일 수 있음)에 닿는 것은, 결함 있는 upstream이 proxy가 다음 요청 head를 쓴 뒤에 요청하지 않은 응답을 보낼
  때뿐이고, 그 byte는 다음 요청의 응답으로 읽힌다. upstream은 원래 모든 principal의 data를 다루는 쪽이라 새 권한은 아니다.
- 트래픽이 끊긴 route의 idle 연결은 다음 호출이 올 때까지 닫지 않는다(sweep timer 없음). 수는 위 상한 이하다.
- 세션 DELETE와 `initialize` 거절 뒤 cleanup은 지금처럼 호출마다 새 연결이다.

시험: `tests/relay_pool.rs` 6개. principal 2개가 번갈아 한 순차 호출 40회가 upstream 연결 4개 이하를 쓰고(수정 전 42개,
수정 후 1개) 각 호출이 자기 id의 응답을 받음, client가 읽기를 멈춘 SSE의 upstream 연결은 닫히고 다음 호출은 자기 응답 전체를
받음, route를 다른 upstream으로 바꾼 table 적용 뒤 호출은 새 upstream에만 감, `Connection: close` 응답의 연결은 다시 쓰지 않음,
idle 1초가 지난 연결은 다시 쓰지 않음, DNS 답이 바뀌어 이번 호출의 검사 목록에 없는 주소로의 pool 연결은 쓰지 않음.
`upstream_pool.rs` unit test 1개는 idle 상한을 넘긴 연결을 닫는지 본다. 기존 "재시도 안 함" 시험 2개는 upstream이 받은
호출 수 1만 확인한다(연결 수는 pool 때문에 1 또는 2).

로컬 측정(macOS 26.6.2 arm64, 12 core, release, load average 4.5–7.3, 다른 세션의 cargo test가 같이 돌았음, state는 APFS).
수정 전(`1808577`)과 수정 후 바이너리를 run마다 번갈아 돌렸고 driver는 같은 바이너리다. TIME_WAIT는 1초마다
`netstat -an -p tcp`에서 load server port(18090)의 TIME_WAIT를 센 최댓값이다.

| 조건 | 수정 전 | 수정 후 |
|---|---|---|
| closed loop 동시성 8, 30초, run 3개씩 | 측정 116,101–121,032회 중 502 99,768–104,696회(86%), 성공 16,332–16,336회, TIME_WAIT 최대 16,331–16,336 | 오류 0, 5,559–5,965 calls/s, TIME_WAIT 최대 22–46 |
| closed loop 동시성 32, 30초, run 3개씩 | 측정 124,324–124,960회 중 502 108,013–108,653회(87%), TIME_WAIT 최대 16,303–16,311 | 오류 0, 5,765–5,903 calls/s, TIME_WAIT 최대 47–52 |
| open loop 100 calls/s, 동시성 32, 30초 × 3 round, run 2개씩 | 오류 0, 추가 p50 0.913 / 0.811 ms(round 0.726–0.923), p95 1.56 / 2.50 ms | 오류 0, 추가 p50 0.737 / 0.742 ms(round 0.729–0.752), p95 1.18 / 1.16 ms |

위 수정 후 열은 리뷰 반영(idle 상한 2초 → 1초, 쓰지 않은 요청은 `not_sent`) 전 바이너리다. 반영한 최종 바이너리로 한 번씩
다시 쟀다. closed loop 동시성 8은 오류 0, 5,566 calls/s, TIME_WAIT 최대 33. 동시성 32는 오류 0, 5,534 calls/s, 최대 67.
open loop는 오류 0, 추가 p50 0.748 ms(round 0.727–0.760), 최대 45.

모든 run에서 load server 호출 수 = 성공 응답 수. 수정 전의 성공 수가 run마다 약 16,330인 것은 macOS ephemeral port 범위
(49152–65535, 16,384개)와 맞는다. 포트가 차면 그 뒤 호출은 거의 다 실패한다. 수정 후 closed loop 처리량은 동시성 8과 32에서
같고 p50만 0.90 ms에서 3.7 ms로 늘어, 직렬 구간 하나가 상한이다. 호출마다 하는 start record의 내구 commit으로 추정하며
프로파일하지 않았다. proxy CPU는 run당 약 47초(약 1.3 core)라 CPU 한계는 아니다. open loop 추가 p50 차이 약 0.1 ms는 round
범위가 거의 맞닿아 작은 차이이고, loopback TCP 연결 비용만큼이다. 두 쪽 모두 driver send lag p99가 3–6 ms라 경고가 났다.
loopback이 아닌 upstream과 https upstream의 연결·TLS 비용 절감은 재지 않았다.

## 2026-11-07 성능 측정 도구 (`feat/proxy-loadgen`)

[validation.md](validation.md)가 요구한 synthetic load server와 driver다. Python fixture는 성능 측정에 쓰지 않는다는 조건에 맞춰
Rust crate `crates/lodeline-proxy-loadgen`(publish 안 함, release·패키지 목록에 없음)으로 만들었다. 사용법은
[그 README](../../../crates/lodeline-proxy-loadgen/README.md), validation.md 대응과 차이는 [validation.md](validation.md) "성능 측정 도구" 절.

- `serve`: `load_echo` 도구 하나, 응답을 요청한 크기로 채움, `/_load/counters`로 받은 호출 수 공개.
- `principals`: principal마다 256-bit token(0600 파일)과 SHA-256 verifier. config에는 verifier만 들어가고 control plane의
  `PUT /v1/proxies/{id}/config`로 적용한다. principal `i`는 route `i % R`만 쓴다. principal 하나의 동시 호출 한도 8과
  route 하나의 한도 16 때문에 동시성 C에는 principal C/8개, route C/16개 이상이 필요하다. 기본값 8 × 4는 동시성 32까지,
  64에는 16 × 8을 쓴다.
- `run`: lane 하나가 principal 하나의 MCP session이다. open loop(고정 rate, 동시성 상한)와 closed loop. round마다 direct와
  proxied를 돌리고 짝수 round는 proxied가 먼저다. 응답마다 id와 marker를 확인하고 오류를 종류별로 센다. 성공 응답 수와 load
  server 호출 수를 비교한다. 측정 구간 오류(`--allow-errors`가 없을 때)나 호출 수 불일치가 있으면 0이 아닌 값으로 끝난다.
  timeout은 latency 분포에 경과 시간으로 들어가고, 예정 시각부터 잰 `latency_from_due_ms`를 함께 낸다.
- `stack.sh`: 시험 PKI, local collector `lodeline-server`, proxy, load server를 loopback에 띄운다. `PROXY_WRAP`로 systemd scope.
  pid 파일로 자기가 띄운 프로세스만 멈추고, `up`이 중간에 실패하면 띄운 것을 거둔다.

시험: 단위 21개(scheduler의 open-loop 시각·상한·warm-up·closed loop·lane 수, 분위수, timeout 집계, 예정 시각 기준 latency,
오류 분류, principal 파일, 응답·요청 크기), load server 직접 3개(호출 수, round 순서 교대, 종료 코드), e2e `loadgen_e2e.rs` 1개(실제 relay·spool·server. 동시성 32 open loop 오류 0, 40 worker closed loop는 429만),
긴 run 1개는 `#[ignore]`.

로컬(macOS 26.6.2 arm64, release, 12 core, load average 1.8–2.7, state는 APFS): 100 calls/s, 동시성 32, warm-up 5초 + 30초 × 3 round.
오류 0, load server 호출 수 = 성공 응답 수. direct p50 0.26 ms, 추가 p50 0.94 ms(0.935–0.945), p95 1.48 ms(1.31–1.56),
p99 4.41 ms(4.12–4.92). driver timer 지연(`send_lag_ms`)은 macOS에서 p50 약 2.5 ms라 latency 시작점을 task 실행 시각으로 했다.
principal 하나에 closed loop 동시성 16을 걸면 429 `too_many_requests` 132,057회와 성공 9,297회로 셌다(upstream 9,297).

관찰(macOS): closed loop 고속 run에서 proxy는 호출마다 upstream 연결을 새로 연다. 약 2초 만에 load server 쪽 TIME_WAIT가 16,332개로
macOS ephemeral port 범위(16,384)를 채웠고, 그 뒤 호출은 502 `upstream_unavailable`이었다(동시성 8, 8초, 35,708회 중 19,400회).
Linux loopback은 `tcp_tw_reuse` 기본값 2로 TIME_WAIT를 재사용하므로 아래 AWS run에서는 나지 않았다. loopback이 아닌 upstream에서
같은 상한이 걸리는지는 측정하지 않았다. 이 문제는 `fix/proxy-upstream-pool`(위 절)에서 고쳤다.

AWS(노드 A만, t4g.small 2 vCPU, AL2023 aarch64, kernel 6.18.54, Neoverse-N1, gp3 xfs, rustc 1.99.1, `cb55a10`): server, proxy,
load server, driver를 A 한 대에. proxy는 `systemd-run --scope`(MemoryMax 512M, MemorySwapMax 0, AllowedCPUs 0), 나머지는 `taskset -c 1`.
validation.md의 목표 환경(Rocky 9, 4 vCPU x86_64, proxy 2 vCPU)이 아니다. 아래 수치는 이 환경의 baseline이고 목표 판정이 아니다.
위 로컬 run과 아래 AWS run은 이 절의 수정 전 도구로 쟀다. round마다 direct가 늘 먼저였고, `latency_from_due_ms`가 없었다.
두 run 모두 timeout을 포함한 오류가 0이라 timeout 집계 변경의 영향은 없다. 예정 시각 기준 추가 지연과 순서 교대 결과는 다시 재야 한다.

| 조건 | 결과 |
|---|---|
| 100 calls/s, 동시성 32, warm-up 30초 + 300초 × 3 round, state gp3 | 측정 호출 180,000회 오류 0, round마다 load server 33,000회 = 성공 응답 33,000회. direct p50 0.27 ms |
| 같은 run, 추가 지연 round 중앙값(범위) | p50 3.33 ms (3.328–3.332), p95 7.93 ms (7.36–8.05), p99 20.8 ms (15.8–22.9), max 71.6 ms (58.2–80.1) |
| state tmpfs 대조, 60초 × 2 round | 추가 p50 0.77 ms (0.763–0.777), p95 3.5 ms (2.5–4.5), p99 9.9 ms (9.5–10.3), 오류 0 |
| closed loop 30초, gp3, 동시성 1 / 8 / 32 / 64 | proxied 281 / 313 / 378 / 416 calls/s, p50 2.5 / 16.9 / 62.3 / 129 ms, 오류 0 |
| closed loop 30초, tmpfs, 동시성 32 | proxied 2,049 calls/s, p50 15.2 ms, 오류 0 |
| proxy 자원(gp3 run 전체 뒤) | VmHWM 16 MiB, cgroup memory.peak 238 MB(spool page cache 포함), FD 17 |

한계 요인: gp3의 추가 p50 3.33 ms 중 tmpfs와의 차이 약 2.56 ms가 저장장치다. 2026-11-06 측정의 격리 start fsync 2.2 ms와 맞는다.
gp3 closed loop 처리량 약 400 calls/s도 같은 날 측정한 start fsync 직렬 상한(약 400)과 같다. tmpfs 2,049 calls/s의 상한은 proxy가
쓰는 CPU 0 한 개로 추정한다(측정 안 함). driver와 load server는 CPU 1 하나로 direct 9,200–10,700 calls/s를 냈으므로 proxied run의
상한이 아니다. 추가 p99와 max의 원인은 이번에 밝히지 않았다.

미검증: 목표 VM(Rocky 9, x86_64, SELinux Enforcing), proxy 2 vCPU, validation.md 3·4단계, TLS listener, loopback이 아닌
upstream의 연결 재사용, Linux에서 ignored 긴 e2e.
노드는 A만 14:52–15:49 UTC에 켰다(약 0.95 노드시간, 약 $0.03). 끝난 뒤 A·B 모두 stopped를 확인했다.

## 2026-11-06 지속 부하에서 감사 writer queue가 차서 나던 503 수정 (`fix/proxy-writer-queue`)

증상: 동시 호출을 오래 걸면 정상 호출이 503 `audit_unavailable`로 거절됐다. 로컬에서 relay를 지나는 8 client × 400 `ping`은 3,200회 중 1,295–1,330회,
AWS gp3에서 동시성 8 `tools/call`은 3,200회 중 1,239–1,510회였다. [validation.md](validation.md)는 정상 부하에서 거절 0을 요구한다.

client 요청에서 spool까지의 경로:

1. relay는 upstream에 닿기 전에 `request_started`를 기다리고, 거절이면 503 `audit_unavailable`로 답한다(`server.rs`).
2. `record_start`(`invocation_sink.rs`)는 기다리지 않고 바로 거절한다: 종료 중, writer queue가 가득 참(`tx.capacity() == 0`, `QUEUE_DEPTH` 1024),
   진행 중 호출 4,096개(`MAX_INFLIGHT`), 같은 호출 번호.
3. `tools/call`만 registry 조회를 한다. slot 4개를 `LOOKUP_TIMEOUT`(2초) 안에서 기다린다(`fix/proxy-lookup-503`).
4. start는 자기 task에서 spool에 append하고 commit과 fsync를 기다린다. spool 명령 channel은 상한이 없고, spool writer thread 하나가 FIFO 순서로
   명령마다 transaction 하나를 commit한다. spool이 거절하는 것은 가득 참(`Full`)과 저장 불가(`Unavailable`)뿐이다.
5. cancel, completion, 거절 쌍은 relay가 기다리지 않는 bounded queue(1024)에 들어가고, 넘치면 `local_record_failed` gap으로 센다.
   writer task 하나가 이를 spool에 append한다.

원인: 5의 writer task는 기록 하나를 append하고 그 응답을 받은 뒤에야 다음 기록을 꺼냈다. start는 호출마다 자기 task에서 같은 spool FIFO에
들어가므로, completion 하나는 앞에 줄 선 start를 모두 기다렸다. 로컬 e2e에 임시 계측을 넣어 확인했다. completion 두 개 사이에 spool이 commit한
start는 0–8개(대부분 3–6개)였고, writer queue는 completion 40개마다 0, 175, 384, 565, 751, 937, 1024로 늘어난 뒤 가득 찬 채로 남았다.
거절은 모두 2의 `tx.capacity() == 0`에서 나왔다(`ping` 3회 1,295–1,330회 전부, `tools/call` 1회 1,173회 전부). `ping`은 조회를 하지 않으므로
조회 slot 문제가 아니다. queue가 찬 동안 들어온 completion은 버려져 `local_record_failed`가 됐다. gp3에서는 start fsync가 약 2 ms라
completion 하나가 기다리는 시간이 길어 더 빨리 찬다. 위 `perf/proxy-spool-sync` 절의 동시성 8 503도 이것이다.

수정: writer task는 queue에 쌓인 job을 모두 꺼내(`recv_many`) 그 event를 모두 spool에 보낸 뒤에 응답을 기다린다. spool 왕복 한 번에 backlog
전체를 넘긴다. `Spool::append_async`와 `Admission::append`는 처음 poll할 때가 아니라 호출하는 순간 명령을 보내므로 event 순서는 queue 순서
그대로다. 거절 쌍은 전처럼 start가 저장된 뒤에만 completion을 append한다. `Stop` 뒤에 들어온 job은 버리지 않고 함께 쓴다.
바꾸지 않은 것: queue 상한과 `tx.capacity() == 0` 거절(이제 spool이 실제로 뒤처질 때만 난다), start fsync 뒤 전달, completion·cancel·ACK의
NORMAL commit, `durable_seq`와 넘김 규칙. group commit(start 여러 개를 fsync 하나로)은 이 503의 원인이 아니어서 넣지 않았다. spool만 group
commit하면 writer는 여전히 왕복마다 completion 하나만 넘기므로 queue가 같은 방식으로 찬다(모델 추론, 시험하지 않음). 아래 AWS 수치처럼
지금 처리량 상한은 start fsync 직렬이라 group commit은 별도 성능 작업 후보다.

status `last_assigned_sequence`(#498 리뷰 후속): 바꾸지 않았다. 서버는 tail gap을 `last_assigned_sequence − spool.unsent_events`까지만 연다
([ledger-and-query.md](contracts/ledger-and-query.md), 2026-10-21 결정). durable하지 않은 행은 넘기지 않으므로 늘 `unsent_events`에도 들어 있고,
tail 끝은 전원 손실 뒤에도 남는 sequence만 가리킨다. `min(last_seq, durable_seq)`만 보고하면 tail을 durable하지 않은 행 수만큼 덜 보고한다.
[decisions.md](decisions.md) 문구를 이에 맞게 고쳤다.

시험: `sustained_concurrent_calls_are_neither_refused_nor_lost`(sink 단위, 16 × 400 `ping`, 거절 0·손실 0·gap 없음·event 12,800개. 수정 전
6,400회 중 5,246회 거절, 3/3회), e2e `sustained_concurrent_calls_are_not_refused`(relay 경유 8 × 400 `ping`과 `tools/call`. 수정 전 `ping`
1,295–1,330회 거절, 3/3회), `the_tail_a_status_names_survives_a_power_loss`. `only_a_start_commit_fsyncs`,
`power_loss_never_reissues_a_handed_out_sequence` 등 #498 시험은 그대로 통과한다. mutation 7개 중 5개가 실패했다. 살아남은 둘(거절 쌍에서 start
실패 뒤 completion append, 종료로 포기한 writer의 submit)은 이 PR이 옮기기만 한 분기이고 main에도 시험이 없다(추론, main에서 돌리지 않음).

AWS 측정(노드 A, t4g.small, AL2023 aarch64, gp3 xfs, 기준 `db9e804`과 브랜치 바이너리를 같은 노드에서, 운영자의 로컬 harness, Python client가
호출마다 새 연결, proxy 하나에 principal 하나):

| 조건 | 기준 `db9e804` | 변경 |
|---|---|---|
| gp3, 동시성 8 × 400 `tools/call`, 기준과 변경을 단독으로 3회 교대, 503 | 3,200회 중 1,354–1,510 | 0 |
| 같은 run, 성공 호출 p50 / p99 | 13.7–14.1 / 41.5–51.4 ms | 16.8–17.3 / 52.5–54.1 ms |
| 같은 run, 저장된 호출/s | 369–408 | 385–405 |
| proxy 4개(gp3·tmpfs × 기준·변경) 교대, `tools/call` 3 round, 503 | gp3 1,239–1,389, tmpfs 0 | gp3 0, tmpfs 0 |
| 같은 방식 `ping` 2 round, 503 | gp3 1,374–1,685, tmpfs 0 | gp3 0, tmpfs 0 |
| 동시성 8, 약 100 calls/s, 300초(30,000회), 1회 | 거절 0, p50 5.26, p99 25.5 ms | 거절 0, p50 5.31, p99 28.3 ms |
| 동시성 1, 200회 × 5 교대, 추가 p50 중앙값(범위) | 2.97 ms (2.28–3.22) | 3.03 ms (1.82–3.42) |
| strace, 동시성 8 × 400: WAL fsync / 저장된 start | 1,678 / 1,649 | 3,244 / 3,200 |

변경 쪽 처리량 상한은 spool writer의 start fsync 직렬이다. 저장된 호출은 두 쪽 모두 초당 약 400회로, 격리 FULL commit 2.05 ms에 맞고,
strace의 fsync 중앙값은 2.12 ms였다. 그동안 CPU는 80% idle, IO pressure full은 약 10%였다. 기준은 같은 속도로 저장하고 나머지를 503으로
빨리 돌려보내므로 성공 호출의 p50이 낮다. 약 100 calls/s에서는 기준도 거절하지 않았다. queue는 부하가 start fsync 처리량에 가까울 때만 찬다.
proxy 4개를 한 round에 차례로 돌린 run에서는 뒤 round로 갈수록 두 쪽 모두 느려졌다(변경 `tools/call` 388 → 211 → 141 calls/s). 단독 교대
run에서는 재현되지 않았다(385–405 calls/s). 앞 proxy가 남긴 서버 수집 작업이 같은 디스크를 쓴 탓으로 추정하며 확인하지 않았다.
동시성 32 run(약 100 calls/s)은 무효다. principal 하나의 동시 호출 한도 8 때문에 429가 나고(기준 2, 변경 5), session 시작에서 429를 받은
client는 끝나 버려 호출의 약 절반만 돌았다. 그 run의 503은 두 쪽 모두 0이었다.
노드는 11:26–12:18 UTC에 켜졌고(약 1.7 노드시간, 약 $0.04), 끝난 뒤 둘 다 stopped를 확인했다.

미검증: 동시성 32(principal 하나의 동시 호출 한도 8 때문에 이 harness로는 만들 수 없다), Rocky 9·목표 VM, Linux에서 e2e 반복, 실제 전원 차단.

## 2026-11-06 spool 기록별 내구성 (`perf/proxy-spool-sync`)

사용자 결정(안 3, [decisions.md](decisions.md) "spool 기록별 내구성")의 구현이다. `invocation.started`만 `synchronous=FULL`로 commit하고,
completion·cancel_requested·수집 ACK 표시는 같은 writer 연결에서 그 transaction만 `synchronous=NORMAL`로 commit한다(`spool.rs` `Writer::deferred`).
writer는 fsync로 덮인 가장 높은 sequence(`durable_seq`)를 기억한다. start commit이 끝나거나 checkpoint가 WAL을 모두 옮기면 올라간다.
수집 client에는 `sequence <= durable_seq`인 행만 넘기고, 그런 행이 없는데 덮이지 않은 행이 있으면 먼저 checkpoint한다.
`wal_autocheckpoint=0`이고 checkpoint는 명령 사이에서만 돈다: maintenance pass, 위의 poll, 512 명령마다(응답 뒤).

시험(`spool.rs` tests, 시험 전용 VFS `sync_vfs.rs`가 파일별 `xSync`를 세고 마지막 `xSync` 때의 파일 내용을 보관해 전원 손실을 모사한다):
`only_a_start_commit_fsyncs`, `power_loss_never_reissues_a_handed_out_sequence`(process crash 사본은 모두 유지, 전원 손실 사본은 start만 남고 sequence 2를 다시 배정하지만 넘긴 행은 모두 같은 sequence로 남음, idle poll이 checkpoint 뒤 나머지를 넘김),
`rows_wait_while_a_reader_stops_the_checkpoint_short`, `checkpoints_bound_the_wal`, `maintenance_checkpoints`. mutation 11개 중 10개가 실패했다.
살아남은 하나는 open 직후 `durable_seq`를 0 대신 최댓값으로 두는 것이다. 시작 때 maintenance pass가 첫 명령 전에 checkpoint하므로 다른 연결의 reader가 그 checkpoint를 막지 않는 한 동작이 같다.

AWS 측정(노드 A, t4g.small, gp3 xfs, `6632638` 기준 바이너리와 브랜치 `9d1bd54` 바이너리를 같은 노드에서, 운영자의 로컬 harness, state를 gp3와 tmpfs에 둔 proxy 4개, 호출마다 새 연결, 오류 0):

| 조건 | 기준 | 변경 |
|---|---|---|
| 동시성 1, 200회 × 5 교대, 추가 p50 중앙값(범위) | 3.44 ms (3.24–3.86) | 2.95 ms (2.67–3.50) |
| 같은 조건 p99 중앙값(범위) | 10.36 ms (9.70–12.98) | 10.72 ms (8.17–12.04) |
| 동시성 1, 1000회 × 5 교대, 추가 p50 | 3.54 ms (3.46–3.56) | 3.23 ms (3.08–3.39) |
| tmpfs 대조, 추가 p50(200회) | 0.62 ms | 0.64 ms |
| strace, 동시성 1, 1000회: WAL fsync/호출, `spool.db` fsync | 2.07, 16 | 1.01, 5 |
| strace, 동시성 8, 800회: WAL fsync/호출 | 2.04 | 1.03 |

run마다 변경 쪽 p50이 낮았다(200회 5/5, 0.36–0.77 ms. 1000회 5/5, 0.15–0.48 ms). tmpfs 쪽 차이는 −0.10–0.35 ms로 차이가 없다. 남은 추가 시간은 start fsync 하나(앞에 fsync가 없을 때 p50 2.42 ms)와 proxy 자체 약 0.6 ms다.
p99는 200회에서 차이가 없고, 1000회에서는 기준 42.0 ms(17.4–42.2), 변경 24.0 ms(23.6–25.5)다. 꼬리의 원인은 밝히지 못했다. strace를 걸면 호출이 7–8 ms로 느려져 귀속이 안 됐고, tmpfs 쪽 p99도 4.7–16.3 ms라 저장장치 밖의 잡음도 섞인다.

동시성 8(8 × 200, 5회)은 **결론 없음**이다. 두 바이너리 모두 gp3 쪽에서만 503 `audit_unavailable`이 났다. `tools/call` 기준 8000회 중 1609회, 변경 1221회. `ping`도 기준 1587회, 변경 877회이고 tmpfs 쪽은 `ping` 0회다.
`ping`은 registry 조회를 하지 않으므로 이 503은 조회 slot 한도가 아니다. 아래 `fix/proxy-lookup-503` 절이 계측한 writer queue 가득 참(`tx.capacity() == 0`)과 맞는다(추정, 이 run에서 계측하지 않음): completion을 writer task 하나가 차례로 append하므로, start fsync가 느린 gp3에서 지속 부하가 걸리면 queue가 먼저 찬다. proxy log의 "could not be stored locally" 경고는 기준 328, 변경 190회였다. 진단 때(8 × 100, proxy 2개)는 gp3 쪽 0회였다.
노드는 10:23–10:48 UTC에 켜졌고(약 0.8 노드시간, 약 $0.02) 끝난 뒤 둘 다 stopped를 확인했다.

미검증: 실제 전원 차단(모사만 함), Rocky 9·목표 VM, macOS의 `F_FULLFSYNC`, group commit(별도 PR).

## 2026-11-06 registry lookup 슬롯 부족으로 인한 503 수정 (`fix/proxy-lookup-503`)

증상(AWS node A, AL2023 aarch64, `3500adb`, state를 tmpfs에 둔 proxy): 동시성 8에서 `tools/call` 800회마다 4–13회가 503 `audit_unavailable`이었다. 같은 조건의 `ping` 1,600회와 state를 gp3에 둔 proxy는 0회였다. [validation.md](validation.md)는 정상 부하에서 거절 0을 요구한다.

원인: `invocation_sink.rs`의 registry lookup은 blocking pool 슬롯 4개(`LOOKUP_CONCURRENCY`)를 `try_acquire_owned`로 기다리지 않고 잡았고, 슬롯이 없으면 lookup 실패(`None`)로 처리해 start를 거절했다. registry 읽기는 하나의 mutex 아래에서 직렬로 돌기 때문에, 정상 registry에서도 5번째 이후의 겹친 lookup이 바로 거절됐다. gp3에서는 start가 fsync 뒤에 줄을 서서 겹침이 드물었다. 로컬 재현: 기존 코드에서 relay를 지나는 8 client × 100 `tools/call` e2e가 20회 중 5회 실패(503 1회 4번, 16회 1번)했고, 임시 계측에서 그 503은 슬롯 획득 실패에서 나왔다.

슬롯 상한이 지키던 것(T-13d producer 리뷰 F2, "lookup timeout 잔존 작업 상한"): timeout으로 포기한 lookup도 blocking 읽기가 끝날 때까지 슬롯을 쥐므로, 멈춘 registry가 잡는 blocking thread는 4개 이하다. 또 멈춘 registry에서는 client 재시도와 writer의 refusal 기록 경로가 기다리지 않고 바로 실패한다(writer task가 2초씩 멈추지 않음).

수정: lookup은 이제 자기 `LOOKUP_TIMEOUT`(2초) 안에서 슬롯을 기다린다(deadline은 슬롯 대기와 읽기를 합친 시간). 슬롯은 semaphore 대신 `LookupSlots`(빈 슬롯 수와 "슬롯을 잡은 lookup 중 가장 늦은 deadline"을 한 lock 아래에 둠, 해제 시 `Notify`로 대기자를 깨움)로 관리한다. 바로 실패하는 경우는 빈 슬롯이 없고 그 가장 늦은 deadline도 지났을 때, 즉 모든 슬롯이 자기 deadline을 넘긴 읽기에 잡혀 있을 때(registry가 멈춤)뿐이다. 슬롯 획득과 deadline 기록, 멈춤 판정이 같은 lock 안에서 일어나므로, 다른 lookup이 슬롯을 잡았지만 아직 시각을 기록하지 않은 틈에 판정해 정상 registry에서 503을 내는 경합(독립 리뷰 지적, 첫 수정의 `acquire_owned` 뒤 timestamp 방식)이 구조상 없다. blocking thread 상한 4는 그대로다. writer 동작: 멈춘 registry에서 슬롯이 찬 뒤 처음 최대 2초 동안은 즉시 실패가 아니므로 writer는 멈춘 구간마다 한 번 최대 2초를 기다릴 수 있고, 바쁜 정상 registry에서는 refusal 기록을 버리던 자리에서 최대 2초를 기다린다. writer의 refusal 기록 lookup도 같은 함수를 쓰므로, 겹침 때문에 refusal 기록이 `local_record_failed`로 잃어지던 경로도 같이 고쳐졌다(이 경로는 따로 측정하지 않음).

테스트: `lookups_beyond_the_slots_wait_for_a_busy_registry_and_proceed`(registry lock을 모든 슬롯이 찰 때까지만 잡음, 수정 전 `Refuse`), `a_lookup_arriving_as_a_slot_frees_waits_instead_of_failing_fast`(위 경합을 결정적으로 재현, 첫 수정에서 `Refuse`), e2e `concurrent_tool_calls_on_a_healthy_registry_are_not_refused`(8 × 100, AWS와 같은 모양), 기존 `a_stuck_registry_holds_a_bounded_number_of_lookups`는 슬롯 수 읽는 방법만 바꾸고 통과. mutation 8개는 PR 본문에 기록했다.

새로 찾은 별도 문제(이 PR에서 고치지 않음): 같은 e2e를 8 × 400으로 돌리면 3,200회 중 약 1,100회가 503이고, 계측상 원인은 lookup이 아니라 writer queue 가득 참(`tx.capacity() == 0`, `QUEUE_DEPTH` 1024)이다. 추정: start는 8개가 동시에 spool에 commit되지만 completion은 writer task 하나가 한 번에 하나씩 append하므로, 빠른 storage에서 지속 부하가 걸리면 queue가 쌓인다. 800회 이하 묶음에서는 1024에 닿지 않아 AWS run에서는 보이지 않았다. 이슈 등록과 수정 방향(group commit 등)은 orchestrator 판단으로 남긴다.

미측정: AWS 재확인, 동시성 32, Linux에서의 e2e 반복.

## 2026-11-06 AWS 실기 run I (상태 유지, 변형, 패키지)

`3500adb`(main, #495)에서 운영자가 로컬 harness로 같은 2노드 환경(t4g.small 2대, AL2023 aarch64, 커널 6.18.54, systemd 252)을 다시 띄워 세 단계를 실행했다. 시험서는 [aws-smoke-test.md §19](aws-smoke-test.md#19-aws-run-i-2026-11-06-utc)다. 빌드는 A에서 `cargo build --release --locked -p lodeline-server -p lodeline-proxy`(증분 193초, `lodeline-proxy 0.13.0`, rustc 1.99.1)다. 1·2단계는 SELinux Permissive(이전 실행과 같음), 3단계는 A만 Enforcing으로 돌렸고 끝나고 Permissive로 되돌렸다.

| 단계 | 구성 | 결과 |
|---|---|---|
| 1 상태 유지 §4–§13 | B의 proxy, D1 | 모두 통과. 10-25 H와 10-31 재시험과 숫자가 같다. 시나리오 27/27, ledger 22 completed·중복 0·canary와 도구 이름 0, drift added→removed(member_count 5, 6, 5), fixture `smoke_echo` 1·`deletes` 2·`cancels_matched` 1, privacy B 15·A 12 파일 0건(대조군 FOUND), offline replay 6(중복 0), 서버 없이 재시작 `Expired`·`forwarding: false`·401 → 복구 뒤 `Valid`·200, spool 32×200/48×503(upstream delta 32 일치)과 경계 호출 1건 `started`, disable 401 → enable 200, 관리 감사 seq 0–4 ok |
| 2 fixture 변형 §9–§10 (AWS 첫 실행) | B의 proxy, D1. 변형마다 fixture와 proxy를 재시작 | `--stateless`, `--initialize-sse`, 둘 다 모두 시나리오 27/27, ledger 22(표 동일), privacy B 15·A 12 파일 0건. fixture `deletes`는 stateless 0(proxy가 DELETE에 직접 응답), initialize-sse 2, 둘 다 0. `cancels_matched`는 모두 1. 둘 다 변형은 §17 로컬 리허설과 같다 |
| 3 패키지 + systemd | A 한 대, RPM(`packaging/build.sh proxy rpm`, 110초), A의 loopback fixture, Enforcing | 모두 통과, AVC 0건. 설치 직후 `disabled`·`inactive`, 라이브 `proxy.yaml` 없음, 8480 listen 없음. 시작 후 `Valid`·`forwarding: true`, NRestarts 0, 프로세스 context `unconfined_service_t`, state dir 0700. §9 27/27, ledger 22, privacy 16 파일(state dir, journal, `proxy.yaml`) 0건, offline replay 6, `systemctl restart`를 서버 없이 해도 유닛이 active로 남고(crash loop 없음) 401 → 복구 뒤 200, spool 32/48·delta 32, disable/enable, 감사 seq 5–9 ok. `systemctl stop` 0.04초, `outcome=Drained`, Result=success |

AVC는 Enforcing 구간(05:57:39–06:02:29 UTC)과 당일 전체에서 `ausearch -m avc,user_avc` 0건이다. 같은 구간에 `lodeline-proxy`의 SERVICE_START 4건이 잡혀 검색이 동작함을 확인했다. 처음 AVC 단계는 날짜 형식 오류로 실패해 시각만 쓰도록 harness를 고친 뒤 다시 조회했다.

관찰값(validation.md의 성능 조건이 아님, 패키지 proxy, release 빌드, 기본 한도). RSS 9.2 MiB(§9–§13 뒤) → 12.1 MiB(호출 2,000회 뒤), fd 17, 스레드 7로 뒤에도 같다. soak이 아니다. 순차 호출(동시성 1, 요청마다 새 연결) 200회를 5번 교대로 쟀고 전부 200이다. 직접 1.5–1.6 ms/호출, proxy 경유 5.0–5.8 ms(중앙값 5.2), 추가 약 3.6 ms다. 지연의 원인은 **프로파일하지 않았다.** proxy CPU는 약 1.04초 실행당 약 0.29초라 CPU 한계는 아니다. 같은 gp3 볼륨의 600 byte write+fsync 중앙값이 1.99 ms라서, 호출마다 하는 fsync가 추가 시간의 큰 몫일 것으로 추정한다. 프로파일이나 spool을 tmpfs에 두는 비교로 확인하기 전에는 추정이다.

성능 목표(100 calls/s 동시성 32의 p50/p95/p99, 32×60초 SSE, 1·8 MiB 경계 부하, 65-call 포화)는 측정하지 않았다. 고정 환경(Rocky 9, 4 vCPU/8 GiB, proxy cgroup 2 vCPU/512 MiB)을 t4g.small(2 vCPU/2 GiB 전체)이 만족하지 못하고, 별도 부하 서버·driver가 필요한데 validation.md가 Python smoke fixture를 성능 서버로 쓰지 못하게 하며 저장소에 load driver도 없다.

이번에 다시 읽지 않은 것: harness가 proxy-detail의 gap 목록을 출력하지 않아 `local_record_failed`와 `central_outage` gap은 확인하지 못했다(`started` 경계 호출은 확인함).

시험이 끝난 뒤 패키지, 유닛, listen, 파일 목록이 두 노드 모두 실행 전과 같음을 확인하고 노드를 중지했다.

미측정: vendor client(R, 별도로 승인된 compatibility probe 필요), D2 공개 HTTPS(공개 DNS 이름, 해당 이름의 인증서, 고정 IP, 방화벽 규칙 필요), x86_64, 성능 목표(load driver와 4 vCPU/8 GiB Rocky 9 호스트 필요), 제한된 proxy SELinux 도메인(존재하지 않음), 호스트 사이 패키지 경로, Rocky 9.

## 2026-10-29–31 spool hardening·실기 재시험

| PR | 작업 | 이슈 |
|---|---|---|
| #334 | agent spool GC가 sender의 실제 offset(경로·필드)을 읽도록 수정, 같은 날 rotation 세그먼트를 (날짜, seq) 순으로 정렬(sender 미전송 버그 포함) | #331 |
| #336 | spool·registry DB를 Unix에서 `SQLITE_OPEN_NOFOLLOW`로 열기(state dir은 canonicalize). Windows는 대응 수단이 없으나 support-matrix.md상 미지원이라 조치하지 않음 | #302 |
| #337 | `lodeline-proxy.service`에 `After=time-sync.target`. 대기 서비스는 chrony-wait(180초 상한)를 권장하고 systemd-time-wait-sync(timeout 없음)는 시계 없는 호스트에서 쓰지 않는다. AL2023(systemd 252, chrony 4.3)에서 확인 | #302 |
| #342 | quarantine 행을 `quarantined_at`이 Q(= 서버가 내려준 E, `event_retention_seconds`)보다 오래되면 maintenance pass에서 삭제(모든 code, `registry_conflict_original` 포함). E를 받기 전에는 삭제하지 않음. 결정 1 | #302 |
| #360 | by-index 422도 `MAX_CONSECUTIVE_SINGLE_QUARANTINES`(응답 8개, event 8개가 아님)에 응답 단위로 세고 count를 지우지 않는다. 200만 지운다. 409 by item과 424는 세지도 지우지도 않는다. 한도를 넘으면 stopped 상태로 backoff하고, status에 `central.ingest_stopped: true`와 `spool.state: degraded`를 보고하며, max backoff 주기(기본 300초)마다 event 1개만 quarantine해 뒤의 정상 event가 재개된다. 업그레이드 후 대기는 최대 360초(300초 + jitter 20%) | #339 |
| #356 | spool `events(acked_at) WHERE state = 1` 부분 인덱스 `idx_acked_at`을 추가하고 ack purge를 `acked_at` 순으로 바꿔 maintenance pass의 전체 scan 제거(기존 DB는 open 시 추가, `SCHEMA_VERSION` 유지). 1M unsent + 1M quarantined 600 byte에서 pass 120 ms → 18 ms(release, macOS). 남은 시간은 `oldest_unsent` | #345 |
| #387 | `oldest_unsent`가 ack batch마다 `idx_unsent_created`를 정렬하던 것을 `INDEXED BY idx_unsent`로 고쳐 순서대로 한 행만 읽게 함. plan 테스트 추가. 1M unsent(600 byte)에서 중앙값 21.5 ms → 0.002 ms(SQLite 3.45.0 bundled, opt-level 2 test build, 30회) | #359 |
| #387 | spool status의 `Full`과 admission 거절이 하나의 규칙 `admits(unsent, size, limit)`을 쓰도록 통일. status는 `event_max_bytes` 크기의 event가 들어가지 않으면 `Full`이고, 그보다 작은 event는 `Full` 중에도 들어갈 수 있다. `Ok`이면 허용된 모든 event가 들어간다 | #362 |
| #387 | stopped 상태에서 이름 없는 409/422 응답이 backoff를 지워 5초에 요청 2개가 나가던 것을 수정. 여러 event batch의 이름 없는 응답은 stopped이면 progress가 아니고, stopped의 느린 quarantine도 progress가 아니다. 이제 stopped는 max backoff(300초, jitter 20%)당 요청 1개이고 손실은 주기당 event 1개 이하. paused clock 테스트: 4500초 구간 요청 1750 → 11–19 | #363 |
| #389 | stopped 요청 간격 테스트가 가끔 실패하던 것(run 41317778315)을 수정. 원인은 테스트다: `jitter`의 하한은 정수 permille 800이라 300초 주기에서 정확히 240초 지연이 나올 수 있는데, 테스트는 `mul_f32(0.8)`(240.0000036초)과 비교했다. 하한을 `period * 4 / 5`로 바꿨고 제품 코드와 수치는 그대로. 수정 전 paused clock 2000회 중 60회 실패(회당 3.0%), 수정 후 24000회 실패 0 | #387 |
| #420 | `MAX_CONSECUTIVE_SINGLE_QUARANTINES` count를 `gap_queue.json`의 `single_quarantines`에 영속화. 응답이 event를 옮기기 전에 쓰고(crash 시 과대 계산만 가능), 200의 reset도 기록한다. 한도에서 재시작하면 바로 stopped이고 다음 느린 quarantine까지 max backoff 전체를 기다리므로 crash loop에서 추가 손실이 없다. 읽을 수 없는 `gap_queue.json`은 기존대로 시작 거부. 복구는 server 수정·업그레이드 후 다음 200. 재시작 단위 테스트 2개(수정 전 8 대신 12 quarantine) | #361 |
| `fix/proxy-registry-retention` | registry `entries` 보존(README "D-05 metadata registry (N9)" Retention 행). 60초마다 도는 retention pass가 ACK된 entry 중 snapshot과 대기 report가 부르지 않는 것을 표시하고 그때의 spool `last_assigned_sequence`를 기억한다. 다음 pass에서 spool에 그 sequence 이하의 행(unsent, 보존 중인 acked, quarantine)이 없으면 지운다. 두 pass 사이에 snapshot에 다시 나온 entry는 표시를 버리고 다음 pass에서 다시 표시한다(그사이 start가 그 entry로 조회되었을 수 있음). 서버 보존 기간 E는 확인하지 않는다(README Retention 행도 E를 조건으로 두지 않음). ACK되고 snapshot·대기 report·spool 행 어느 것도 부르지 않는 entry는 E를 받기 전에도 지운다. E는 quarantine 행을 통해서만 영향을 준다. quarantine 행은 Q = E가 지나야 사라지므로, E를 받기 전에는 quarantine 행이 부를 수 있는 entry만 남는다. 표시는 메모리에만 있고 재시작하면 더 높은 sequence로 다시 표시한다(더 오래 보존할 뿐). 표시 직전에 조회한 start가 표시 뒤에 append되면 지운 entry를 부를 수 있으며, 이때는 README "Not-yet-synced refs"대로 그대로 보내고 서버가 판정한다(서버는 ACK한 entry를 보존). 같은 정의가 다시 목록에 나오면 새로 저장하고 다시 올린다. 수정 전 실패 테스트 3개 | #307 |
| `fix/proxy-registry-retention` | inventory report backlog 상한. 대기 complete report는 256개(서버 `pending_previous` 한도와 같은 P1 시험값)까지 두고, 넘으면 scope key의 최신 snapshot이 아닌 가장 오래된 report를 거절된 report와 같은 경로로 버린다(chain의 다음 report는 `initial_baseline`이 되고 서버는 `baseline_restated`로 본다). 최신 snapshot의 report는 버리지 않으므로 상한은 256 + scope key 수다. 이 경우와 incomplete 64개 상한에서 버린 report를 status `registry.discarded_reports`에 센다(새 필드 없음, [decisions.md](decisions.md) 2026-11-03). report 하나를 버리는 일(report 삭제, snapshot 정리, 다음 report 재작성)은 transaction 하나다. client가 report를 읽어 보내고 정리하는 동안에는 listing의 상한 정리를 건너뛰고 다음 listing에서 한다(보내는 중인 report를 버리거나 그 다음 report를 바꾸지 않음). 수정 전 실패 테스트 2개(259개 보관, 0개 계산; 전송 중 정리로 1개 버림) | #307 |

- clock-jump guard는 시도 후 리뷰에서 되돌렸다(suspend가 jump로 계산되어 R 이후 재전송 위험). 대신 결정 4로 boot-clock age를 구현했다: 행마다 `(boot_id, boot clock)` stamp를 side table에 두고 같은 boot 안에서는 boot clock, boot가 다르거나 stamp가 없으면 wall clock으로 R·Q를 잰다(macOS는 개발 환경, Windows는 wall clock만). quarantine 정책은 #302 결정 1–4로 정함(https://github.com/Ju571nK/lodeline/issues/302#issuecomment-6537627891): Q = E purge, byte 상한 없음(`quarantined_bytes` 노출), replay·upload 없음, boot-clock 기반 age.
- 운영자 로컬 harness로 main에서 AWS 2노드 smoke 재실행(§3–§13, D1): 시나리오 27/27, ledger 22, privacy 0, outage replay 6, 재시작 fail-closed, spool 32×200/48×503(delta 32), disable/enable 정상, 감사 seq 0–4 ok.
- 미측정: vendor client, D2, stateless/SSE 변형, SELinux.
- 남은 P1: T-15(lodeline-manager#37), T-16, 후속 #302, #307, #279, #269.

## 2026-10-25 AWS 2노드 실기 (H)

`b17b2d2`에서 운영자가 EC2 2대(t4g.small, AL2023 aarch64)로 [시험서](aws-smoke-test.md#18-aws-run-h-2026-10-25-utc) §4–§13을 D1로 실행했다.
시나리오 27/27, ledger 22 completed·중복 0, privacy 0건, offline replay 6, 재시작 fail-closed, spool 32×200/48×503(upstream delta 32),
disable/enable, 관리 감사 seq 0–4 모두 통과. spool 경계 호출 1건이 `started` + `local_record_failed` gap으로 남았고
`central_outage` gap은 계약대로 `state: open`이며(close는 `sequence_gap`만), `started_at`/`ended_at`이 §12 서버 중지와 일치해 정상 기록·종료됐다. 서버 중지 3회 중 outage gap은 1건뿐인데, 연속 ingest 실패 3회(`OUTAGE_THRESHOLD`) 기준에 짧은 §11 중지가 못 미친 것으로 추정한다(재시도 횟수 미측정). Vendor client(R), D2, manager UI, systemd는 미측정.

## 2026-10-24 T-13d / T-12b2 착수

기준: main `e5612f8` (#313 merged), 작업 브랜치 `feat/proxy-invocations-sessions`.
사용자 요청: 두 작업의 구현·독립 리뷰·검증을 마무리한다. 외부 배포·실기 완료나 P1 전체 완료를 뜻하지 않는다.
Orca Run: `run_284f3b0923d3`.

| 작업 | 역할 / Dispatch | 소유 파일 | 상태 |
|---|---|---|---|
| T-12b2 호환성 gate | researcher / `ctx_b3121a18faa1` | `docs/research/sigil-proxy-t12b2-compatibility-2026-10-24.md` | 완료, 인용 정리 `ctx_3f6967d4e22e` completed/released |
| T-13d/T-12b2 분해·계약 점검 | planner / `ctx_1a60a1718a30` | 읽기 전용 | 완료, 사용자 요청으로 보존 terminal 종료 |
| 계약·실행 기록·통합 | orchestrator | 이 문서 및 필요한 proxy 스펙 문서 | 진행 중 |
| T-13d/T-12b2 구현·통합 | coder / `ctx_ac452c5b9280` | `crates/lodeline-proxy/**`, `crates/lodeline-proxy-e2e/**` | provider 세션 한도로 worker_done 없이 종료, abandoned/failed; WIP 보존 후 재배정 |
| initialize gate | coder / `ctx_a2df824d06cb` | `crates/lodeline-proxy/src/mcp/initialize.rs`만 | 격리된 base export에서 단위 18개·clippy·MSRV 통과, released |
| initialize buffer 상한 보완 | coder / `ctx_d0cc17fbd9a0` | 같은 parser 파일 단일 작성자 | 격리 base 단위 19개·fmt/clippy 통과, released; 통합 coder에게 소유권 반환 |
| 구현 계약 독립 검토 | reviewer / `ctx_4ecc09b97238` | 읽기 전용 | needs_changes R1/R2 문구 보완, 최종 코드 리뷰에서 재확인; released |
| producer 조기 독립 검토 | reviewer / `ctx_077cd7d07136` | `invocation_sink.rs` 중심 읽기 전용 | needs_changes (ACK 취소 중 orphan, lookup timeout 잔존 작업 상한 등); released |
| session/health 조기 독립 검토 | reviewer / `ctx_d86213826a64` | session·health·cancel 모듈 읽기 전용 | needs_changes (late binding mark, initialize session oracle, Debug redaction); released |
| AWS 시험 준비 | writer / `ctx_de36f4a2f324` | `aws-smoke-test.md`, `scripts/proxy-smoke/**` | provider 한도 abandoned/failed 이력; retry에서 scripts 복구·재검증 완료, terminal 종료 |
| 구현 재개·통합 | coder / `ctx_40bca12dbac6` | proxy/e2e 코드 (producer 파일 제외) | 구현 및 표적 테스트 완료, released; H1 별도 보완까지 최종 승인 |
| producer 마무리 | coder / `ctx_9d479bc88b33` | `crates/lodeline-proxy/src/invocation_sink.rs`만 | 구현 완료, 표적 회귀 12개 통과; 독립 검토 `ctx_60ce3b1dbc7a` needs_changes; H1/M2 보완 `ctx_4f8cba8e644f` 및 최종 H1 `ctx_dacf0769c76e` 완료, terminal 종료 |
| AWS 시험 준비 재개 | writer / `ctx_a99d825b0319` | runbook·`scripts/proxy-smoke/**` | 완료, 도구 단위 13개 통과; released. 최종 코드 로컬 예행 별도 |
| 통합 독립 리뷰 | reviewer / `ctx_bb6ebe5bdca9` → `ctx_6618094b71e4` | 읽기 전용 | 초기 needs_changes 수정 후 최종 approve; 모두 종료 |

최종 상태: H1 보완 `ctx_dacf0769c76e`, 독립 리뷰 `ctx_6618094b71e4`, 로컬 예행 `ctx_d8d4dce093de` 모두 완료/released. AWS 자원은 생성하지 않았다.
`/scripts/*` ignore의 예외로 시험 도구 소스만 추적한다. 생성한 토큰·인증서·실행 결과는 커밋하지 않는다.

### 최종 독립 리뷰 (2026-10-24)

`ctx_6618094b71e4`가 현재 변경 소스와 회귀 테스트를 읽고 **approve**했다.
초기 리뷰 결함을 수정한 후 현재·대기 작업 RAII loss accounting, pending start의 ACK/취소 경쟁,
포화 gap queue의 accepted-or-counted 인계와 lifecycle `Stopping` 오류 경계를 재검토했다.
독립 표적 실행은 producer 16, 실패 종료 1, HTTP session 14 + health 2, inventory queue 2,
initialize parser 19개 통과(exit 0). 실기·AWS·vendor client·전체 workspace 검증은 이 리뷰에 포함되지 않는다.
Inventory Drop/coalescing의 정확한 수명 경계는 정적 검토이며 saturation 회귀가 보조한다.
최종 producer SHA256 `7f0ac803370bd90053d49903415c980fed43aceafe46198c42809ad18b9632b3`,
lifecycle `3f2171a06f67d127bce535847805175d39f607d6b37b238968d9914ee129af29`.

### 확정 소스 통합 검증

- `cargo test -p lodeline-proxy -p lodeline-proxy-e2e --all-features`: **572 passed, 0 failed**, exit 0.
  실제 binary build 실패를 skip하던 두 E2E를 assertion으로 보완했고 현재 둘 다 실행·통과했다.
  중첩 compile 실패 0. 사전 workspace 검증 이후 변경된 proxy/e2e 전 범위를 다시 검증했다.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo +1.88 check --workspace --all-targets --locked`, `cargo fmt --all -- --check`,
  `git diff --check`: 모두 exit 0.
- 확정 소스 로컬 바이너리 예행 완료: stateful/stateless SSE 각각 27/27, ledger 각각 22 completed,
  privacy 0건. Offline replay 6 completed, spool 제한 31×200/49×503와 upstream delta31 일치,
  재시작 fail-closed 및 복구 통과. [시험서 최종 예행](aws-smoke-test.md#17-final-source-local-rehearsal-l-2026-10-24-utc). AWS 미실행.
- 사용자 요청으로 완료·중단 상태에 남아 있던 terminal 6개를 명시적으로 닫았다.
  예행 verifier도 완료 후 released. 현재 하위 에이전트는 모두 종료했다.

### 사전 통합 검증 이력

- Orchestrator fixture/helper 테스트 14개 통과 (exit 0). 누락·읽기 실패·빈 scan target은 실패로 처리한다.
- Workspace all-features 사전 검증 exit 0, 합산 2,477 passed. 다만 실행 중 source 변경으로
  중첩 binary build 두 번이 실패했고 기존 테스트가 local skip 처리했다. 이 결과는 최종
  production-binary 검증이 아니다. 해당 테스트를 fail-closed로 보완하고 최종 소스로 다시 실행한다.
- Producer H1/M2 보완 `ctx_4f8cba8e644f`: 14개 회귀 및 좁은 strict clippy 통과,
  SHA256 `994e798cb0534445fe5fd5d2dc9f10c2c9bbf800eecf6a242b9d92f2f9ecfb11`.
- MSRV `cargo +1.88 check --workspace --all-targets --locked` 및
  `cargo clippy --workspace --all-targets -- -D warnings` exit 0 (H1 최종 변경 전).
- 최종 통합 독립 검토 `ctx_6618094b71e4` 진행. Inventory worker Drop 및 connection JoinSet
  완료 항목의 지속 회수까지 확인한 뒤 코드 확정·로컬 예행을 진행한다.

### 2026-10-24 복구 체크포인트

Claude 작업자 두 명은 provider 세션 한도 메시지로 턴이 종료됐고 worker_done은 없었다.
실행 중 프로세스 종료를 추정하지 않고 Dispatch를 fence(abandon)했으며 파일을 보존했다.
이 WIP는 완료나 승인된 구현이 아니다. 같은 Task를 다른 사용 가능한 provider로 이어간다.

- initialize gate 단위 19개는 별도 base export에서 통과했다. 실제 tree 통합은 별도 확인한다.
- `inventory_route_scope` 구형 테스트는 초기 세션 미수립 대기로 멈춰 해당 테스트 프로세스만
  종료했다. 이후 작성자가 handshake+시간 상한을 보완해 4개 통과를 보고한 도구 출력이 있다.
- producer F1(ACK 중 future drop과 orphan start), F2(timeout 뒤 blocking 작업 상한),
  F3(inflight 예약 상한), loss retry/건강 표시를 현재 소스·회귀 테스트로 재확인한다.
  WIP에 Pending 상태와 lookup semaphore가 추가됐으나 최종 검증 전이다.
- session initialize oracle·Debug·마지막 active call 뒤 종료 hook은 수정 중이었다.
  route_health의 current-binding 검사와 table snapshot은 health mutex **안에서** 해야 한다
  (check-before-lock이면 늦은 이전 binding mark 또는 current() prune이 새 unsupported 상태를 지운다).
- 새 HTTP session/init/DELETE/health 회귀, 실제 server로 invocation 기록·offline replay·privacy E2E,
  full workspace·MSRV·CI 및 통합 독립 리뷰는 아직 완료가 아니다.
- AWS 시험서의 임시 로컬 예행은 실제 AWS/실제 vendor client 검증이 아니다.
  `scripts/proxy-smoke/` 링크가 실제로 갖춰졌는지, scratch 파일과 남은 테스트 프로세스를 확인한다.

인수 범위: PX-003/004/006–011/013–016, AC-03/04/05/06/07/08/12/15.
T-13d는 실제 중계 요청의 start durable ACK → 단일 upstream dispatch → cancel/completion 기록,
검증된 설정/협상에서만 actor·revision·protocol provenance를 가져오는 경로와 spool 실패 차단을 포함한다.
T-12b2는 세션의 principal·route 격리, cancel key의 세션 구분, JSON/SSE initialize 판정,
미지원 capability/version 거절·upstream cleanup, 초기화 이후 version header 규칙,
GET 405·DELETE 및 inventory session 종료 연결을 포함한다.
지원 revision(2025-11-25), relay-first 원문 보존, P1 observe 및 제품별 기존 compatibility gate를 유지한다.
세션 누락·stateless upstream·upstream POST404 등 세부 선택과 인수 기준은
[T-13d/T-12b2 계약](t13d-t12b2.md)에 고정했다. 현재 client 버전 확인은 로컬 정적 근거이며
기존 probe와 다른 버전의 proxy-path 실기 호환성을 주장하지 않는다.

## 2026-10-23–24 PR #313 병합 전 회귀 수정

기준: `d9e98f3`, T-13c / #312 / PR #313. 요구사항 PX-005/006/010/011,
인수 기준 AC-05/06, 계약 scope key·M2b·N11. 기존 호환성 gate와 P1 한계를 유지한다.

| 작업 | 역할 / Dispatch | 소유 파일 | 상태 |
|---|---|---|---|
| T-13c-fix | coder / `ctx_e37a41641c1f` | `crates/lodeline-proxy/**`, `crates/lodeline-proxy-e2e/**` 중 필요한 구현·회귀 테스트 | completed, 사용자 인계로 terminal retained |
| 실행 기록·통합 | orchestrator | 이 문서 | 로컬 검증 완료, PR 업데이트 |
| 독립 재리뷰 | reviewer / `ctx_05ece3268fd2` | 코드·회귀 테스트 읽기 전용 | approve (정적 검토, 테스트 재실행·실기 검증 아님), released |
| 자동 검증 | orchestrator / verifier | 읽기 전용 테스트 실행 | workspace 2,417 passed, 0 failed |

수정 대상:

- 요청 완료 시 최신 route scope를 조회하여 이전 upstream 응답을 새 upstream/credential scope의
  기준 목록으로 기록하는 경쟁 조건. 실제 전달에 사용한 불변 라우트와 같은 scope를 유지해야 한다.
- 일시 재시도 중단인 `Poisoned`를 `Quarantined`로 취급하여 conflict 없이 spool 이벤트를
  영구 rewrite하는 회귀. 실제 quarantine만 conflict rewrite를 허용한다.

수정 전 증거: 기존 표적 테스트 51개 통과와 별개로 scope 변경 중 요청 재현 테스트 실패.
Poisoned 경로는 독립 정적 리뷰와 orchestrator 코드 확인으로 확인했고 회귀 테스트를 추가한다.
완료 결과 (2026-10-24):

- `RouteSpec`/불변 `Route`가 scope를 보존하고, 실제 선택된 라우트의 scope를
  `CallRef`에 복사한다. `InventorySink`의 가변 scope map과 별도 publish 경로를 제거했다.
- `EntryCheck::Poisoned`를 분리해 재시도 중인 메타데이터의 이벤트를 변경 없이 전달한다.
  실제 `Quarantined`만 conflict rewrite를 허용한다.
- 신규 HTTP 회귀 테스트 4개는 `ConfigSync::on_fetch`로 설정을 적용하고 요청 전달 직전
  credential scope·upstream 변경과 route 삭제를 끼워 넣어 이전 scope 보존을 확인한다.
- Poisoned 회귀는 sync/async `CheckedSource` 모두 원문·ref 보존, gap 부재,
  unpoison+ACK 복구, 이후 실제 conflict의 원문 보존·rewrite·gap을 확인한다.
  이전 `verify_entry` 매핑으로 잠시 되돌렸을 때 실패하고 복원 후 통과했다.
- coder: `cargo test -p lodeline-proxy --all-features` 473 passed;
  `cargo test -p lodeline-proxy-e2e --test inventory_e2e` 4 passed.
- orchestrator: `cargo fmt --all -- --check`, `git diff --check`,
  `cargo clippy --workspace --all-targets -- -D warnings` 통과;
  `cargo test --workspace` 2,417 passed, 0 failed, 0 ignored.
- 독립 정적 리뷰 approve. GitHub 승인 리뷰나 실기 검증을 뜻하지 않는다.
  PR push 후 Windows·Linux·MSRV 등 원격 CI는 별도로 확인한다.

유지되는 한계: principal을 session 대신 사용하는 P1 동작, Windows inventory 미지원,
실제 클라이언트·운영 환경 실기 미검증. Poisoned 복구 회귀의 ACK는 store에 직접 적용하며,
기존 registry client retry 테스트를 대체하지 않는다. Poisoned member를 포함한 inventory
report 제외·drop 동작은 이번 event rewrite 수정 범위 밖으로 유지했다. 실제 병합은 하지 않았다.

## 2026-10-11 P1 1회차 배정 (기준 `2120415`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| P0-exit-audit | sonnet (spec auditor, 읽기 전용) | P0 종료 조건·잔여 분류·추적성 | 전체 | 없음 | — |
| P1-plan | sonnet (planner, 읽기 전용) | T-10/T-11 구현 계획·슬라이스 | T-10/T-11 | 없음 | — |
| PR0 | sonnet (coder, worktree) | `lodeline-proxy-api` wire DTO crate + golden 테스트 | PX-005/006/010/011/016, AC-05/06 | `crates/lodeline-proxy-api/**`, workspace `members` | #244 |
| T-10 A–D | sonnet (coder, worktree, PR0 브랜치 기반) | `lodeline-proxy` 골격·bootstrap·limits·state_dir·rpm/systemd | PX-001/013/016, AC-07/12/14 | `crates/lodeline-proxy/**`, `packaging/` proxy 파일 | #245 |
| T-11 S1 | sonnet (coder, worktree, PR0 브랜치 기반) | server proxy 신원·등록, 404 `proxy_unknown` 선검사 | PX-008/009, AC-04 | `crates/lodeline-server/src/proxy/**` 외 배정 시 명시 | #246 |

진행: P0-exit-audit completed(코딩 착수 차단 항목 없음, 문서 gate 문구만 남음 → P0 종료 문서 반영). P1-plan completed(PR0 → T-10 갈래 A와 T-11 S1 병렬 → S2–S5 순차; app.rs·config.rs는 한 작성자). fixture 14 tests orchestrator 재실행 통과. PR0 coder completed → 독립 리뷰 needs_changes(M-1 serde 오류의 값 echo, M-2 validate 비재귀, L-1–L-4) → fix → 재확인 **approve**(차등 298건·canary 18건) → PR #248. T-10 A–D(#245): coder → 리뷰 accept with fixes(M1 origin 정규화·http 정책, M2 fd 기반 파일 검사) → fix(공유 verifier를 lodeline-proxy-api로) → 재확인 accept → PR #249(#248 위 stacked). T-11 S1(#246): coder → 보안 리뷰 approve-with-fixes(M1 판정 불가 issuer, M2 e2e 격리, M3 registry 로드) → fix → 재확인 approve(release 빌드에 test seeding 없음 확인) → PR #250(#248 위 stacked). T-10 E 패키징(#245): coder → 리뷰 request changes(H1 CI 포트 상수 오류, H2 릴리스가 미완성 binary 공개) → fix(전용 `lodeline-proxy` 사용자, 릴리스 제외) → 재확인 approve → PR #253 머지. T-11 S2a(#251): coder → 보안 리뷰 approve with changes(M1 fsync 중 registry 잠금, M2 승격 감사 트랜잭션 밖) → fix → 재확인 approve → PR #255 머지(Windows 빌드 import 수정 포함). 후속 이슈 #252(deb sysusers 공유 파일 충돌), #254(감사 체인 helper 공유).

### 1회차 머지 결과 (2026-10-11)

| PR | 작업 | 이슈 |
|---|---|---|
| #247 | P0 종료 문서 | — |
| #248 | PR0 `lodeline-proxy-api` | #244 |
| #249 | T-10 A–D `lodeline-proxy` 골격 | #245 |
| #250 | T-11 S1 신원·등록·404 guard | #246 |
| #253 | T-10 E 패키징(설치만, 비활성, 릴리스 제외) | #245 |
| #255 | T-11 S2a 관리 인증·감사·lifecycle·운영자 CLI | #251 |

남은 P1: T-11 S2b(CSR 서명), S3(config·status), S4(ledger·ingest), S5(projection·조회), T-12 relay, T-13, T-14, T-15(manager, lodeline-manager#37), T-16.
실기 미검증: Rocky 9 SELinux enforcing·systemd `is-enabled`(컨테이너에 systemctl 없음), x86_64 baseline.
교훈: unix 전용 코드의 import도 `cfg(unix)`로 막는다(Windows CI 실패 2회). 후속: `parse_entry_view`, ParseError 분류 marker 위조(T-11 S4), upload proxy_id 대조(server).

## 2026-10-12 P1 3회차 배정 (기준 `bbe48c8`)

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| T-12c1 | sonnet (coder, worktree) | proxy config fetch·apply, #260 한도 min·verifier `not_after`·origin 공유 | PX-005/008/012/016, AC-04/12 | `crates/lodeline-proxy/**`, `crates/lodeline-proxy-api/**` | #263 |
| T-12c2 | sonnet (coder, worktree, T-12c1 뒤) | proxy status 보고, #260 503 `storage_limit`·422 처리 | PX-012/016, AC-12 | 같음 | #265 |
| 통합 e2e | sonnet (coder, worktree) | 실제 server + proxy, loopback mTLS 수명주기 | PX-005/008/009/012, AC-04 | `crates/lodeline-proxy-e2e/**`, `lifecycle.rs` test-util | #267 |
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
| S4 A | sonnet (coder, worktree) | parse 오류 분류를 typed 신호로(marker 위조 차단), 413/429/503 code | PX-010/011, AC-05/06 | `crates/lodeline-proxy-api/**`, server `status.rs` 호출부 | #271 |
| S4 B1 | sonnet (coder, worktree, A 뒤) | server SQLite ledger: 중복·tombstone·gap·보존·한도·SV-1 | PX-010/011, AC-05/06 | `proxy/ledger.rs`, `proxy/mod.rs`, `config.rs`, `config_api.rs`(PUT 검사) | #274 |
| S4 C | sonnet (coder, worktree, B1과 병렬) | proxy ingest client·gap queue 영속·#260 F1/F2·상태 필드 | PX-011/012/016, AC-06/12 | `crates/lodeline-proxy/**` | #275 |
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
| S5 e2e | sonnet (coder, worktree) | 실제 mTLS로 ingest→projection→조회 | AC-05/06/12 | `crates/lodeline-proxy-e2e/tests/server_proxy_query_e2e.rs` | #293 |
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
남은 P1: S2b(CSR 서명), T-12b(MCP protocol), T-13(registry entry 생성)·T-14(spool·이벤트 생성), T-15(manager, lodeline-manager#37), T-16.
실기 미검증: 변화 없음. 조회 API의 실제 TLS 검증은 e2e(macOS 로컬·CI)까지이며 Rocky 실기·SELinux·systemd는 하지 않았다.
교훈: 병렬 갈래가 같은 파일을 필요로 하면 먼저 끝난 갈래를 머지하고 rebase한 뒤 소유권을 넘긴다(C 2단계). 고정 날짜 fixture는 보존 정리가 있는 경로에서 시간이 지나면 깨진다(e2e L4).

## 2026-10-20 P1 6회차 배정: T-12b1·T-13·T-14 (기준 `ad63551`)

결정(사용자, 2026-10-20·10-21): [decisions.md "T-13/T-14 범위"·"T-13a/T-13b 후속 결정"](decisions.md).

| 작업 | 모델/역할 | 목표 | Spec | 소유 파일 | 이슈 |
|---|---|---|---|---|---|
| 골격 | orchestrator | `mcp`·`spool` 모듈 자리, 결정 기록 | — | `lib.rs`, `Cargo.toml`, decisions.md | — |
| API DTO | sonnet (coder, worktree) | inventory 보고 DTO, `ErrorItem.metadata_ref` | PX-005/016, AC-02 | `crates/lodeline-proxy-api/**` | #298 |
| T-14a | sonnet (coder, worktree) | SQLite WAL spool, fsync 뒤 ack, 한도·격리 | PX-011/012, AC-06/12 | `lodeline-proxy/src/spool.rs` | #297 |
| T-12b1 | sonnet (coder, worktree) | MCP 요청·응답 분류, `ObservationSink`, cancel | PX-003/004, AC-07 | `lodeline-proxy/src/mcp/**` | #299 |
| T-14b | sonnet (coder, worktree) | spool을 lifecycle·status 보고에 연결 | PX-011/012, AC-06/12 | `lifecycle.rs`, `status_report.rs`, `ingest_client.rs`, `state_dir.rs`, e2e | #305 |
| T-13a-server | sonnet (coder, worktree) | inventory 수신·snapshot/drift projection·조회 | PX-005/006, AC-02 | `lodeline-server/src/proxy/inventory*.rs`, `ledger*.rs`, `query.rs`, e2e | #304 |
| T-13b | sonnet (coder, worktree) | registry key·JCS·registry 저장소·inventory 엔진·upload client | PX-005, AC-02/05 | `lodeline-proxy/src/{jcs,registry_key,registry_store,inventory,registry_client}.rs` | #306 |
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
| T-12a | sonnet (coder, worktree) | raw relay·목적지 검사·한도·listener TLS | PX-003/004/008/014/015, AC-07 | `crates/lodeline-proxy/**` | #258 |
| T-11 S3 | sonnet (coder, worktree) | server config 발급·status 수신 | PX-005/008/012, AC-04/12 | `crates/lodeline-server/src/proxy/**` 외 배정 시 명시 | #257 |

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

1. PR0 `lodeline-proxy-api`(#244): coder → 독립 리뷰 → 검증 → PR.
2. PR0 뒤 병렬: T-10 `lodeline-proxy` 골격(#245), T-11 S1 신원·등록(#246). 파일 소유가 겹치지 않게 배정한다.
3. 이후 T-11 S2(관리 인증·운영자 CLI) → S3(config·status) → S4(ledger·ingest) → S5(projection·조회). app.rs·config.rs는 한 작성자.
4. T-12 relay는 T-10 골격 뒤. T-15 manager는 lodeline-manager#37과 그 저장소 지침에 따른다.

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
