# 테스트 계획과 실제 검증

## A5 최종 판정 — 2026-11-08

**완료.** [승인 설계](superpowers/specs/2026-11-07-a5-design.md)에 따라 Engine → EventPublisher → EventLogger를 연결했다. 최종 Debug·Release/clang-tidy·ASan/UBSan은 같은225개 각각 전부 통과했고 실패·disabled·skip0, 포맷 검사도 통과했다. 독립 리뷰 중요1건(SIGXFSZ)을 실제 RED→GREEN으로 수정했으며 경미3건은 [한계](known-limitations.md)에 보류했다. [A5 실행 증거](a5-validation-2026-11-08.json)에 JUnit·명령·해시·실제 출력·리뷰를 기록한다. 아래 A4 이하는 당시 결과이며 현재 A5 기능 부재를 뜻하지 않는다.

- 로거12개: 공통 schema/7종 이름/uint64/UTC·null·범위 밖 시각, global locale 독립성, 제어문자·잘못된 UTF-8·절단, reserved key/줄 상한, 부분 쓰기·flush 예외·실패 고정, 독점 생성/600/링크·부모 경로.
- Engine11개: 소유 수명, valid/parse 오류·양방향·만료, 재전송 중복 억제, Flow 용량 후 packet fallback, EOF/abort 반복/후속 inspect 거부, 배열 정리, 역순 시각·설정/처리 예산 오류.
- Publisher5개: 종료 watermark·최초 관측 방향, gap_filled 정보 구별, Flow 거부 후 verdict, 외부 오류 절단, 기록 실패 후 엔진 진행/정리.
- CLI12개: stdout JSONL 재파싱·stats 자기 포함, 파일과 기존 콘솔, 입력/룰/기존/링크 보존, 빈 입력/null·입력 열기 오류/abort, 룰 우선 검증, 옵션 오류, sink 쓰기/최종 flush 오류, Pass/Drop·escape, 처리 예산 오류에 거짓 Allow 없음, 합성 PCAP의 이벤트7종/독립 논리 집계.
- standalone jsonl.process1개(내부7시나리오): 실제 파일/0600·기존 파일 보존·stdout·손상 PCAP·SIGPIPE·SIGXFSZ의 stdout/파일 경로. Python3로 이번 세 구성 모두 등록·실행됐다. 기존184개+신규41개=225개다.

RED 기록은 build-a5-work에 보관한다. 로거/Engine 최초 missing-header는 컴파일 실패이며 실행 성공으로 세지 않는다. 숫자 locale 회귀는 실제 assertion RED 후 classic locale로 GREEN. CLI --log 미구현10개 assertion RED, 실제 닫힌 stdout은 exit -13(SIGPIPE) RED 후 main에서 처리한다. 통합 중 기존 console flush 진단 누락은 기존 회귀가 포착해 복구했다. 합성 입력은 first-seen 상충 재전송까지 포함해 healthy Drop3이며 failed-sink 검사도 이 기준과 비교한다.

리뷰 후 파일 크기 제한1024바이트에서 실제 exit -25를 재현하고 main의 신호 정책을 수정했다. stdout JSONL과 파일 로그 양쪽이 나머지10패킷(9parsed/1skipped), Drop3을 유지한 뒤 exit1/log_complete0으로 종료했다. 최종 root·uid65534 실행에서 각7시나리오를 통과했다. 건강한 합성 출력은25줄, detections2/emitted3/suppressed4/Drop3/actualDrop0이다. 기록에 미래 flush/close 성공을 단정하는 log_complete는 없고 최종 stderr 요약만 이를 확정한다.

A4 소스47개 중40개는 해시가 같고7개만 계획된 연결 변경이다. 신규 소스/룰/프로세스 검사14개를 더한61개 해시와 문서·fixture·실행 증거 해시를 기록했다. strict tidy의 optional 접근과 미사용 parse 반환값 진단도 억제 없이 해소했다. 실제 장치 close 실패/실제 bad_alloc 주입, 방화벽/NFQUEUE/live/Inline/AI 및 처리량·지연·fsync 내구성 검사는 미실행이다. 자동 commit/push 없이 현재 폴더에 남기고 A6는 다음 지시를 기다린다.

## A4 최종 판정 — 2026-11-07

**완료.** [승인 설계](superpowers/specs/2026-11-07-a4-design.md)에 따라 KMP 룰 엔진을 구현했다. 리뷰 중요2건을 수정한 최종 소스로 Debug·Release/clang-tidy·ASan/UBSan 각각184/184, 실패·skip0과 포맷 검사를 통과했다. 정상/악성 예시의 결정적 alert/pass/drop과 모든 룰 테스트를 실제 확인해 A4 인수 조건을 충족했다. 경미3건은 명시적으로 보류한다.

| 검사 | 현재 결과 |
| --- | --- |
| 기존 A3 회귀 | 146개 보존 |
| 새 로더 | 8개, 타입/필드/중복/정수/ASCII/UTF8/파일·깊이·룰 수 경계 subcase 통과 |
| 새 룰 엔진 | 16개, 우선순위·재전송·ACK·겹침·상태 상한·만료·모순된 API 범위 거부 통과 |
| 새 A3 관련 범위 | 4개, 허용/거부/wrap/갭/깊이/종료 범위 통과 |
| 새 CLI | 10개, 선택 룰·오류 선행·fallback·expiry·Unicode 제어문자·출력 오류 통과 |
| Debug | 184/184, 실패·skip0 |
| Release/clang-tidy | 최종 빌드 성공, 184/184, 실패·skip0 |
| ASan/UBSan | 최종 빌드 성공, 184/184, 실패·skip0 |
| format-check | 통과 |
| 최종 독립 리뷰 | Critical0, Important2 수정, Minor3 보류, 판단 보류 없음 |

로더와 엔진 초기 RED는 새 헤더 부재로 컴파일이 실패한 것이며 런타임 실행으로 기록하지 않는다. CLI는 기존 A3 코드에서 실제8개 실패/기존 invalid-option1개 통과를 확인한 뒤 구현했다. 빈 함수나 기대값 변경으로 통과시키지 않았다.

실제 프로세스에서 예시 HELLO stream alert는 events1/drop0, BLOCKME packet 룰은 events1/simulated_drops1, 우선순위 pass 룰은 Allow를 확인했다. HEL+LO 후 HEL 재전송과 순수 ACK는 events1/suppressed1/simulated_drops2였고 ACK는 Allow다. EOF state_bytes0, 예산7바이트는 detection_error/코드1, 잘못된 룰은 PCAP 열기 전 rule_error/코드1이었다. nobody(uid65534)의 packet drop 시뮬레이션도 확인했다.

사용자 자체 테스트는 A0~A8 IPS 완성 뒤 별도로 진행한다. 이번 자동/합성 PCAP 검증을 사용자 자체 테스트의 완료로 기록하지 않는다. B0/AI는 미착수다. 원본 로그/기준선은 ignored build-a4-work/에 보관하며 원격 CI·실제 차단·성능 측정은 미실행이다.

독립 fresh-context 리뷰(gpt-6-astra/high)는 모순된 직접 API 재조립 범위가 ACK를 Drop시키는 문제와 DEL/C1/Unicode 줄 구분자가 콘솔에 출력되는 문제를 재현했다. 회귀2개를 먼저 실행해2개 모두 실제 실패한 뒤 수정했다. 현재 payload 길이·새 연속 구간 첫 바이트와 허용 위치의 관계를 상태 변경 전에 검사하고, message를 DEL까지 포함한 ASCII JSON 표현으로 출력한다. 회귀2/2 GREEN과 전체 Debug184/184을 확인했다. 테스트 helper의 optional은 검사 후 반환하는 getter로 바꿔 정적 분석의 증명 경로를 명확히 했으며 입력/기대값/검사 설정은 유지했다.

경미3건은 stream_evaluated의 window-availability 의미, 일부 오류의 실제 필드명 부재, 시스템 할당 실패 분류/직접 API 재시도 원자성이다. [알려진 한계](known-limitations.md)에 계약과 영향을 기록했다. 할당 실패 주입은 자동 승인 검토 사용량 한도로 미실행이며 해당 경로를 런타임 검증한 것으로 보고하지 않는다. 두 중요 수정은 별도 재리뷰 없이 회귀와 최종 세 구성 전체 검사로 검증한다.

최종 세 구성은 각각184/184로 같은 검사를 실행했다. 기존146개와 새 로더8/엔진16/관련 범위4/CLI10개이며 GoogleTest169개+기존 프로세스/fixture15개다. 소스/로그/예시·임시 룰·PCAP 해시, JUnit, 명령과 직접 실행 출력은 [A4 실행 증거](a4-validation-2026-11-07.json)에 저장했다. A3 소스35개 중29개는 그대로이고6개만 계획된 연결 변경이다.

### A4 변경 파일

- 신규 생산 코드: rule.hpp, rule_loader.hpp, rule_engine.hpp, detection_decision.hpp, src/rule_loader.cpp, src/rule_engine.cpp, rules/example.json.
- 기존 연결: tcp_reassembler.hpp/.cpp의 ByteRange, src/cli.cpp, 루트/테스트 CMakeLists, fixture_writer.cpp.
- 신규 테스트: test_rule_loader.cpp, test_rule_engine.cpp, test_reassembly_ranges.cpp, test_cli_rules.cpp와 fixtures/rule_fixtures.hpp.
- 문서: AGENTS/PROJECT_SPEC/IMPLEMENTATION_PLAN/README의 사용자 자체 테스트 조건, 설계 결정·한계·테스트·fixture 설명, 승인 설계/실행 계획, A4 실행 증거. 현재 폴더에서 자동 commit/push 없이 보관했다. A5와 B0/AI는 시작하지 않았다.

## A3 최종 판정 — 2026-11-07

**완료.** 승인된 [설계](superpowers/specs/2026-11-07-a3-design.md)와 [계획](superpowers/plans/2026-11-07-a3.md)에 따라 구현했다. HEL+LO의 실제 HELLO 복원과 역순·중복·gap, 자원 제한 및 정리를 확인했다. 독립 리뷰 중요 문제를 수정한 최종 소스로 세 구성의 전체 검사를 통과해 A3 인수 조건을 충족했다. 경미 항목 2개는 아래에 보류 기록을 남긴다.

| 구성/검사 | 실제 결과 |
| --- | --- |
| 기존 기준선 | A2 101/101, 2026-11-07 재확인 |
| 재조립 코어 | 최초 28개 + 리뷰 회귀 3개, 최종 31개 통과 |
| Flow 수명 연동 | 5개 새 검사 통과, 코어/Flow 관련 54/54 통과 |
| CLI 통합 | 9개 새 검사 포함 최종 Debug 146/146 통과, 실패·skip 0 |
| Release/clang-tidy | 최종 빌드 성공, 146/146 통과, 실패·skip 0 |
| ASan/UBSan | 최종 빌드 성공, 146/146 통과, 실패·skip 0 |
| format-check | 통과 |
| 독립 최종 리뷰 | Important 2건의 회귀 3개 RED→GREEN, Minor 2건 보류 |

기존 101개에 코어 31개·수명 연동 5개·CLI 9개를 추가했다. 총 131개 GoogleTest와 15개 CTest 프로세스/fixture 작업으로 146개다.

### 인수 조건과 경계

- SYN 99 → HEL at100 → LO at103의 prefix가 실제 HELLO이며, SYN → LO → HEL 순서도 같은 결과다. 중복은 신규 바이트 0, 갭 뒤 바이트는 pending이고 앞의 누락을 채우기 전에는 노출하지 않는다.
- 정·역방향 분리, borrowed 입력 변경 뒤 pending 유지, 여러 갭과 부분/전체 보충, pending/노출된 overlap의 first-seen 및 충돌 이벤트.
- midstream의 과거 데이터 처리, 순수 ACK/FIN, SYN payload, SYN 재전송/재사용, FIN 선도착·과거 FIN 거부·RST 양방향 정리·잘못된 SYN+RST의 부작용 방지.
- 0xffffffff→0 순환에서 갭/재전송, 동일·반 공간 차이의 비교, 깊이 경계/초과, bitmap 반올림, 여러 Flow/양방향 공유 예산, 거부 후 재시작 방지와 정리 후 새 ID의 공간 재사용.
- observe 자동 만료·명시 만료·역순 시계·잘못된 입력의 상태 미변경·만료 콜백 예외의 정확한 집계·EOF sink 실패 정리.
- CLI의 옵션 오류/큰 유효 설정의 지연 할당, UDP/추적 거부의 미할당, 파싱 오류 중 만료, 영구 gap/midstream, 충돌·깊이·예산 한도, 종료 이벤트 출력 실패.

### RED/GREEN와 실제 프로세스

코어 첫 RED는 새 헤더 부재의 컴파일 실패다. 이때 런타임 테스트가 실행된 것으로 기록하지 않는다. Flow 만료 overload 부재도 컴파일 단계에서 확인했다. 추가한 빈 FIN 뒤 RST의 closed 플래그 검사는 실제 assertion 실패 후 수정했다. CLI는 기존 실행 코드에서 새 9개 중 8개가 실제 실패했고, 원래도 잘못된 옵션을 거부하던 1개는 통과했다. 구현 후 전체 Debug 143개가 통과했다.

fixture writer가 생성한 reassembly_hello/gap PCAP을 실제 `build/miniips` 프로세스로 읽었다. hello는 신규 5바이트·FIN 관측·최종 배열 0바이트, gap은 prefix 0/pending 2와 최종 gap/capture_end였다. 깊이 4/예산 5와 예산 1도 각각 제한 이벤트를 확인했다. hello는 uid 65534에서도 같은 정상 결과다. 전체 자동 검사는 root로 수행하며 비특권 확인을 전체 테스트 검증으로 확대하지 않는다.

### 독립 리뷰와 수정

fresh-context read-only 리뷰(gpt-6-astra/high)가 Critical 0, Important 2, Minor 2를 보고했고 판단 보류는 없었다. 중요한 두 문제는 정상 FIN 뒤 RST가 거짓 gap을 만드는 동작과, payload 끝의 FIN 위치가 반 시퀀스 공간에 도달해도 종료 표식을 확정하는 동작이었다.

실제로 실패한 회귀 테스트 3개를 먼저 추가했다. RST 뒤 새 pending을 계산하지 않고 원래 존재한 gap 이력만 보존하며, FIN/세그먼트 끝이 지원하는 비교 범위를 벗어나면 종료 표식 저장 전에 거부하도록 수정했다. 3/3 GREEN과 전체 Debug·Release/clang-tidy·ASan/UBSan 각각 146/146을 확인했다. 별도 재리뷰 대신 같은 수정 소스에 세 빌드 구성을 실행했다. 실제 프로세스로 reassembly_reset.pcap의 거짓 gap 부재와 reassembly_ambiguous_fin.pcap의 모호한 경계 거부 뒤 정상 FIN 수락도 확인했다.

경미 항목은 RST 뒤 ACK의 reset 이벤트 중복과 잘못된 enum 캐스트로 호출한 finish_all의 상태 정리/거부 불일치다. [알려진 한계](known-limitations.md)에 보류 이유와 직접 API 사용 계약을 남긴다. 정상 CLI의 데이터 순서/메모리 제한이나 A3 인수 조건의 미완료 항목으로 분류하지 않는다.

원본 로그·JUnit·시작 기준선은 ignored `build-a3-work/`에 보관한다. [A3 실행 증거](a3-validation-2026-11-07.json)에 명령·JUnit 요약·소스/로그/fixture 해시·직접 실행 결과와 보류 항목을 저장했다. 재개 시 세 구성의 빌드가 모두 `ninja: no work to do.`였고 A2 소스 28개 중 22개는 동일, 6개만 계획된 A3 연결 변경임을 대조했다. 처리량·RSS 측정과 원격 GitHub Actions는 미실행이며 실제 네트워크/방화벽은 변경하지 않았다.

### A3 변경 파일

- 새 생산 코드: `include/miniips/tcp_reassembler.hpp`, `src/tcp_reassembler.cpp`.
- 기존 연결: `include/miniips/flow_table.hpp`, `src/flow_table.cpp`, `src/cli.cpp`, 루트/테스트 `CMakeLists.txt`.
- 새 테스트: `tests/test_tcp_reassembler.cpp`, `tests/test_reassembly_lifecycle.cpp`, `tests/test_cli_reassembly.cpp`, `tests/fixtures/reassembly_fixtures.hpp`; fixture writer와 설명도 갱신했다.
- 문서: README, design-decisions, known-limitations, test-plan, 승인 설계/실행 계획, 신규 A3 실행 증거 JSON. 기존 변경을 보존하고 commit/push 없이 남겼다. 다음 A4는 시작하지 않았다.

## A2 최종 판정 — 2026-11-06

**완료.** 승인된 [A2 설계](superpowers/specs/2026-11-05-a2-design.md)에 따라 양방향 Flow 추적을 구현했다. 요청·응답의 동일 ID와 만료 뒤 삭제·새 ID 생성이라는 인수 조건을 실제 PCAP과 단위 테스트로 확인했다.

| 구성/검사 | 실제 결과 |
| --- | --- |
| 시작 기준선 | 기존 CTest 67/67 통과 |
| Flow 모듈 | 새 단위 테스트 22/22, 전체 회귀 89/89 통과 |
| 최종 Debug | 101/101 통과, 실패·skip 0 |
| Release + clang-tidy | 빌드 성공, 101/101 통과, 실패·skip 0 |
| ASan/UBSan | 빌드 성공, 101/101 통과, 실패·skip 0 |
| format-check | 통과 |
| 독립 코드 리뷰 | fresh context의 read-only 리뷰, Critical/Important/Minor 모두 0 |

기존 67개에 Flow 모듈 22개, Flow CLI 9개, 실제 프로세스 검사 3개를 추가했다. GoogleTest 86개와 CTest 프로세스·fixture 작업 15개의 합계가 101개다. 세 구성에서 같은 101개를 실행했다.

### 기능과 경계 검증

- 정규화 키·반대 방향·모든 주소/포트/프로토콜 필드, 정렬된 키의 높은 endpoint에서 먼저 관측한 방향, 동일 endpoint 처리.
- IPv4 길이 기준 방향별 바이트·패킷·IAT·flag 집계, 역순 IAT의 0 처리, UDP의 TCP 상태 부재.
- SYN/SYN-ACK/ACK 관측에 따른 단순 상태와 FIN/RST 상태, 종료 상태를 후속 ACK/SYN으로 재개하지 않는 동작.
- 기본 120초의 직전/정확한 경계, 양방향 활동 갱신, 역순 시계, 음수 거부와 int64 최대 시각.
- 최대 개수에서 새 키 거부·기존 키 유지·만료 후 공간 재사용, 스냅샷 복사본의 독립성, payload를 보관하지 않는 상태 구조.
- CLI의 설정 순서·중복·누락·0·음수·부호·숫자 범위 초과, 매우 큰 유효 제한에서 선할당하지 않는 동작.
- 손상 패킷의 상태 미생성·처리 지속·만료 시계 진행, 추적 거부의 packet 줄·stderr·요약 표시.

### 직접 실행한 인수 사례

기존 fixture writer가 생성한 합성 PCAP을 `./build/miniips --mode pcap --input <파일>`로 실행했다.

| PCAP | 실제 관측 |
| --- | --- |
| flow_bidirectional.pcap | ID 1 유지, 방향 fwd/bwd/fwd, 패킷 2/1·IP 바이트 90/45, created=1 active=1 |
| flow_expired.pcap | 마지막 활동 2초에서 122초로 이동해 ID 2 생성, created=2 active=1 expired=1 |
| flow_capacity.pcap + --max-flows 1 | UDP 신규 키 1개 untracked, 기존 역 TCP는 ID 1 유지, rejected=1, EOF 종료 코드 0 |
| 비특권 uid 65534 실행 | bidirectional PCAP에서 동일한 정상 결과 |

### 실패를 먼저 확인한 기록과 리뷰

Flow 테스트를 먼저 작성했을 때는 구현 헤더 부재로 빌드가 실패했다. 이 첫 RED에서 런타임 테스트가 실행됐다고 기록하지 않는다. 구현 후 22개가 통과했다. CLI는 기존 A1 실행 파일에서 새 테스트 9개 중 8개가 Flow 출력·옵션 부재로 실제 실패했고, 이미 거부되던 잘못된 옵션의 회귀 검사 1개는 통과했다. 이후 구현해 전체 101개를 통과시켰다.

첫 Release 정적 분석에서 생산 코드는 통과했고 테스트 helper의 숫자 인자 두 개가 혼동될 수 있다는 경고가 발생했다. 두 번째 인자를 기존 TcpMetadata 값으로 바꾸고 같은 flag 값과 assertion을 유지해 해소했다. 의도적으로 미지원 프로토콜 값255를 넣는 테스트에는 해당 enum 범위 경고만 이유와 함께 제외했다. 전역 검사 설정을 완화하지 않았다.

독립 리뷰는 A2 시작 전 파일 복사본과 비교한 전용 diff를 사용했다. 기존 미커밋 A0/A1 작업을 A2 변경으로 오인하지 않도록 분리했다. 검토된 생산·연결 파일 10개의 해시가 최종 파일과 일치함을 확인했고, 테스트 helper 변경도 리뷰어에게 별도로 전달했다. 추가 수정 요구나 경미한 보류는 없었다.

[실행 기록](a2-validation-2026-11-06.json)에 정확한 호출 명령, 직접 실행 출력, 최종 소스 28개·PCAP 3개·로그 18개의 해시와 JUnit 결과를 기록했다. 원본 로그와 작업 기록은 Git 제외인 `build-a2-work/`에 있다. 전체 테스트는 root로 수행했으며 uid 65534 확인은 합성 PCAP 실행 1건이다. 원격 GitHub Actions와 처리량·RSS 측정은 미실행이다.

### A2 변경 파일

- 신규 생산 코드: `include/miniips/flow.hpp`, `include/miniips/flow_table.hpp`, `src/flow_table.cpp`.
- 생산·빌드 연결: `src/cli.cpp`, `CMakeLists.txt`, `tests/CMakeLists.txt`.
- 신규 테스트: `tests/test_flow_table.cpp`, `tests/test_cli_flow.cpp`, `tests/fixtures/flow_fixtures.hpp`, `tests/check_flow_cli.cmake`; fixture writer도 갱신했다.
- 문서·기록: README, design-decisions, known-limitations, test-plan, fixture README, 승인 설계, 구현 계획, 신규 `a2-validation-2026-11-06.json`.

현재 폴더에 기존 변경을 보존하고 커밋·push 없이 남겼다. A3 재조립은 시작하지 않았다.

### 재개 확인 — 2026-11-07

토큰 제한 이후 재개 요청을 받아 작업 기록과 현재 소스를 대조했다. A2는 구현·문서·리뷰까지 완료 상태였으며, 완료 당시의 소스 28개 해시가 모두 일치했다. 빌드는 `ninja: no work to do.`였고 Debug CTest를 다시 실행해 101/101 통과, 실패·skip 0을 확인했다. Release·ASan/UBSan은 동일 소스의 2026-11-06 성공 기록을 참조한다.

미완료 A2 구현은 없었으므로 코드를 다시 작성하지 않고 작업 기록의 현재 상태와 완료 보고를 정리했다. [재개 점검 기록](a2-resume-check-2026-11-07.json)에 이번 명령과 결과를 보관한다.

## A1 최종 판정 — 2026-11-05

**완료.** A0 완료 이후 사용자가 요청한 A1 인수 검토를 수행했다. `IMPLEMENTATION_PLAN.md`의 A1 완료 조건인 고정 PCAP/패킷 바이트의 정상 필드 파싱과 손상 입력의 무해 처리를 코드·테스트·직접 실행 결과에 대조했다. 이번 A1 검토에서는 생산 코드와 테스트 코드를 수정하지 않았다.

| A1 확인 항목 | 근거와 결과 |
| --- | --- |
| libpcap 오프라인 파일 읽기와 EOF 처리 | 정상 2건·혼합 2건·빈 파일 직접 실행, PcapSource 13개 테스트 |
| Ethernet/IPv4/TCP/UDP 정상 필드 | PacketParser 27개 테스트, 문서용 IP·포트·타임스탬프·길이·TCP 필드의 실제 출력 일치 |
| 잘린 헤더·길이 불일치·미지원 입력 | TCP/UDP의 모든 잘린 prefix, IHL·Total Length·Data Offset·UDP Length·caplen·fragment·EtherType 검사 통과 |
| 손상 패킷 이후 처리 지속 | mixed 파일에서 첫 패킷 `truncated_ethernet`, 이후 UDP 처리, `parsed=1 skipped=1` |
| 파일 손상·미지원 링크의 명확한 실패 | 두 경우 모두 종료 코드 1, `capture_error:` 출력, 성공 summary 없음 |
| 메타데이터 출력과 출력 장애 | PcapCli 8개 테스트에서 원시 payload 미출력, 출력·flush 오류 처리 통과 |
| 메모리 오류 검사 | A1 관련 ASan/UBSan 테스트 54/54 통과, 실패·skip 0 |

새로 실행한 Debug 빌드는 `ninja: no work to do.`로 현재 소스와 빌드가 일치함을 확인했고, 전체 CTest는 **67/67 통과**했다. ASan/UBSan에서는 `PacketParser`, `PcapSource`, `PcapCli`, `pcap.*`를 선택해 **54/54 통과**했다(27 + 13 + 8개 GoogleTest와 fixture 준비·프로세스 검사 6개). Release·clang-tidy·포맷의 동일 소스 검증 결과는 아래 A0 기록을 함께 사용한다.

기존 fixture writer로 `build/a1-review-fixtures/`에 고정 PCAP을 새로 생성하고 `./build/miniips --mode pcap --input <파일>`을 직접 실행했다.

| 파일 | 종료 코드 | 관측 결과 |
| --- | --- | --- |
| normal.pcap | 0 | TCP·UDP 각 1개, `packets=2 parsed=2 skipped=0` |
| mixed.pcap | 0 | 잘린 Ethernet 1개를 건너뛰고 UDP 처리, `packets=2 parsed=1 skipped=1` |
| empty.pcap | 0 | `packets=0 parsed=0 skipped=0` |
| truncated.pcap | 1 | 59 bytes 중 58 bytes만 존재한다는 libpcap 오류, 성공 summary 없음 |
| unsupported.pcap | 1 | Ethernet 링크가 필요하다는 오류, 성공 summary 없음 |

normal.pcap은 비특권 Linux 계정 `nobody`(uid 65534)에서도 같은 정상 결과로 종료했다. 전체 테스트는 root로 실행했으므로 이 결과를 일반 개발 계정 전체의 검증으로 확대하지 않는다.

정확한 실행 명령, 출력, 테스트 결과, 소스 21개와 fixture 5개의 SHA-256은 [A1 실행 기록](a1-validation-2026-11-05-linux.json)에 저장했다. JUnit 결과는 `build/a1-results.xml`, `build-sanitize/a1-results.xml`에 있다(Git 제외).

남은 범위 제한은 Ethernet IPv4 TCP/UDP, 체크섬 미검사, IPv6/VLAN/fragment 미지원, PCAPNG·다른 libpcap 버전의 별도 검증 미실행이다. 이는 문서화된 A1 범위이며 live 수집·실제 차단의 완료를 의미하지 않는다. 다음 단계 A2는 시작하지 않았다.

이번 검토의 변경 파일은 `README.md`, `docs/test-plan.md`, `docs/design-decisions.md`, `docs/known-limitations.md`, `docs/superpowers/plans/2026-11-03-a1.md`, `tests/fixtures/README.md`, 신규 `docs/a1-validation-2026-11-05-linux.json`이다.

## A0 최종 판정 — 2026-11-05

**완료.** 사용자 재부팅 이후 WSL 조회에는 응답했으나 설치된 배포판이 없어, `wsl.exe --install -d Ubuntu-24.04 --no-launch`로 Ubuntu를 설치했다. README의 시스템 의존성 설치 후 현재 A1 코드가 포함된 작업 트리로 A0를 검증했다.

환경: WSL2, Ubuntu 24.04.5 LTS, x86_64, GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1, clang 도구 18.1.3, libpcap 1.10.4, libnetfilter_queue 1.0.5, GoogleTest 1.14.0. Linux root 계정을 명시적으로 선택해 실행했으며 일반 사용자 권한과 원격 GitHub Actions는 별도 검증하지 않았다.

| 항목 | 실제 결과 |
| --- | --- |
| CMake Debug configure/build | 종료 코드 0 |
| `./build/miniips --help`, `--version` | 종료 코드 0, 도움말과 `miniips 0.1.0` 출력 |
| Debug CTest | 67/67 통과, 실패·skip 0 |
| `cmake --build build --target format-check` | 최초 실패 후 9개 파일 포맷 정리, 최종 종료 코드 0 |
| Release + `MINIIPS_ENABLE_CLANG_TIDY=ON` | 초기 진단 수정 후 빌드 성공, CTest 67/67 통과 |
| Debug + `MINIIPS_ENABLE_SANITIZERS=ON` | 빌드 성공, ASan/UBSan CTest 67/67 통과 |
| README 빌드·실행 안내 | 실행 환경과 실제 결과 반영 |

현재 67개는 55개 GoogleTest와 12개 CTest 작업이다. 동일한 67개를 세 구성에서 확인했으며 201개의 서로 다른 테스트를 만든 것은 아니다. 최종 소스 변경 후 Debug도 다시 빌드·실행했다.

실행한 핵심 Linux 명령은 아래와 같다. 실제 WSL 호출, 초기 실패와 최종 성공 출력을 [Linux 실행 기록](a0-validation-2026-11-05-linux.json)에 보관한다.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel 2
./build/miniips --help
./build/miniips --version
ctest --test-dir build --output-on-failure --no-tests=error
cmake --build build --target format-check

cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_CLANG_TIDY=ON
cmake --build build-release --parallel 2
ctest --test-dir build-release --output-on-failure --no-tests=error

cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel 2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-sanitize --output-on-failure --no-tests=error
```

CTest의 JUnit 결과는 각 빌드 디렉터리의 `a0-results.xml`에 저장했다(Git 제외). 최초 정적 분석에서 enum 기저형, 정수 곱셈의 타입, 테스트의 optional 접근과 의도적인 미지원 enum 값이 지적됐다. 타입 명시와 명확한 분기로 수정하고, 값99를 쓰는 거부 테스트는 이유와 해당 줄의 `NOLINTNEXTLINE`으로 의도를 기록했다. 전역 검사 설정, 기대값과 테스트 수는 변경하지 않았다.

A0 완료는 빌드 기반의 인수 판정이다. A1 테스트는 함께 실행됐지만 별도 단계 인수 검토를 자동 완료하지 않으며 A2는 시작하지 않았다.

이번 검증에서 변경한 파일:

- 타입 명시: `include/miniips/packet.hpp`, `include/miniips/packet_parser.hpp`, `src/packet_parser.cpp`.
- 포맷 및 기존 테스트 표현 정리: `src/main.cpp`, `src/pcap_source.cpp`, `tests/test_cli.cpp`, `tests/test_packet_parser.cpp`, `tests/test_pcap_source.cpp`, `tests/test_cli_pcap.cpp`, `tests/pcap_fixture.hpp`, `tests/fixtures/packet_fixtures.hpp`. `src/packet_parser.cpp`에도 포맷을 적용했다.
- 문서: `README.md`, `docs/design-decisions.md`, `docs/known-limitations.md`, `docs/test-plan.md`.
- 실행 기록 신규: `docs/a0-validation-2026-11-05.json`(환경 복구 전), `docs/a0-validation-2026-11-05-linux.json`(복구 후).

## A0 재검증 — 2026-11-05 (환경 복구 전 기록)

**환경 확인에서 중단, A0 미완료 유지.** 현재 A1 코드가 포함된 작업 트리에서 A0 실행 환경을 다시 확인했다. 과거 기록을 통과로 변경하지 않았다.

- `Get-Command`로 CMake, Ninja, GCC/Clang, clang-format, clang-tidy 및 Docker/Podman을 찾지 못했다. 프로젝트는 Linux 빌드만 지원한다.
- 제한된 실행 환경의 `wsl.exe --list --verbose`는 종료 코드 1을 반환했다. 실행 권한을 확장해 같은 명령을 재시도했으나 역시 종료 코드 1과 `Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG` 오류로 실패했다. 한국어 출력은 인코딩 문제로 깨졌지만 오류 코드는 확인했다.
- 제한된 환경의 서비스 조회도 Service Control Manager 접근 오류로 실패했다. 배포판 설치 여부, Linux 내부 패키지와 WSL 설치/등록 오류의 근본 원인은 확정하지 않았다.
- CMake configure/build, `miniips --help`, CTest는 **미실행**이다. 실행한 테스트는 0개이며, 코드의 컴파일 실패나 assertion 실패를 관측한 것은 아니다.
- 시스템 설치·서비스·방화벽 변경 명령은 실행하지 않았다. WSL 조회 명령 자체가 `Install` 경로의 오류를 반환했다.

현재 결과는 [재검증 기록](a0-validation-2026-11-05.json)에 보관한다. WSL 또는 다른 Linux 환경을 복구한 뒤 README의 빌드·도움말·CTest 명령을 실행해야 한다. A1 완료나 A2 진행 허가로 해석하지 않는다.

## A1 판정 — 2026-11-03 (당시 기록)

**구현 작성, 실행 검증 대기(미완료).** 사용자가 A0를 보류하고 A1을 진행하도록 승인했다. A0 기록을 통과로 바꾸지 않았다.

### 구현된 검증 대상

| 대상 | 작성한 검사 |
| --- | --- |
| PacketParser — 27개 | TCP/UDP 필드·payload, 모든 잘린 prefix, caplen/원본 길이, IHL/Total Length/Data Offset/UDP Length, fragment·미지원 입력, 옵션·padding·바이너리·빈 payload |
| PcapSource — 13개 | 정상/빈/없는/손상 파일, 미지원 링크, micro/nano 시각, callback 예외, snapshot 262144/262145 경계, caplen/원본 길이 분리 |
| 기존 Cli — 7개 | 도움말·버전·오류 분기 유지, PCAP 필수 인자 누락 검사로 갱신 |
| PcapCli — 8개 | 파일 읽기→파싱→메타데이터, 옵션 순서, 손상 패킷 후 계속, 파일 오류 1, 중복·미지원 인자 2, 쓰기/flush 실패 |
| CTest 프로세스 — 12개 | 기존 CLI 6개, fixture 준비 1개, 정상·mixed·빈·손상·미지원 링크 PCAP 5개 |

총 55개 GoogleTest + 12개 CTest 작업 = **기대 등록 수 67개**다. 실제 실행·통과 수는 0개이며 도구 부재로 미실행했다. parser용 고정 바이트 배열과 테스트 중 생성하는 classic PCAP을 사용한다.

### 실제 실행 시도

[원본 결과](a1-validation.json)의 7개 명령은 모두 CommandNotFoundException으로 시작하지 못했다.

| 명령 | 결과 |
| --- | --- |
| cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON | cmake 없음, configure 미시작 |
| cmake --build build --parallel 2 | cmake 없음, 빌드 미시작 |
| .\\build\\miniips --help | 실행 파일 없음 |
| .\\build\\miniips --mode pcap --input build/tests/fixtures/normal.pcap | 실행 파일 없음. fixture도 아직 생성되지 않았다. |
| ctest --test-dir build --output-on-failure --no-tests=error | ctest 없음, 테스트 미시작 |
| cmake --build build --target format-check | cmake 없음, 포맷 검사 미시작 |
| clang-tidy -p build src/packet_parser.cpp src/pcap_source.cpp src/cli.cpp | clang-tidy 없음 |

A0 환경 복구는 이번 요청에서 보류했다. 실제 assertion 실패나 컴파일 오류를 관측한 것이 아니며, 실행 환경 때문에 아직 확인하지 못한 상태다.

### 실제 수행한 파일·정적 확인

- Python 표준 라이브러리로 고정 배열이 TCP 59 bytes, UDP 45 bytes인지, IPv4 Total Length와 헤더 체크섬이 일치하는지 확인했다.
- 프로젝트 인용 include의 대상 파일 존재와 GoogleTest 선언 수 55개를 확인했다.
- 독립 코드 리뷰로 파서 경계·callback 수명·RAII·CMake 연결을 검토했다.
- 리뷰의 stdout 버퍼 flush 오류 경로를 수정하고 회귀 테스트를 추가했다. snapshot 경계 테스트도 보완했다.
- 재검토에서 해당 지적의 코드상 해소를 확인했다. 실행 중 메모리 오류·핸들 누수·실제 출력 동작을 증명한 것은 아니다.

### Linux에서 남은 검증

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --no-tests=error
./build/miniips --help
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input ./build/tests/fixtures/normal.pcap
cmake --build build --target format-check
```

README의 Release·clang-tidy·ASan/UBSan 구성도 실제 실행해야 한다. libpcap 버전별 oversized record·잘못된 snapshot 보정, 실제 파일 핸들 정리, PCAPNG 지원 범위는 별도 확인 대상으로 남긴다.

A1 합격은 위 실행으로 정상 필드와 손상 입력의 무해 처리를 재현한 뒤에만 판정한다. A2는 이번 요청에서 시작하지 않는다.

### A1 변경 파일

신규 15개:

- `docs/a1-validation.json`
- `docs/superpowers/plans/2026-11-03-a1.md`
- `include/miniips/capture_source.hpp`
- `include/miniips/packet.hpp`
- `include/miniips/packet_parser.hpp`
- `src/packet_parser.cpp`
- `src/pcap_source.cpp`
- `tests/check_pcap_cli.cmake`
- `tests/fixture_writer.cpp`
- `tests/fixtures/README.md`
- `tests/fixtures/packet_fixtures.hpp`
- `tests/pcap_fixture.hpp`
- `tests/test_cli_pcap.cpp`
- `tests/test_packet_parser.cpp`
- `tests/test_pcap_source.cpp`

수정 10개:

- `CMakeLists.txt`
- `README.md`
- `docs/design-decisions.md`
- `docs/known-limitations.md`
- `docs/test-plan.md`
- `include/miniips/cli.hpp`
- `src/cli.cpp`
- `tests/CMakeLists.txt`
- `tests/check_cli.cmake`
- `tests/test_cli.cpp`

---

아래는 A0의 당시 기록이다.


## A0 판정 — 2026-10-26

**미완료.** README와 기반 파일은 작성했으나 configure/build, 도움말 실행, CTest 성공이라는 인수 조건을 확인하지 못했다.

| A0 인수 조건 | 현재 결과 |
| --- | --- |
| CMake configure/build 성공 | 미실행: cmake 명령 없음 |
| miniips --help 실행 | 미실행: 빌드된 실행 파일 없음 |
| ctest --test-dir build --output-on-failure 성공 | 미실행: ctest 명령 없음 |
| README 빌드·실행 안내 | 작성, Linux 명령 자체는 미검증 |

## 작성한 테스트

### GoogleTest 단위 테스트 — 7개

| 테스트 | 검증할 동작 |
| --- | --- |
| Cli.HelpShowsSupportedOptions | 도움말, 지원 옵션, 성공 코드, stderr 비어 있음 |
| Cli.VersionIdentifiesProgram | 프로그램 버전 출력, 성공 코드, stderr 비어 있음 |
| Cli.MissingOptionFails | 인자 누락은 2, stdout 없음, stderr 사용법 |
| Cli.UnknownOptionFails | 알 수 없는 옵션은 2와 오류 출력 |
| Cli.FutureModeIsRejected | 아직 미구현인 --mode pcap 거부, 미구현 안내 |
| Cli.ExtraArgumentsFail | --help 뒤 추가 인자를 무시하지 않고 거부 |
| Cli.EmptyOptionFails | 빈 옵션을 거부 |

### CTest 프로세스 통합 테스트 — 6개

`cli.help`, `cli.version`, `cli.missing`, `cli.unknown`, `cli.future_mode`, `cli.extra_arguments`가 실제 miniips 프로세스를 호출하도록 작성했다. 버전 출력 형식, 사용법, 종료 코드 및 출력 스트림을 검사한다. 파일 부재·프로세스 실행 실패·5초 시간 초과를 통과로 취급하지 않는다.

총 13개는 **작성한 테스트 수**다. 현재 통과 수가 아니다. 이 단계에는 패킷·Flow·TCP·룰·Inline·AI 테스트를 미리 만들지 않는다.

## 실제 실행 시도

호스트: Windows PowerShell. 작업 위치: 사용자가 지정한 프로젝트 루트. 아래 명령을 실제 호출했으나 모두 명령/실행 파일 탐색에서 막혀 검사 본체는 실행되지 않았다. 원본 예외 유형과 메시지는 [a0-validation.json](a0-validation.json)에 보관했다.

| 실행한 명령 | 실제 결과 |
| --- | --- |
| cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON | CommandNotFoundException, configure 미시작 |
| cmake --build build --parallel 2 | CommandNotFoundException, 빌드 미시작 |
| .\\build\\miniips --help | 실행 파일 없음, CLI 미시작 |
| .\\build\\miniips --version | 실행 파일 없음, CLI 미시작 |
| ctest --test-dir build --output-on-failure | CommandNotFoundException, 테스트 미시작 |
| clang-format --dry-run --Werror include/miniips/cli.hpp src/cli.cpp src/main.cpp tests/test_cli.cpp | 명령 없음, 포맷 검사 미시작 |
| clang-tidy -p build src/cli.cpp src/main.cpp | 명령 없음, 정적 분석 미시작 |

추가 환경 확인:

- `git status --short`, `git rev-parse --show-toplevel`, `git log -1 --oneline`: Git 저장소가 아니므로 실패했다.
- `Get-Command` 및 알려진 설치 경로 확인: CMake/Ninja/GCC/Clang/품질 도구를 찾지 못했다.
- `wsl.exe --list --verbose`: 종료 코드 1, “시스템에서 파일에 액세스할 수 없습니다.”
- `curl.exe --head --location --connect-timeout 10 --max-time 15 https://cmake.org`: 종료 코드 6, “Could not resolve host: cmake.org”.
- Python으로 C++ 파일의 100자 초과 행을 확인한 결과 0개였다. 이것은 포맷 검사나 컴파일 결과가 아니다.
- Release, ASan/UBSan 및 GitHub Actions: 미실행. Linux 도구체인 및 원격 CI 실행 환경 미확보.

빌드 오류나 assertion 실패가 발생한 것처럼 분류하지 않는다. 현재 관측된 원인은 **도구·실행 환경 부재/접근 오류**다.

## Linux에서 해소할 검증

[README](../README.md)의 의존성 설치 후 다음을 실행한다.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel 2
./build/miniips --help
./build/miniips --version
ctest --test-dir build --output-on-failure --no-tests=error
cmake --build build --target format-check
```

README의 별도 Release·clang-tidy·sanitizer 구성도 확인하고 실제 출력, 테스트 수, 실패 및 미실행 사유를 갱신한다. A0 인수 조건이 통과하기 전에는 완료라고 선언하지 않는다. A1은 사용자가 승인한 뒤에만 시작한다.

## 파일·문서 확인

로컬 Markdown 링크 대상의 존재, 검증 JSON의 형식과 7개 명령의 미시작 상태를 확인했다. 원본 문서 4개의 크기는 최초 확인 값과 동일하며 후속 단계 디렉터리는 만들지 않았다. 신규 텍스트 파일의 줄바꿈은 LF로 정리했다. 이 확인은 C++ 빌드·테스트를 대체하지 않는다.

## 생성 파일 — 19개

- `.clang-format`
- `.clang-tidy`
- `.github/workflows/ci.yml`
- `.gitignore`
- `CMakeLists.txt`
- `README.md`
- `config/.gitkeep`
- `docs/a0-validation.json`
- `docs/design-decisions.md`
- `docs/known-limitations.md`
- `docs/superpowers/plans/2026-10-26-a0.md`
- `docs/test-plan.md`
- `include/miniips/cli.hpp`
- `rules/.gitkeep`
- `src/cli.cpp`
- `src/main.cpp`
- `tests/CMakeLists.txt`
- `tests/check_cli.cmake`
- `tests/test_cli.cpp`
## WSL 설치·검증 재시도 — 2026-11-03

사용자의 설치·검증 지시에 따라 wsl.exe --version, --list --verbose, --install -d Ubuntu-24.04 --no-launch를 직접 실행했다. 세 명령은 모두 종료 코드 1과 “시스템에서 파일에 액세스할 수 없습니다.”를 반환했다. 현재 실행 토큰은 관리자 권한이 아니다. 파일 접근 오류의 정확한 원인은 확정하지 않았다.

이 실행 환경에서는 관리자 권한으로 전환할 수 없어 설치를 계속하지 못했다. Ubuntu 내부 의존성 설치, Linux 빌드와 CTest는 미실행이다. 설치·실행 성공으로 기록하지 않았다. 원본 요약은 [wsl-setup-validation.json](wsl-setup-validation.json)에 보관한다.
