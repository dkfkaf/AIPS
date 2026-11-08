# 설계 결정

## A6 라이브 IDS — 2026-11-08

사용자의 A6 요청·중단 작업 재개 지시에 따라 [설계](superpowers/specs/2026-11-08-a6-design.md)와 [계획](superpowers/plans/2026-11-08-a6.md)을 실행한다. 독립 설계 검토는 중요한 미정 사항 없음으로 끝났다. 아래 기본값은 작성자가 기존 단일 처리 구조에 맞춰 선택한 것이며 개별 사용자 승인으로 주장하지 않는다.

- LivePcapSource는 비차단 Ethernet libpcap 핸들을 RAII로 소유한다. promiscuous off, snaplen262144, immediate mode와 최대100ms의 ppoll 대기를 사용한다. 매 대기 전에 required select timeout을 재조회해 짧은 제한을 적용한다. 이 API 때문에 libpcap 최소 버전을1.9.0으로 올렸으며 현재1.10.4는 그대로 사용했다.
- main의 live 전용 sigaction은 SIGINT/SIGTERM을 sig_atomic_t 요청으로 바꾸고 종료 시 복구한다. handler에서 Engine/pcap/log를 호출하지 않는다. source와 run_cli는 일반 StopRequest callback을 받고 임베딩 프로세스의 신호 정책을 바꾸지 않는다. 바쁜 수집에서도 매 패킷 정지 요청을 확인한다.
- pcap와live가 한 consume/finish 경로로 Engine과 renderer/Publisher를 공유한다. 모드는 EventContext/RunPublication의 명시적 값이며 기본값은 Pcap이다. PCAP의 기존225개 계약을 유지한다.
- 정상 live 중지는 Stopped, 처리 오류는 Aborted, 파일 EOF는 Eof로 구분한다. 정상 live의 capture_complete=false/run_complete=true이며 이후 로그 완료는 독립적이다. source 핸들을 유지한 채 pcap_stats를 읽은 뒤 정리한다. 시각/Flow 만료는 실제 캡처 watermark 기준을 유지하고 무입력 벽시계를 섞지 않는다.
- ps_recv/ps_drop/ps_ifdrop은 네이티브 폭의 원시 카운터다. Engine 처리 수·룰 Drop과 같다고 가정하지 않고 인터페이스 유실 통계의 플랫폼 의존성을 표시한다. API 미지원은 null/unavailable로 기록하며 정상 중지 자체를 실패로 바꾸지 않는다.
- live logger 실패를 한 번 즉시 진단한 뒤 요청 정지/packet-count까지 판정한다. SIGPIPE/SIGXFSZ 격리는 A5 main 정책을 유지한다. human/진단 출력 장애는 중단할 수 있다.
- 실제 수집 검사는 익명 network namespace 안의 전용 veth에만 합성 프레임을 주입한다. 스크립트는 호출 전 namespace ID와 현재 ID가 다를 때만 링크를 생성한다. 주소 자동 생성을 끄고 외부 통신·호스트 인터페이스·방화벽을 변경하지 않는다. 기본 CTest와 권한 있는 실제 검사를 구분한다.

자동 commit/push·A7·AI 구현은 하지 않는다. IPS 완성 뒤 사용자 자체 테스트와 명시적 AI 착수 지시 조건을 유지한다.

## A5 JSONL와 공통 파이프라인 — 2026-11-08

사용자가 승인한 [A5 설계](superpowers/specs/2026-11-07-a5-design.md)와 [계획](superpowers/plans/2026-11-07-a5.md)을 현재 폴더에서 구현한다. 자동 commit/push 없이 기존 변경을 보존한다. 아래 A0~A4 절의 미구현 표시는 각 단계 당시의 기록이다.

- Engine inspect는 로그 I/O 없이 파서·Flow·TCP·룰을 처리하고 원본 span 없는 소유 결과를 반환한다. CLI는 한 결과씩 발행·폐기한다. 만료/EOF/abort에서 방향별 요약을 복사한 뒤 버퍼·룰 배열을 정리하며 종료는 Flow ID로 정렬한다. 마지막 Flow active 통계는 유지한다.
- 설정된 룰 상태 예산 실패는 owned processing_error로 반환해 이미 수집된 만료 기록을 보존하고 엔진을 실패 상태로 고정한다. 해당 패킷의 Allow verdict를 만들지 않고 abort로 정리한다. 호출자는 processing_error를 확인해야 한다. 실제 OOM의 강한 예외 보장은 제공하지 않는다.
- EventPublisher가 이벤트7종을 한 건씩 생성하며 Pass/억제된 match는 alert가 아니다. 논리적 emitted(Pass 포함)/suppressed/detections/Drop 집계와 실제 기록 성공 수는 독립적이다. 오류 정보는 ErrorInfo의 이름 있는 필드로 묶어 같은 타입의 인자 혼동을 줄인다.
- schema_version=1, mode=pcap/enforced=false. 시각은 캡처 UTC microseconds와 timestamp_us 정수이며 문자열은 classic locale을 사용한다. 종료는 watermark, 빈 입력은 null, 지원 범위 밖 문자열 시각은 null/out_of_range다. 외부 메시지4096바이트·줄65536바이트 상한, ASCII/DEL escape·invalid UTF-8 replacement를 적용한다. payload 원문을 기록하지 않는다.
- --log PATH는 Linux O_EXCL/O_CLOEXEC 새 파일만0600 요청해 생성한다. 기존 파일·입력·룰·심볼릭/하드 링크를 보존한다. --log -는 stdout JSONL 전용이고 요약/진단은 stderr다. 옵션이 없으면 기존 콘솔 경로를 유지한다.
- 최초 로그 실패를 고정하고 이후 쓰기를 중단·미기록 집계하지만 나머지 PCAP 판정은 계속해 코드1로 종료한다. standalone main은 --log -의 SIGPIPE와 모든 --log 경로의 SIGXFSZ를 무시해 실제 write 오류로 처리한다. 임베딩 라이브러리는 호출자의 신호 정책을 바꾸지 않는다.
- JSON stats는 생성 시점 log_status_at_emit와 자신을 포함한 성공 수만 표시한다. 미래 flush/close 성공을 예상하는 log_complete를 넣지 않는다. finish 이후 stderr의 logger_summary와 종료 코드가 최종 로그 완료 여부를 확정한다. fsync 내구성·I/O 지연 상한은 보장하지 않는다.
- Git을 바꾸는 스크립트 대신 ignored build-a5-work에 기준 복사본/실행 증거/판단 기록을 보관한다. 삭제하면 미커밋 A5의 근거를 잃으므로 보존한다.

**A0~A8 IPS → 사용자 자체 테스트 → 결과·명시적 지시 확인 → B0 AI** 순서를 유지한다. A6/Inline/AI는 이번에 구현하지 않는다.

## 사용자 진행 결정과 A4 — 2026-11-07

**IPS 먼저 완성(A0~A8) → 사용자 자체 테스트 → 결과 확인과 AI 착수 지시 → AI 모델 개발(B0~B5) → 연동(C단계)** 순서를 사용자가 지정했다. A8의 개발자 검증만으로 B0를 자동 시작하지 않는다. AGENTS.md, PROJECT_SPEC.md, IMPLEMENTATION_PLAN.md, README에 같은 조건을 기록했다. 이 결정은 AI를 제거하는 것이 아니라 사용자 자체 테스트 이후로 착수 시점을 정한 것이다.

사용자는 [기존 A4 설계](superpowers/specs/2026-11-07-a4-design.md)의 KMP 방식을 승인했다. Aho–Corasick은 다중 패턴의 타당한 대안이지만 이번에 도입하지 않으며 실제 성능 우위를 측정한 것으로 주장하지 않는다. 현재 폴더에서 직접 실행하고 기존 변경을 보존하며 자동 commit/push는 하지 않는다.

### 검증과 정책

룰 파일은 깊이/중복 키를 파싱 중 검사하고, 전체 필드/타입/범위/중복 SID를 검증한 뒤 불변 RuleSet으로 만든다. 임의의 Rule 벡터로 검증을 우회할 수 없다. 제한된 파일 전체가 유효해야 하며 disabled 룰도 예외가 아니다. KMP 실패 함수를 한 번 만들고 priority/sid 순서로 검색한다.

packet은 현재 payload, stream은 새 연속 구간과 A3가 허용한 현재 payload 위치에 겹친 패턴을 검사한다. A3가 ByteRange를 제공하므로 시퀀스 해석을 중복 구현하지 않는다. 접두어/접미어 컨텍스트를 포함하되 갭을 가로지르지 않는다. 중복 발행 watermark와 terminal 판정을 분리해 같은 악성 세그먼트의 재전송이 Allow로 뒤집히지 않도록 한다. 순수 ACK나 무관한 새 suffix에 과거 stream 룰을 적용하지 않는다.

대표 match는 관련 영역과 겹치는 가장 큰 end-offset이고 룰당 관측당 이벤트 하나다. 더 앞선 과거 위치도 watermark 이하이면 이벤트를 억제한다. 이는 occurrence별 완전 이력을 보관하지 않는 제한된 기본 억제 정책이다.

### 상태와 CLI

TCP Flow 메타데이터는 max_flows로, 방향별 uint64 배열은32 MiB 기본 예산으로 제한한다. 배열은 첫 stream 이벤트 직전에만 할당한다. 예산 부족을 정상 Allow나 무제한 이벤트로 숨기지 않고 분석 오류로 종료한다. 만료/EOF에 정리하고 원본 payload span은 저장하지 않는다.

--rules는 선택 옵션이고 --rule-state-bytes는 함께 사용해야 한다. JSON 오류는 PCAP을 열기 전에 rule_error로 종료한다. 출력 message는 JSON 문자열 인코딩으로 제어문자를 escape하며 payload 원문은 출력하지 않는다. 실제 Drop·JSONL·AI는 구현하지 않는다. 기존 A3 경미 보류는 이번 범위 밖이다.

최종 리뷰 뒤 현재 payload로 생성할 수 없는 재조립 조합을 직접 API가 거부하도록 보완했다. 허용 구간 길이는 payload 길이를 넘을 수 없고, 새 prefix가 늘 때 첫 새 바이트를 현재 허용 payload가 포함해야 한다. 빈 payload/disabled 방향이 새 구간을 주장할 수도 없다. 콘솔 메시지는 UTF-8 원문을 보관하되 ASCII JSON 표현과 별도 DEL escape로 출력해 C1·Unicode 줄/문단 구분자까지 보호한다. 한글 메시지도 콘솔에서는 Unicode escape로 표시된다.

## A3 — 2026-11-07

사용자가 승인한 [설계](superpowers/specs/2026-11-07-a3-design.md)와 [실행 계획](superpowers/plans/2026-11-07-a3.md)에 따라 현재 폴더에서 직접 구현했다. A0~A2 미커밋 파일의 수정 전 복사본과 작업·검증 로그는 Git 제외인 `build-a3-work/`에 보관한다. 자동 커밋·push와 후속 A4 구현은 하지 않는다.

### 소유권, prefix와 자원

`TcpReassembler`가 flow_id별 두 방향의 데이터와 존재 비트맵을 소유한다. 기본 방향별 첫 65536바이트만 보관·검사하며, 존재하지 않는 위치를 가로질러 prefix를 내보내지 않는다. 새 연속 구간과 누적 prefix는 다음 변경 전까지만 유효한 span으로 반환한다. 콜백에서 받은 원본 payload span은 저장하지 않는다.

데이터가 처음 허용될 때 고정 배열을 지연 할당한다. 글로벌 134217728바이트 예산은 payload+ceil(depth/8) 존재 비트맵을 합산하며 기본 방향당 73728바이트다. 메모리 거부 방향은 같은 Flow 내에서 다시 시작하지 않는다. 깊이 밖 데이터는 제외하고 불완전 이력을 남긴다. metadata/map의 개수는 Flow 한도로 제한하지만 예산이 전체 RSS의 정확한 상한은 아니다.

### 순서와 불완전 상태

SYN의 다음 시퀀스를 기준점으로 삼는다. SYN 없이 첫 payload/FIN을 받으면 midstream이며 뒤늦은 과거 데이터로 기준점을 바꾸지 않는다. 시퀀스 비교는 unsigned 차이와 반 공간의 모호함을 구분한다. first-seen은 pending과 이미 내보낸 prefix 모두에 적용한다. 값이 다른 overlap은 관측당 이벤트 1개이고 원래 바이트를 유지한다. 일시적인 gap_pending은 보충 뒤 사라지지만 영구 갭·충돌·한도·midstream 이력은 최종 결과에 남긴다.

FIN은 데이터 바이트가 아닌 종료 경계다. 기존 데이터보다 앞선 새 FIN 세그먼트는 거부하고, 먼저 받은 FIN 뒤로 새 데이터가 늘어나지 않게 한다. 잘못된 SYN+FIN/SYN+RST는 제어 부작용도 실행하지 않는다. 동일 SYN은 유지하고 다른 SYN은 session_reuse로 해당 방향을 중단한다. RST는 두 방향의 배열을 해제하고 같은 ID로 재시작하지 않는다. 이는 완전한 TCP 수신 상태 머신이 아니다.

새 ID는 A2가 처음 관측한 순서대로 증가해야 한다. 추적 거부/정리한 ID를 나중에 재시작하지 않도록 고정 크기의 최고 ID 값 하나를 사용한다. ID 거부 이력을 무제한 목록으로 저장하지 않는 선택이며, 직접 API 사용자도 모든 tracked TCP 관측을 순서대로 전달해야 한다.

### 수명과 출력

FlowTable의 observe/expire에 기본값이 빈 동기 만료 sink를 추가해 기존 호출을 유지했다. 삭제 직전에 재조립기를 최종화하고 해제한다. 콜백 예외 때 이전에 삭제한 Flow의 expired 집계는 유지하고 해당 Flow는 남긴 채 예외를 전파한다. CLI는 이를 런타임 오류로 종료한다. 종료 이벤트 sink 실패도 성공으로 숨기지 않고 재조립 배열을 정리한다. sink 내부 재진입과 뷰 보관은 금지한다.

CLI는 기존 패킷·Flow 필드 뒤 재조립 메타데이터와 별도 콘솔 이벤트를 출력한다. 원문 payload·룰·JSONL·실제 차단은 추가하지 않았다. EOF의 재조립 active=0/memory_bytes=0은 명시적인 정리 이후 값이고 Flow active는 마지막 캡처 시각의 통계다. stream_closed는 관측 FIN까지의 연속성일 뿐 전체 검사 완료 표시가 아니다.

최종 독립 리뷰 뒤에는 RST로 이미 해제한 데이터를 pending으로 다시 계산하지 않게 하고, 시작 SEQ뿐 아니라 FIN/세그먼트 끝의 반 시퀀스 공간 경계도 검사하도록 보완했다. 회귀 3개 RED→GREEN과 세 구성 각각 146/146을 확인했다. 경미 보류 2건과 실제 실행 증거는 [검증 기록](test-plan.md)에 연결한다.

## A2 — 2026-11-06

사용자가 승인한 [설계](superpowers/specs/2026-11-05-a2-design.md)와 [계획](superpowers/plans/2026-11-06-a2.md)에 따라 현재 AIPS 폴더에서 직접 구현했다. 기존 A0/A1 미커밋 변경을 보존하기 위해 수정 예정 파일을 먼저 복사했고, 자동 커밋·push는 하지 않았다. 작업 기록과 원본 검증 자료는 이미 Git 제외인 `build-a2-work/`를 사용했다.

### 키와 방향, 보관 상태

숫자 IPv4·포트 endpoint를 정렬한 5-tuple과 명시적 해시·동등 비교로 한 Flow를 식별한다. 정렬 순서와 통계 방향은 분리하며 처음 관측한 source를 fwd로 유지한다. 같은 endpoint의 양방향은 구별할 수 없어 fwd로 집계한다. ID는 테이블의 성공한 생성 횟수를 사용하는 양의 uint64로, 만료 후 재등장한 키에 새 ID를 준다.

방향별 IP 전체 길이 합계·패킷 수·IAT·TCP flag, 실제 캡처 시각의 최소/최대와 관측 TCP 상태만 보관한다. 패킷·payload·가변 길이 스트림 버퍼는 보관하지 않는다. 외부에는 스냅샷 값을 복사해 반환한다. 기존 엔트리는 복사본에서 checked counter 연산을 마친 뒤 반영해 부분 갱신을 피한다.

### 시간과 용량

기본 max_entries=10000, idle_timeout=120초이며 설정 구조체와 CLI 옵션으로 조절한다. 만료 시계는 관측한 캡처 시각의 최댓값이다. 역순 시각은 시계를 되돌리지 않고 현재 논리 시각에 활동한 것으로 처리하되 캡처 최소/최대는 따로 유지한다. 유휴 간격이 설정값 이상이면 lookup 전에 제거한다. 잘못된 시각·소비 메타데이터는 상태 변경 전에 거부하고, malformed frame의 유효한 캡처 시각은 CLI에서 expire에 전달한다.

용량이 가득 차면 기존 키는 계속 갱신하고 새 키만 거부한다. 거부 횟수와 untracked 표시를 남긴다. EOF는 마지막 관측 시각의 상태를 요약하고 가상의 시간을 더해 전부 만료시키지 않는다. 순회 기반 만료는 단순성과 고정 상태 검증을 택한 승인된 절충이며 O(n) 비용을 한계로 남긴다.

### TCP·CLI·검증

TCP는 SYN/SYN-ACK/최종 ACK의 방향과 FIN/RST를 관측하는 휴리스틱이다. 시퀀스 번호·완전한 연결 정상성을 판정하지 않는다. FIN/RST만으로 엔트리를 즉시 제거하지 않는 설계를 유지하므로 같은 tuple의 빠른 재접속을 구분하지 못할 수 있다.

CLI는 기존 메타데이터 뒤에 ID·방향·방향별 패킷/바이트를, EOF에 Flow 요약을 추가한다. 새 옵션은 양의 정수·중복·표현 범위를 검증하며 초를 마이크로초로 바꾸기 전에 오버플로를 확인한다. EOF 0, 런타임 오류 1, 인자 오류 2의 계약을 유지했다. 용량 거부는 추적 누락이며 패킷 DROP으로 표현하지 않는다.

테스트를 먼저 작성해 없는 인터페이스의 빌드 실패와 기존 CLI에서의 실제 assertion 실패를 확인했다. 이후 기존 67개와 새 34개를 모두 통과시켰다. 정적 분석의 테스트 helper 인자 경고는 TcpMetadata 값 타입으로 정리해 기대값을 유지했다. 의도적 값255 입력의 enum 범위 경고만 해당 테스트 줄에 이유를 적어 제외했다.

fresh-context read-only 리뷰에서 수정 요구는 없었다. Debug·Release/clang-tidy·ASan/UBSan의 101개씩과 포맷 검사가 통과했고, 직접 생성 PCAP으로 동일 ID·정확한 만료 경계·용량 거부를 재현했다. [실행 기록](a2-validation-2026-11-06.json)에 소스·fixture·로그 해시와 실제 출력을 남긴다. 후속 A3는 구현하지 않았다.

## A1 인수 검토 완료 — 2026-11-05

사용자는 A0 완료 보고의 다음 단계인 기존 A1 완료 기준 검토를 요청했다. 오프라인 PCAP 로드, Ethernet/IPv4/TCP/UDP 필드 파싱, 손상 입력 처리와 메타데이터 출력을 검토 범위로 삼았다. F-01의 live 수집은 A6, NFQUEUE 입력은 A7의 범위로 유지했다.

생산 코드의 길이 검사 순서, big-endian 바이트 읽기, IP 길이 안으로 제한한 payload, 콜백 뷰의 수명과 unique_ptr의 pcap_close 경로를 읽고 기존 테스트에 대조했다. 새 기능이나 추가 코드 수정이 필요한 차단 사유는 발견하지 못했다.

전체 Debug 테스트 67개와 A1 관련 ASan/UBSan 테스트 54개를 새로 실행했다. 별도 빌드 디렉터리의 고정 PCAP 5종을 실제 CLI로 재생해 정상 필드, 손상 패킷 후 계속 처리, 빈 파일, 컨테이너 손상·미지원 링크의 오류 종료를 확인했다. 손상 파일과 미지원 링크의 종료 코드 1은 예상된 거부 동작이며 테스트 실패로 집계하지 않는다.

정상 PCAP은 기존 비특권 시스템 계정 nobody(uid 65534)에서도 실행했다. 사용자 계정·비밀번호를 새로 만들지 않았으며 이 한 건의 결과를 전체 비특권 개발 환경의 검증으로 취급하지 않는다.

이번 요청에서는 코드·테스트·빌드 설정을 변경하지 않고 인수 판정과 오래된 미실행 안내를 갱신했다. [A1 실행 기록](a1-validation-2026-11-05-linux.json)에 실제 명령·출력·소스와 fixture 해시를 남긴다. A1은 완료이며 다음 A2 구현은 사용자 지시 후 진행한다.

## A0 실행 검증 완료 — 2026-11-05

사용자의 WSL 복구 및 재부팅 후 Ubuntu 배포판이 아직 없어 설치를 이어서 수행했다. Ubuntu 24.04의 시스템 패키지로 README 의존성을 설치하고 현재 작업 트리에서 검증했다. Linux root 계정을 사용한 초기 설치·검증이며, 사용자 이름이나 비밀번호를 임의로 만들지 않았다.

첫 Debug 빌드와 기존 67개 테스트는 통과했다. 추가 품질 검사에서 발견한 다음 항목만 정리했다.

- 기존 clang-format 설정으로 지적된 9개 파일의 포맷을 적용했다.
- `PacketLayer`와 `ParseError`의 기저형을 `std::uint8_t`로 명시했다. 내부 enum의 표현 크기는 바뀌지만 이름·열거값은 유지되며, 영향을 받는 모든 빌드 대상을 다시 컴파일했다.
- IPv4/TCP 헤더 길이 곱셈을 `std::size_t`에서 수행하도록 명시했다. 원래도 4비트 필드의 최대값이 60 bytes이므로 실제 오버플로를 관측한 수정으로 보고하지 않는다.
- TCP 메타데이터 optional을 확인하는 테스트는 fatal failure가 명확한 분기로 보이도록 작성했다. 기존 필드 검증과 테스트 수를 유지했다.
- 알 수 없는 계층 값99를 전달하는 기존 테스트는 입력 거부를 검증하기 위한 의도적 사례다. 생산 코드에 테스트 전용 enum을 추가하지 않고, 해당 줄에만 이유와 `NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)`를 기록했다. 전역 검사 목록과 warnings-as-errors는 바꾸지 않았다.

최종 Debug, Release/clang-tidy 및 ASan/UBSan의 CTest는 각각 67개 전부 통과했다. A0의 네 인수 조건을 충족했으며, [실행 기록](a0-validation-2026-11-05-linux.json)에 최초 실패와 최종 결과를 함께 남긴다. 후속 기능을 구현하거나 A1/A2의 진행 상태를 자동 승인하지 않는다.

## A0 재검증 — 2026-11-05 (환경 복구 전 기록)

사용자의 현재 검증 요청에 따라 A0 실행 환경을 다시 확인했다. A1 코드와 기존 테스트를 유지하고 기능 구현은 변경하지 않았다. Windows 네이티브 빌드로 목표 환경을 바꾸지 않는다.

WSL 조회를 제한된 환경과 실행 권한을 확장한 환경에서 각각 시도했다. 후자도 `Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG`로 실패했고 빌드 도구도 PATH에서 찾지 못해, A0를 미완료로 유지한다. 설치/등록 오류의 근본 원인은 미확정이며 시스템 복구를 수행한 것으로 기록하지 않는다. 실제 결과는 [검증 기록](a0-validation-2026-11-05.json)에 남긴다.

## A0 — 2026-10-26

### 범위와 인터페이스

사용자가 승인한 A0만 작성했다. 기존 네 문서는 수정하지 않았다. `include/miniips/`, `src/`, `tests/`, `rules/`, `config/`, `docs/`를 구성했으며 rules/config는 자리만 확보했다.

CLI는 `miniips::run_cli(std::span<const std::string_view>, std::ostream&, std::ostream&)` 자유 함수로 작성한다. 인자는 프로그램 이름을 제외하며 함수 호출 중 유효해야 한다. 비소유 뷰를 저장하지 않는다. 숨길 상태나 다형성이 없어 클래스를 추가하지 않았다. main의 표준 컨테이너가 뷰 목록을 소유하고 원본 argv의 수명 안에서 호출한다.

정확히 한 개의 `--help` 또는 `--version`만 지원한다. 성공 출력은 stdout/0, 잘못된 인자는 stderr/2다. `--mode`를 포함한 후속 단계 옵션은 처리하지 않는다. 도움말에도 패킷 처리가 미구현임을 표시한다. 버전은 CMake 프로젝트의 `0.1.0`에서 컴파일 정의로 전달한다.

### 빌드와 의존성

대상은 명세대로 Linux와 GCC/Clang이며 CMake >= 3.22, C++20, 표준 확장 비활성화를 사용한다. Windows용 우회 구현은 추가하지 않았다.

libpcap/libnetfilter_queue는 pkg-config imported target, nlohmann/json·spdlog·GoogleTest는 시스템 CMake package를 사용한다. configure에서 네트워크 다운로드를 하지 않으며 필수 패키지가 없으면 실패한다. A0에서는 의존성 탐색·링크 기반만 마련하고 라이브러리의 패킷 처리 API는 호출하지 않는다.

GoogleTest 대상과 실제 실행 파일을 호출하는 CTest 스크립트를 구분한다. 후자는 종료 코드와 stdout/stderr를 검사하고 실행 파일 부재·실행 실패·시간 초과도 실패 처리한다. 검증용 mock이나 성공만 반환하는 테스트는 없다.

포맷은 Google 기반 4칸/100자다. clang-tidy 및 ASan/UBSan은 독립 옵션으로 켠다. CI에는 Debug/Release와 sanitizer 작업을 구성했다.

### 환경 때문에 적용하지 않은 절차

최초 폴더에는 문서 네 개만 있었으며 Git 저장소가 아니었다. 사용자가 지정한 프로젝트 루트에서 새 파일을 작성했다. worktree 생성, Git 초기화, 커밋, 원격 push는 하지 않았다.

현재 Windows에서 CMake·Ninja·컴파일러를 찾지 못했고 WSL은 접근 오류로 실행되지 않았다. 다운로드도 DNS 해석에 실패했다. 기능 계약을 바꾸거나 테스트를 생략한 성공 판정을 하지 않는다. A0는 실제 빌드·테스트 증거가 확보될 때까지 미완료다.

## A1 — 2026-11-03

### 진행 허가와 현재 상태

사용자는 “A0은 보류하고 A1으로 진행하자”라고 명시적으로 지시했다. AGENTS.md의 사용자 명시적 범위 요구 우선순위에 따라 이번 요청에서는 A0 완료를 요구하는 일반 진행 규칙에 예외를 적용했다. A0는 보류·미완료로 유지하고, A1 코드와 테스트를 작성했다. 빌드 환경 복구, A2 이후 구현은 진행하지 않는다.

기존 PROJECT_SPEC.md/IMPLEMENTATION_PLAN.md/CODING_STYLE.md/AGENTS.md의 기능 계약과 일반 단계 규칙은 변경하지 않았다. 이번 지시는 후속 단계의 자동 진행 허가가 아니다.

### 패킷 파서 계약

- PacketEnvelope는 캡처 바이트 span, 원본 프레임 길이, 마이크로초 캡처 시각과 Ethernet 시작점을 전달한다.
- parse_packet은 ParsedPacket 또는 ParseError를 반환한다. 헤더를 구조체 포인터로 매핑하지 않고 검증된 범위의 big-endian 바이트를 읽는다.
- ParsedPacket의 payload는 비소유 뷰다. 원본이 유효한 동안에만 사용한다. CLI는 PCAP 콜백 안에서 즉시 출력하고 뷰를 저장하지 않는다.
- caplen > 원본 길이는 잘못된 입력, caplen < 원본 길이는 보수적으로 잘린 캡처로 구분한다. padding만 누락된 경우도 건너뛴다.
- IPv4 IHL/Total Length, TCP Data Offset, UDP Length를 검사한다. IPv4 Total Length 밖의 Ethernet padding은 payload에 포함하지 않는다.
- 비조각 UDP Length는 IP payload 길이와 같아야 한다. 작은 UDP Length 뒤의 여분 IP 바이트를 정상으로 해석하지 않는 첫 구현 정책이다.
- IPv6·ARP·VLAN·미지원 링크/IP 프로토콜·fragment는 실패 이유로 구별한다. IPv4 예약 flag도 거부한다.
- IPv4/TCP 옵션의 길이는 처리하되 내용·체크섬·응용 프로토콜은 검사하지 않는다.

### PCAP 소스와 오류

read_pcap은 libpcap의 offline API와 pcap_next_ex를 사용한다. unique_ptr의 deleter가 pcap_close를 호출하므로 정상 EOF, 읽기 실패, 콜백 예외에도 정리 경로가 있다. 실제 핸들 누수 검사는 아직 하지 못했다. 사용 API에 맞춰 libpcap 최소 버전을 1.5.1로 명시했다.

libpcap에 마이크로초 정밀도를 요청하고 음수·잘못된 소수부·정수 오버플로를 거부한다. 나노초 파일의 정밀도는 마이크로초로 줄어든다. libpcap이 보고하는 snapshot을 262144 bytes 이하로 제한하고 전달된 caplen도 검사한다. 파일 안의 잘못된 snapshot이나 oversized record를 libpcap이 보정·거부하는 방식은 버전별 실제 검증이 필요하다. "-"는 stdin 대기 방지를 위해 거부한다.

개별 패킷 오류는 stderr의 원인과 skipped 수로 남기고 다음 레코드를 처리한다. 읽기를 계속할 수 없는 파일 오류는 종료 코드 1이며 성공 summary를 내지 않는다. EOF 완료 0은 모든 패킷의 분석 성공을 의미하지 않는다.

### CLI와 테스트

기존 도움말/버전을 유지하고 --mode pcap --input PATH만 추가한다. A5의 --rules/--log/JSONL 이벤트와 live/inline은 미구현이다. 출력은 주소·포트·시각·IP 길이·TCP 시퀀스/ACK/flags·payload 길이이며 원시 payload는 제외한다.

A0 테스트 중 “PCAP 모드 미구현”을 가정하던 항목만 “PCAP 입력 인자 누락” 검사로 갱신했다. 기존 테스트를 삭제하거나 기대 성공만 반환하는 mock을 만들지 않았다.

독립 정적 리뷰에서 종료 전 버퍼 flush 실패가 늦게 발견되는 경로를 확인했다. 성공 반환 전에 stdout/stderr를 flush하고 상태를 확인하도록 수정했으며 sync() 실패 회귀 테스트를 추가했다. 수정 재검토는 코드상 해소 확인이며 실행 통과 증거는 아니다.

고정 바이트와 별도 PCAP 인코더를 사용하며 실제 캡처·대용량 데이터는 추가하지 않는다. 테스트 파일은 고유 임시 디렉터리 또는 CMake 빌드 디렉터리에서만 생성한다.
