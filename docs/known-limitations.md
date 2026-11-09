# 알려진 한계

## A8 종합 범위와 남은 한계 — 2026-11-09

- 선택된 격리 TCP/UDP 합성 트래픽에서 실제 packet/stream 차단을 확인했다. HEL이 먼저 도착한 뒤 LO를 차단하므로 이미 지난 prefix를 소급 차단하지 않는다. IPv6/fragment/암호화/OS 정규화·모든 공격 탐지 또는 운영망 보호 보장은 아니다.
- reader 정지 후 UDP16384개로 수신 소켓 압박을 만들고 오류 종료·overflow 통계·종료 정리를 확인했다. 모든 전송이 사용자 공간 callback으로 전달되지는 않는다. 애플리케이션 exactly-once는 받은 유효 ID의 시도 범위이며 무손실/자동 복구/큐 가용성 보장이 아니다. 커널 /proc queue 스냅샷은 원문만 저장하며 열을 추정해 해석하지 않았다.
- A7의 overflow 분류 누락은 poll SO_ERROR와 recvmsg ENOBUFS에서 보완했다. 오류 주입3개와 실제 압박을 확인했지만 모든 poll/recv/close 실패·실제 OOM·커널 crash를 주입하지 않았다. 정상 종료 fallback Drop의 개별 receipt 공백은 계속 적용한다.
- 성능은 합성 UDP/128 Flow/일곱 합성 룰의 Release PCAP CLI 경로다. 프로세스 시작·PCAP 읽기·룰·로그 직렬화·관측 대기를 포함한다. CPU 고정/캐시 제거를 하지 않았고 반복 warm-up 후 측정했다. wall/N은 평균 환산 비용이며 패킷별 p99·wire 처리량·탐지 정확도가 아니다. 실시간 지속 부하 성능은 별도다.
- 기록한 RSS는 GNU time이 수집한 개별 자식의 최대값이다. TCP/룰 배열 예산은 전체 프로세스 RSS 상한이 아니다. 고정 시드12000 손상 입력은 추가 범위 확인이며 exhaustive fuzzing/보안 완전성 증명이 아니다.
- root WSL 경로의 실제 검증을 실행했다. 가이드의 sudo 환경 변수 보존 경로·다른 커널/CPU·원격 CI는 별도 검증하지 않았다. 기존 A5/A6 경미 보류(최종 human 출력 실패 시점, 일부 human unavailable 통계, 지속 부하 신호 회귀)는 유지한다.
- AI/UDS/학습 데이터셋·모델은 개발하지 않았다. A단계 완료 후에도 사용자 자체 테스트 결과 확인과 명시적 AI 착수 지시가 필요하다.

아래 A0~A7 한계는 각 단계 당시 기록이다. 특히 A7의 TCP 실제 검증 미실행/overflow 통계 보류는 위 A8 결과로 보완됐다.

## A7 적용 한계 — 2026-11-08

- 실제 허용/차단의 증거는 임시 격리망의 선택된 IPv4 UDP 트래픽과 룰에 한정한다. 모든 TCP 공격/IPv6/fragment/VLAN/암호화/OS 정규화를 처리하는 상용 IPS가 아니다. 실제 TCP stream 차단 일반화·처리량/지연·포화/강제 유실 실험은 미실행이다.
- --enable-inline과 root/CAP_NET_ADMIN이 필요하다. 바이너리는 방화벽을 바꾸지 않지만 기존 운영망 queue에 붙이면 실제 동작에 영향을 줄 수 있다. 예시는 격리 환경에서만 사용한다.
- 미지원/파싱 실패는 ACCEPT하므로 미검사 트래픽이 통과할 수 있다. processing_error/예외의 fallback DROP은 정상 트래픽도 막을 수 있다. Flow/TCP 제한 경고를 완전한 검사로 해석하지 않는다.
- nft bypass/queue fail-open을 켜지 않은 시험 정책에서는 listener 부재/종료가 차단으로 이어진다. 큐/프로세스/커널 장애의 fail-open을 보장하지 않는다. 정상 중지 때도 kernel pending을 모두 처리한다고 주장하지 않는다.
- “한 번”은 유효 callback ID에 대한 verdict 시도다. ID 손상·수신 손실·전송 실패·프로세스 crash까지 전역 exactly-once 성공을 보장할 수 없다. API 제출 성공이 후속 모든 체인의 최종 전달 보증은 아니며 수신기 관측과 구분한다.
- close는 run-scope callback 수명을 보호하기 위해 After를 해제한다. close 중 callback의 fallback Drop은 최종 카운터에 포함해도 개별 receipt가 없을 수 있다. final actual Drop 수와 개별 Drop 줄 수가 반드시 같지는 않다.
- 종료 중 판정 실패/ID 누락은 반복 close와 CLI의 오류 결과에 반영한다. 실제 큐를 열지 않는 링크 시점 오류 주입으로 성공 fallback·전송 실패·ID 누락·CLI 종료 상태를 검사했다. 모든 커널 장애를 주입한 결과는 아니다.
- inline timestamp는 사용자 공간 수신 시각이다. 커널 최초 도착 시각과 차이가 있으며 PCAP/live capture 시각과 의미가 다르다. 원본 길이는 legacy API가 제공한 복사 길이를 사용하고 IP total length로 불완전을 확인한다. 대형/GSO/복사 한계 입력을 검사 완료로 주장하지 않는다.
- libnetfilter_queue handle API는 upstream의 legacy/deprecated 경로다. 지원되는 설치1.0.5 API만 사용하고 신규 libmnl API와 섞지 않는다. 전송 실패/ENOBUFS/oversize는 오류 종료하며 실제 모든 하위 오류 주입은 미실행이다.
- A7 리뷰 경미 보류1건: recvmsg의 ENOBUFS나 ppoll의 POLLERR 경로는 receive_errors 증가·오류 종료하지만 overflow_errors 원인 분류가 빠질 수 있다. 강제 overflow 진단 실험과 분류 개선은 이번 범위에 포함하지 않았다.
- 동기 로그·human 출력이 막힐 때의 시간 상한과 fsync·OOM 정리는 보장하지 않는다. 로그 오류는 verdict 후 처리하며 이후 판정을 계속하지만 human 출력 예외는 중단한다. 이전 A5/A6 경미 보류도 계속 적용한다.

## A6 적용 한계 — 2026-11-08

- Linux Ethernet/DLT_EN10MB 수동 IDS다. 모든 룰 Drop은 시뮬레이션이고 실제 네트워크 차단은0이다. NFQUEUE/A7·AI는 구현하지 않았다. 기존 IPv6/fragment/VLAN·TCP 제한도 유지한다.
- 인터페이스를 명시해야 하며 raw 캡처 권한이 필요하다. promiscuous off로 선택 인터페이스에서 보이는 프레임만 분석한다. any/cooked와 selectable fd가 없는 장치는 거부한다. libpcap<1.9.0은 이제 빌드 대상이 아니다.
- 무입력 정지 확인 대기는 최대100ms지만 동기 I/O·현재 처리·종료 정리 전체의 시간 상한은 아니다. 출력 소비자가 멈춰 write가 막히면 Ctrl+C 뒤 종료도 지연될 수 있다. fsync 내구성·치명적 OOM 정리를 보장하지 않는다.
- logger 실패 후에도 요청 정지/packet-count까지 탐지를 계속하지만 기록되지 않은 결과가 생긴다. 즉시 log_error와 최종 log_complete/종료 코드를 확인해야 한다. human 출력 실패는 수집 자체를 중단할 수 있다.
- capture_complete는 EOF 지표라 live에서는false다. run_complete=true도 정해진 관측 창의 정상 정지일 뿐 네트워크 전체 검사 완료가 아니다. 정상 stop 뒤 버퍼에 남은 미전달 패킷을 완전히 drain한다고 주장하지 않는다.
- capture ps_recv와 실제 처리 수는 다를 수 있다. ps_drop은 캡처 버퍼 유실이며 룰 Drop과 합치지 않는다. ps_ifdrop0은 미지원일 수 있다. 네이티브 폭 원시 카운터의 장기 wrap을 보정하지 않는다. API 미지원이면 null/unavailable이다.
- 유휴 Flow 만료는 실제 캡처 watermark 기준이다. 무입력 시간 동안 정기 벽시계 만료나 주기 통계를 추가하지 않았다. 다음 패킷 또는 정지에서 정리한다.
- 라이브러리를 임베딩하면 호출자가 정지 요청과 신호 정책을 제공해야 한다. standalone main의 신호 처리 복구와 실제 프로세스 검사는 별개다. SIGINT/SIGTERM 정지 시 해당 캡처 창은 한 번만 마무리한다.
- 실제 캡처 유실을 강제로 유발하는 부하/성능 실험, 실제 미지원 stats 장치·장치 제거·메모리 부족·close 실패 주입은 미실행이다. 권한 있는 통합은 별도 임시 namespace/veth에서 검사하고 호스트 방화벽을 변경하지 않는다.
- A5 경미 보류3건과 아래 이전 단계 한계는 계속 적용한다.

### A6 독립 리뷰 경미 보류3건

1. JSON stats는 최종 human 요약/flush보다 먼저 발행된다. 그 뒤 human 출력이 실패하면 run_complete=true가 남아도 종료 코드는1이다. 생성 시점의 처리 종료 상태로 읽고 최종 출력 성공은 종료 코드로 확인해야 한다.
2. human capture_summary는 status=unavailable일 때도 원시 필드를0으로 표시한다. 실제0으로 해석하지 말고 status를 먼저 확인한다. JSONL은 이때 null이며 오류 이유를 함께 기록한다.
3. active SIGINT 실험은10프레임 burst 후 정지이며 지속 송신 부하 중 정지의 회귀를 보장하지 않는다. 구현은 매 패킷 요청을 확인하지만 지속 부하/처리량 검증은 미실행이다.

## A5 적용 한계 — 2026-11-08

- 오프라인 PCAP의 JSONL 통합이다. 모든 drop은 시뮬레이션(enforced=false), actual_drop_packets=0이다. live/Inline/AI/IPC와 실제 차단 성능은 구현·검증하지 않았다. A0~A8 이후 사용자 자체 테스트와 AI 착수 지시를 기다린다.
- 원시 payload를 기록하지 않지만 주소·포트·룰 메시지 등 메타데이터가 포함된다. 새 파일만0600 요청하며 Windows 마운트/ACL의 접근 통제를 POSIX 권한 검사와 동일하게 보장하지 않는다. 부모 경로의 신뢰·디스크 내구성·로그 회전은 관리하지 않는다.
- 동기 I/O 지연 상한, fsync 전원 장애 내구성, 실제 OOM에서 최종 이벤트/통계 발행을 보장하지 않는다. 부분 쓰기는 마지막 JSON 줄을 손상시킬 수 있다. 실패 뒤 재시도·이후 append·파일 삭제는 하지 않는다.
- JSON stats의 log_status_at_emit=ok는 생성 시점 상태다. 이후 flush/close가 실패할 수 있어 최종 logger_summary의 log_complete와 종료 코드를 확인해야 한다. 정상 코드0도 skipped/rejected/incomplete=0을 뜻하지 않는다.
- standalone --log -는 닫힌 stdout의 SIGPIPE를, 모든 --log 경로는 파일 크기 제한의 SIGXFSZ를 쓰기 오류로 처리한다. 임베딩한 run_cli/EventLogger 호출자는 프로세스 신호 정책을 직접 관리해야 한다. borrowed stream은 닫지 않는다. 파일 FD의 close 오류는 검사하지만 실제 장치 close 장애 주입은 미실행이다.
- 결과는 원본 span을 소유하지 않고 종료 배치는 max_flows, 매치 배치는 최대 룰 수로 제한하지만 전체 RSS를 제한하지 않는다. 종료 Flow metadata는 마지막 active 통계를 위해 엔진 소멸까지 유지한다. 처리 예산 실패 뒤 inspect는 거부한다.
- detections는 중복 억제 후 alert/drop 매치 수다. emitted는 Pass 포함, suppressed는 대표 매치 수이며 전체 문자열 occurrence 수가 아니다. stream_window_available은 제한된 stream window의 존재일 뿐 전체 트래픽 검사 완료가 아니다.
- 기존 A3/A4 경미 보류와 IPv6/fragment/TCP gap·overlap·depth 등의 검사 한계는 계속 적용된다. 아래 절들은 각 단계 당시의 이력이다.

### A5 독립 리뷰 경미 보류3건

1. flow/created의 packet_number와 direction은 null이다. 생성 패킷은 같은 flow_id의 verdict와 연결할 수 있으나 패킷 번호만으로 조회하면 생성 이벤트가 제외된다. 종료 이벤트의 최초 관측 방향 정책은 유지한다.
2. 직렬화/줄 상한 실패도 로거 전체를 실패 상태로 고정해 이후 borrowed stream flush를 생략한다. 같은 sink에 다시 접근하지 않는 승인 정책을 유지하므로 이전 수락 레코드가 스트림 버퍼에 남을 수 있다. 최종 코드1/log_complete=0을 확인해야 한다.
3. C++ 공개 LoggerConfig에서 max_line_bytes를65536보다 크게 지정할 수 있다. CLI는 이 옵션을 노출하지 않고65536을 사용하며 내장 발행기도 작은 메타데이터만 생성한다. 직접 라이브러리 호출자의 사용자 지정 상한까지64 KiB로 강제하지 않는다.

## A4 완료 당시 기록 — 2026-11-07

- 리뷰 중요 문제2건 수정 뒤 Debug·Release/clang-tidy·ASan/UBSan에서 각각184/184와 포맷 검사가 통과했다. [실행 증거](a4-validation-2026-11-07.json)와 [테스트 기록](test-plan.md)에 실제 결과를 기록했다. 경미 리뷰3건은 아래에 보류한다.
- KMP는 각 룰의 관련 영역을 다시 검색한다. 최대1024룰을 허용하지만 그 규모의 처리량/지연/RSS 또는 AC 대비 성능은 측정하지 않았다.
- 룰은 printable ASCII의 대소문자 구분 content만 지원한다. 정규식·바이너리 패턴·응용프로토콜 해석·암호화 해제는 하지 않는다. stream+udp/any는 로딩 단계에서 거부한다.
- stream 검사는 A3의 제한된 first-seen prefix다. midstream/gap/depth/memory 제한은 기존 reassembly 출력에 남는다. no-match Allow와 stream_evaluated가 전체 세션/보안 검사 완료를 뜻하지 않는다.
- 중복 이벤트 억제는 Flow/방향/SID별 최대 발행 end-offset이다. 뒤의 match를 먼저 발행한 뒤 앞쪽 과거 위치를 다시 관측하면 그 이벤트도 억제한다. terminal Drop/Pass 판단은 유지한다.
- watermark 예산은 uint64 배열만 계상한다. 파일/룰/문자열 제한이 로더·KMP 자료를 제한하고 Flow 개수가 map 메타데이터를 제한하지만 전체 프로세스 RSS의 정확한 상한은 아니다.
- 룰 파일/상태/출력 오류는 분석을 실패로 종료한다. 현재는 PCAP 콘솔 시뮬레이션이며 NFQUEUE verdict 의무·live·A5 JSONL은 후속 단계다.
- 사용자 결정에 따라 IPS A0~A8 완료와 사용자 자체 테스트·AI 착수 지시 전에는 B0/AI 개발을 시작하지 않는다.
- `stream_evaluated=1`은 관련 stream window가 있다는 의미다. 포트 조건 불일치나 앞 packet terminal로 실제 stream 검색이 생략돼도1일 수 있으므로 실제 검사한 룰 수로 해석하면 안 된다.
- 알 수 없는 필드/중복 키는 거부하지만 오류 메시지에 실제 키 이름이 빠질 수 있다. 룰 인덱스와 일반 원인은 표시한다.
- 실제 시스템 std::bad_alloc은 일반 capture_error로 보고된다. watermark 갱신 뒤 이벤트 벡터 할당이 실패하면 직접 API 재시도 시 발행되지 않은 이벤트도 억제될 수 있다. CLI는 첫 예외에서 종료하며 그 이후 같은 객체 재시도의 원자성을 보장하지 않는다. 이 경로는 정적 리뷰 근거이고 실패 주입 실험은 자동 승인 검토의 사용량 한도로 미실행이다.

## A3 완료 당시 — 2026-11-07

- A3는 오프라인 TCP prefix 재조립을 구현했고 리뷰 중요 문제 수정 뒤 Debug·Release/clang-tidy·ASan/UBSan에서 각각 146/146과 포맷 검사가 통과했다. [실행 증거](a3-validation-2026-11-07.json)와 [검증 기록](test-plan.md)을 참고한다. 중요한 미해결 리뷰 항목은 없고 경미 항목 2개를 아래에 명시한다.
- 방향별 첫 64 KiB가 기본 검사 범위다. 긴 스트림 전체를 처리하는 이동 창이 아니며 깊이 밖을 검사했다고 보고하지 않는다. overlap의 first-seen 비교도 보관 범위에 한정한다.
- 첫 payload에서 방향별 배열+비트맵 73728바이트를 할당한다. 작은 전송에도 전체 방향 버퍼를 할당하는 단순한 선택이며 공간 효율·처리량·RSS는 측정하지 않았다. 글로벌 128 MiB는 배열 예산이고 map/Flow/할당자/프로세스 전체 메모리의 정확한 상한이 아니다.
- SYN 없는 시작은 midstream이며 뒤늦은 앞부분을 소급 복원하지 않는다. FIN/RST·gap·모호한 시퀀스·잘못된 세그먼트·상한 이력을 명시하지만 실제 수신 OS의 ACK/window·정규화·TCP acceptance를 재현하지 않는다. 스트림 전체의 보안 검사 완료를 주장하지 않는다.
- FIN의 기존 데이터와 모순되는 종료 경계는 단순 first-seen 정책으로 거부한다. 같은 tuple의 새 SYN은 해당 방향 재조립을 중단하지만 A2 Flow 통계가 만료 전 연결 재사용을 합치는 한계는 남는다.
- 직접 API는 한 FlowTable에서 부여한 고유 ID 순서대로 모든 TCP 관측을 전달해야 한다. 반환 span은 다음 변경 전까지만 유효하다. 동기 sink는 객체에 재진입하거나 뷰를 보관하면 안 된다.
- EOF·만료·RST로 배열을 정리한다. 메모리 거부는 해당 방향에서 되돌리지 않으며 EOF 종료 코드 0이어도 재조립 불완전 사유와 skipped/rejected가 있을 수 있다.
- 기존 A1의 Ethernet IPv4 한정·체크섬 미검사·미지원 IPv6/VLAN/fragment와 A2의 O(n) 만료 검사는 유지된다. 파싱 실패 패킷은 특정 Flow에 임의 귀속하지 않고 skipped/parse_error로 남긴다.
- 룰 엔진·JSONL·live·Inline·AI/IPC는 후속 단계다. 지금은 어떤 패킷도 탐지 룰로 판정하거나 차단하지 않는다. 향후 스트림 탐지도 앞서 통과한 패킷을 소급 차단할 수 없다.
- 리뷰에서 경미 항목 2개를 보류했다. RST 뒤 순수 ACK에도 reset 콘솔 이벤트가 반복될 수 있다. 기존 reset 이력과 추가 데이터 억제는 유지되며 현재 룰/차단은 없지만 이벤트 소비자는 새 RST 패킷 수로 간주하면 안 된다.
- 직접 API에 명시적 캐스트로 잘못된 ReassemblyEnd를 넘기면 finish_all은 활성 상태를 정리한 뒤 예외를 던지고, 빈 상태에서는 거부하지 않는다. 정상 CLI는 유효한 enum 상수만 사용한다. 호출자는 이 API에 유효한 종료 사유만 전달해야 한다.

## A2 완료 당시 — 2026-11-06

- A0~A2는 완료다. Debug·Release/clang-tidy·ASan/UBSan에서 전체 101개가 각각 통과했고 실제 PCAP과 독립 코드 리뷰로 확인했다. [실행 기록](a2-validation-2026-11-06.json)을 참고한다.
- Flow는 오프라인 Ethernet IPv4 TCP/UDP만 추적한다. 기존 파서의 IPv6·VLAN·ARP·fragment·체크섬·PCAPNG 관련 제한은 유지된다.
- 만료 검사는 매 패킷마다 활성 테이블을 순회하는 O(n) 방식이다. 처리량과 RSS는 측정하지 않았으며 고속·상용 처리 성능을 보장하지 않는다.
- TCP 상태는 관측 flags의 추정이다. 시퀀스/ACK 검증이나 완전한 상태 머신이 아니며 동시 연결 시작·역순 handshake를 완전히 복원하지 않는다. FIN/RST 도착 즉시 삭제하지 않아 만료 전 같은 5-tuple을 재사용한 연결은 합쳐질 수 있다.
- 역순 캡처는 단조 watermark에서 활동한 것으로 처리한다. 실제 활동 시각을 복원하는 정책이 아니다. IAT는 역순 구간을 0으로 계산하며 캡처 시각의 최솟값/최댓값은 별도로 보관한다.
- 개수 제한 시 새 Flow의 추적만 거부한다. 패킷 분석은 계속될 수 있으므로 EOF 종료 코드 0이 `skipped=0` 또는 `rejected=0`을 보장하지 않는다. 이 동작은 실제 네트워크 DROP이 아니다.
- Flow 상태는 payload 없는 고정 크기 값이다. map과 고정 상태의 개수는 설정값으로 제한하지만 라이브러리·할당자의 전체 RSS에 대한 바이트 단위 상한을 실측한 것은 아니다.
- FlowTable은 parse_packet이 만든 메타데이터를 받는다. 구조 전체의 길이 일관성 검사를 다시 수행하지 않으며, 소비하는 시각·프로토콜·TCP 메타데이터 존재·최소 IP 길이만 확인한다.
- 전체 검사는 root로 실행했다. 비특권 계정은 합성 PCAP 1건의 실행만 확인했으며 일반 개발 계정 전체와 원격 GitHub Actions는 별도 검증하지 않았다.
- 재조립·룰·JSONL 이벤트·live/Inline·AI/IPC는 후속 단계다. Flag/IAT의 원시 집계가 있어도 AI 특징 벡터나 추론을 구현한 것은 아니다.

## A1 인수 검토 당시 — 2026-11-05

- A0·A1은 완료다. A1 검토에서 전체 Debug 테스트 67개와 A1 관련 ASan/UBSan 테스트 54개를 실제 실행해 모두 통과했다. 정상·혼합·빈 PCAP과 손상·미지원 링크 파일의 직접 실행 결과도 확인했다. [실행 기록](a1-validation-2026-11-05-linux.json)을 참고한다.
- 지원 범위는 오프라인 Ethernet IPv4 TCP/UDP다. IPv6, VLAN, ARP, IP fragment, 다른 링크/IP 프로토콜은 분석하지 않는다. 헤더 옵션의 길이는 처리하지만 내용과 체크섬은 검증하지 않는다.
- 개별 패킷 오류는 건너뛰므로 종료 코드 0이라도 `skipped`가 있을 수 있다. PCAP 컨테이너 손상과 미지원 링크는 종료 코드 1로 구별한다.
- 바이트와 payload 뷰는 콜백 중에만 유효하다. 이후 보관이 필요하면 복사해야 한다. 나노초 입력은 마이크로초로 변환하며 원래 정밀도를 보존하지 않는다.
- PCAPNG, 다른 libpcap 버전, 모든 손상 입력과 파일 디스크립터 누수의 독립 실측은 이번 인수 검토에서 다루지 않았다. 고정 입력의 통과를 임의 입력 전체에 대한 보장으로 확대하지 않는다.
- 정상 PCAP 실행은 uid 65534에서도 확인했지만 전체 테스트는 root로 실행했다. 일반 개발 계정과 전체 비특권 테스트, 원격 GitHub Actions는 별도 확인이 필요하다.
- Flow, TCP 재조립, 룰 탐지, live 수집, 실제 Inline 차단과 AI는 후속 단계다. 현재 출력은 메타데이터·오류·건수 콘솔 형식이며 A5 JSONL 이벤트가 아니다.

## A0 검증 당시 — 2026-11-05 (환경 복구 후)

- A0는 검증 완료다. WSL2 Ubuntu에서 Debug·Release/clang-tidy·ASan/UBSan 빌드와 기존 테스트 67개가 각각 통과했고 포맷 검사도 통과했다. [실행 기록](a0-validation-2026-11-05-linux.json)을 참고한다.
- 이번 설치와 검증은 Ubuntu의 root 계정으로 수행했다. 일반 사용자 계정의 권한 및 원격 GitHub Actions 실행은 확인하지 않았다.
- 검사 중 발견한 타입·포맷 문제를 수정했다. 알 수 없는 입력 계층 값99를 일부러 넣는 기존 거부 테스트에는 해당 줄의 enum 범위 경고만 이유와 함께 제외했다. 실제 거부 assertion과 전역 검사 설정은 유지했다.
- A1의 고정 입력 테스트도 통과했지만, PCAPNG와 libpcap의 다른 버전, 모든 손상 입력에 대한 동작을 증명한 것은 아니다. 아래 A1 지원 범위의 제한은 계속 적용된다.
- 이번 범위는 A0 검증이다. Flow·TCP 재조립·룰·live·Inline·AI 기능이나 A2 이후 구현, 방화벽 변경은 수행하지 않았다.

## A0 재검증 — 2026-11-05 (환경 복구 전 기록)

- A0는 계속 미완료다. 현재 PATH에서 Linux 빌드에 필요한 도구를 찾지 못했고, 실행 권한을 확장한 `wsl.exe --list --verbose`도 종료 코드 1과 `Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG` 오류로 실패했다.
- 배포판 설치 여부와 Linux 내부 의존성은 확인하지 못했다. 이 오류만으로 관리자 권한 부족이나 Ubuntu 미설치를 원인으로 단정하지 않는다.
- configure/build·도움말·CTest는 미실행이며 테스트 실행 수는 0개다. 코드의 성공/실패 여부를 판정한 결과가 아니다. [재검증 기록](a0-validation-2026-11-05.json)을 참고한다.

## A1 — 2026-11-03 당시 기록

- 사용자 지시에 따라 A0는 보류하고 A1 구현을 작성했다. A0와 A1을 완료로 판정하지 않았다. A1 인수 기준은 실제 Linux 실행 검증 대기 상태다.
- CMake/Ninja/컴파일러 부재로 컴파일·링크·GoogleTest/CTest·포맷·정적 분석·ASan/UBSan이 미검증이다. 정적 리뷰와 fixture 바이트 확인은 이를 대체하지 않는다.
- Ethernet/IPv4 TCP/UDP만 대상으로 한다. IPv6, VLAN, ARP, fragment, 다른 링크/IP 프로토콜은 분석하지 않는다.
- 체크섬, IPv4/TCP 옵션 내용, TCP 세션 성립·재조립·재전송, 응용 프로토콜의 유효성은 검사하지 않는다.
- caplen < 원본 길이를 보수적으로 모두 건너뛰므로 IP 데이터가 온전하고 padding만 잘린 경우도 제외된다. UDP Length와 IP payload 길이의 정확한 일치를 요구한다.
- 타임스탬프 정밀도는 마이크로초다. 음수 시각은 거부하며, 역순의 유효한 시각은 그대로 전달한다. Flow 시간 집계 정책은 A2의 별도 범위다.
- 캡처 바이트와 payload span은 콜백 안에서만 유효하다. 후속 처리에서 보관하려면 소유 버퍼에 복사해야 한다.
- libpcap 자체의 파일 디코더 동작에 의존한다. classic PCAP의 고정 입력 테스트를 작성했으며 PCAPNG와 실제 libpcap 버전별 손상/oversized record 보정·거부 동작은 미검증이다.
- 정상 종료 코드 0이라도 skipped 수가 있을 수 있다. 개별 입력 오류의 경고와 전체 파일 읽기 실패를 구분해야 한다.
- stdout 메타데이터와 stderr parse_error/capture_error는 임시 콘솔 형식이다. A5 JSONL 이벤트와 호환된다고 주장하지 않는다.
- Flow·룰·탐지·live·Inline·AI는 구현하지 않았다. 호스트 방화벽과 실제 네트워크는 변경하지 않았다.
- 현재 폴더는 Git 저장소가 아니다. 자동 Git 초기화·커밋·push·CI 실행은 하지 않았다.

아래 A0 항목은 당시 기록이다. “A1 시작 전 A0 통과”라는 일반 조건은 이번 사용자 지시에서만 예외가 적용됐으며, 일반적인 검증 기준을 완화한 것은 아니다.


## A0 — 2026-10-26

- A0는 **미완료**다. 파일은 작성했지만 실제 C++ 컴파일·링크, CLI 실행, GoogleTest/CTest 통과를 확인하지 못했다.
- 현재 호스트는 Windows다. CMake, Ninja, GCC/Clang, clang-format, clang-tidy를 찾지 못했다. WSL은 종료 코드 1과 “시스템에서 파일에 액세스할 수 없습니다.”를 반환했다. 배포판 설치 여부와 Linux 내부 패키지 상태까지 확인한 것은 아니다.
- 외부 다운로드는 DNS 해석 실패로 진행할 수 없었다. 전역 도구 설치나 호스트 설정 변경을 하지 않았다.
- CMake 의존성 탐색, 포맷, 정적 분석, ASan/UBSan과 GitHub Actions 실행도 미검증이다. 소스 파일 검토가 이를 대체하지 않는다.
- CLI의 도움말·버전과 잘못된 인자 처리만 작성했다. PCAP/live/inline 모드, 파서, Flow 추적, TCP 재조립, 룰 엔진, JSONL 이벤트와 AI/IPC는 구현하지 않았다.
- libpcap와 libnetfilter_queue의 RAII 래퍼는 해당 자원을 실제 사용하는 후속 단계에서 구현한다. 현재는 해당 핸들을 열지 않는다.
- rules/config의 자리 파일은 동작하는 룰 또는 설정 파일이 아니다.
- 빌드가 성공하더라도 A0는 네트워크 분석이나 보호 기능의 완료를 뜻하지 않는다. 운영망 적용·공격 탐지·실제 차단 성능을 주장할 수 없다.
- 호스트 방화벽·nftables·NFQUEUE를 변경하거나 실제 DROP 테스트를 수행하지 않았다.

다음 작업은 Linux 개발 환경에서 README의 A0 빌드·검사를 실행해 미검증 항목을 해소하는 것이다. A1 시작에는 A0 합격 증거와 사용자 승인이 모두 필요하다.
