# 사용자 자체 IPS 테스트 — 2026-11-09

상태: 안내한 사용자 기본 테스트4단계 모두 통과. 사용자 제공 출력으로 PCAP·격리 live·NFQUEUE UDP·TCP/수신 압박을 확인했다. 합성 입력과 지정된 격리 시나리오의 결과이며 사용자 고유 PCAP·운영망·실제 공격 탐지율 검증으로 확대 해석하지 않는다. AI 단계는 아직 시작하지 않았으며 명시적 착수 지시를 기다린다.

## 1. 합성 PCAP — 통과

사용자 실행: jsonl_pipeline.pcap, rules/a5-demo.json, --max-flows 1, --tcp-stream-bytes 16, --log -.

근거: 사용자가 붙여넣은 텍스트.txt 첨부. 원본 SHA256 `9e9570d151aabaebad15a6fae5c9ae2bbc69db8245b8b1461b622000a3788be4`. 첨부는 실행 명령이 아닌 결과 데이터로 읽었다. 사용자 실행 바이너리/소스 해시는 별도로 수집하지 않았으므로 이 판정은 제공된 출력과 고정 입력 기대 결과의 일치 범위다.

| 항목 | 사용자 출력 |
| --- | ---: |
| 전체/파싱/건너뜀 | 10 / 9 / 1 |
| detections | 2 |
| simulated_drop_packets | 3 |
| actual_drop_packets | 0 |
| JSONL attempted/written | 25 / 25 |
| 로그 failed/dropped/io_errors | 0 / 0 / 0 |
| log_complete / exit_code | 1 / 0 |

capture_complete=true, processing_errors=0이다. capacity_exceeded는 Flow 상한1, truncated_ethernet은 의도적인 손상1패킷, gap/overlap/depth 경고는 고정 입력의 재조립 제한 시험 결과다. 모든 이벤트는 mode=pcap/enforced=false이며 실제 차단을 증명하는 결과는 아니다.

## 2. 격리 라이브 IDS — 통과

사용자 제공 콘솔 결과를 확인했다. purt1 계정에서 sudo와 caller namespace token을 사용한 실행이다. 비밀번호 자체는 제공받거나 기록하지 않았다.

| 항목 | 사용자 출력 |
| --- | ---: |
| cases / failed | 11 / 0 |
| packet_limit_processed | 10 |
| detections | 2 |
| simulated_drops / actual_drop_packets | 3 / 0 |
| isolated | true |
| exit_code | 0 |

완료 시나리오: packet_limit_full_pipeline, idle_sigint, idle_sigterm, active_sigint, closed_stdout_continues, file_limit_stdout, file_limit_owned_log, new_file_0600_and_preservation, rejected_device_no_such_ids0, rejected_device_any, capture_permission_denied. 라이브 IDS는 수집·탐지 모드이므로 실제 차단0이 기대 결과다.

## 3. 격리 NFQUEUE UDP — 통과

사용자 제공 JSON 요약과 쉘 종료 코드로 확인했다. sudo 뒤 새 network namespace에서 env로 로컬 nft 라이브러리 경로를 설정하는 명령을 안내했다.

| 항목 | 사용자 출력 |
| --- | ---: |
| cases / failed | 14 / 0 |
| canonical_received | 4 |
| accepted / actual_drop_packets | 3 / 1 |
| isolated | true |
| host_firewall_changed | false |
| exit_code | 0 |

정상/Pass/Alert 실제 전달과 Drop 미도착, listener 부재·종료, 신호 종료, 중복 바인딩, 미지원 ICMP 허용, 로그/출력 장애 뒤 판정 유지, 파일 보존/권한 거부, 자체 규칙 제거 후 통신 복구 시나리오를 통과했다. 표준 시험4패킷의3허용/1차단이며 모든14시나리오의 전체 패킷 수가4라는 뜻은 아니다.

출력의 `>` 프롬프트는 echo 명령 끝의 역슬래시에 따른 쉘 줄 연결로 해석되며, 최종 exit_code=0을 확인했다. 마지막 echo 줄에는 줄 연결 문자를 붙이지 않도록 안내한다.

## 4. 격리 TCP·수신 압박 — 통과

사용자 제공 결과: cases4/failed0/isolated=true/host_firewall_changed=false, 최종 쉘 exit_code=0.

| 시나리오 | 유효 ID / 시도 | 허용 / 차단 | 전송 실패 |
| --- | ---: | ---: | ---: |
| tcp_normal_pass_alert | 13 / 13 | 13 / 0 | 0 |
| tcp_packet_drop | 8 / 8 | 5 / 3 | 0 |
| tcp_split_stream_drop | 10 / 10 | 7 / 3 | 0 |
| bounded_receive_pressure_error_and_cleanup | 1 / 1 | 0 / 1 | 0 |

모든 시나리오에서 callbacks=valid_ids=attempts=accepted+dropped이며 failed/missing_ids/close_errors/processing_errors=0이다. packet/stream 차단3회는 재전송을 포함할 수 있어 서로 다른 공격3건으로 집계하지 않는다. stream 시나리오는 earlier_prefix_delivered=true로 앞선 HEL 전달과 후행 LO 차단을 확인했다.

압박 시나리오는 합성 UDP16384개를 보낸 뒤 receive_errors1/overflow_errors1 및 내부 exit_code1을 확인했다. 이는 의도한 오류 감지·종료 결과이며 검증기 전체는 exit_code0이다. 전송16384개 전체에 대해 애플리케이션 verdict를 제출했다는 뜻은 아니다. 커널 queue 스냅샷은 아래 원문으로만 보존하며 열 의미를 추정해 집계하지 않는다.

```text
42421    612   166 2 65531     0 16218    16384  1
```

## 결과와 다음 단계

PCAP1개, live11개, NFQUEUE UDP14개, TCP·수신 압박4개 시나리오의 사용자 실행 결과를 검토했고 실패 보고는 없다. 이 기본 테스트 범위에서 IPS 실행·탐지·실제 차단·로그 장애/압박 오류 처리를 확인했다. 사용자 고유 입력이나 별도 부하 테스트를 추가할 수 있다.

IPS A0~A8 개발자 검증 → 사용자 기본 자체 테스트 → 결과 확인 순서를 충족했다. 다음 후보 단계는 B0 데이터셋 확정 및 데이터 카드이며, 사용자가 AI 단계 착수를 명시적으로 지시하기 전에는 데이터셋 다운로드·특징 파이프라인·모델 학습을 시작하지 않는다.

실행 방법은 [사용자 가이드](ips-test-guide.md)를 따른다. A8 개발자 검증 기록은 이 사용자 결과와 구분해 보존한다.
