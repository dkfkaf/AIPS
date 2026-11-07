# 고정 입력과 합성 PCAP

## A4 룰 입력 — 2026-11-07

기존 fixture writer에 rules_packet.pcap(BLOCKME packet drop 시뮬레이션)과 rules_retransmit.pcap(SYN → HEL → LO → HEL 재전송 → 순수 ACK)을 추가했다. 두 번째는 stream HELLO drop 룰 사용 시 events1/suppressed1/simulated_drops2이고 ACK는 Allow다. 원본 payload는 콘솔에 출력하지 않는다. 예시 JSON은 rules/example.json이며 HELLO stream alert와 BLOCKME packet drop 두 개다. 실제 네트워크 차단을 테스트한 것은 아니다.

## A3 재조립 입력 — 2026-11-07

`reassembly_fixtures.hpp`는 고정 Ethernet/IPv4/TCP 헤더에서 시퀀스·flags·payload·방향을 바꾸고 IP/TCP 체크섬을 다시 계산한다. 체크섬을 생산 파서가 검증한다는 뜻은 아니다. 외부 트래픽이나 데이터셋은 쓰지 않는다.

| 파일 | 관측 순서 | 기대 결과 |
| --- | --- | --- |
| reassembly_hello.pcap | 1초 SYN99, 2초 LO103, 3초 HEL100, 4초 FIN105 | 처음 LO는 pending 2, HEL 뒤 연속 HELLO 5바이트, 관측 FIN 앞 갭 없음 |
| reassembly_gap.pcap | 1초 SYN99, 2초 LO103 | prefix 0/pending 2, EOF gap/capture_end, 버퍼 해제 |
| reassembly_reset.pcap | SYN99, A+FIN100, RST102 | 정상 FIN 뒤 reset이 거짓 gap을 만들지 않음 |
| reassembly_ambiguous_fin.pcap | SYN0xffffffff, X+FIN0x7fffffff, FIN0 | 모호한 FIN 경계 거부 후 정상 FIN0은 수락 |

네 파일은 기존 fixture writer로 생성한다. CLI는 payload 원문을 출력하지 않으며 HELLO의 정확한 내용은 코어 단위 테스트에서 확인한다. 테스트별 midstream·충돌·한도·만료 입력도 같은 독립 PCAP 인코더로 실행 중 만든다. [A3 테스트 기록](../../docs/test-plan.md)을 참고한다.

## A1 고정 입력

packet_fixtures.hpp의 바이트 배열은 직접 작성한 Ethernet/IPv4 TCP·UDP 패킷이다. 실제 네트워크에서 캡처한 데이터가 아니며 주소는 문서용 192.0.2.1과 198.51.100.2다.

| 항목 | TCP | UDP |
| --- | --- | --- |
| 프레임 바이트 수 | 59 | 45 |
| IPv4 Total Length | 45 | 31 |
| 출발 포트 | 12345 | 53 |
| 목적 포트 | 8080 | 54321 |
| payload | HELLO 5 bytes | DNS 3 bytes(애플리케이션 DNS 메시지를 뜻하지 않음) |
| 기본 캡처 시각 | 1.25초 | 1.25초 |

IPv4·TCP·UDP 체크섬은 fixture 생성 시 계산한 고정 값이다. 생산 파서는 체크섬을 검증하지 않는다. 손상 테스트는 고정 바이트의 길이/필드를 바꾸므로 변형된 입력의 체크섬까지 갱신하지 않는다.

PCAP 컨테이너는 tests/pcap_fixture.hpp의 독립된 little-endian 인코더가 테스트 실행 중 만든다. fixture_writer는 normal, mixed, empty, truncated, unsupported 파일을 빌드 디렉터리에 생성한다. 원본 PCAP을 저장소에 추가하지 않는다.

## A2 Flow 입력

2026-11-06부터 같은 writer가 아래 세 파일도 생성한다. 역 TCP 패킷은 고정 바이트의 Ethernet·IPv4·포트 endpoint를 서로 바꾼 값이며 실제 연결 전체나 TCP handshake를 재현한 파일은 아니다.

| 파일 | 레코드 시각과 내용 | 기대 Flow 결과 |
| --- | --- | --- |
| flow_bidirectional.pcap | 1초 정 TCP, 2초 역 TCP, 3초 정 TCP | ID 1, fwd/bwd 패킷 2/1, IP 바이트 90/45 |
| flow_expired.pcap | 1초 정 TCP, 2초 역 TCP, 122초 정 TCP | 마지막 활동부터 120초 경계에서 ID 2 생성, expired=1 |
| flow_capacity.pcap | 1초 TCP, 2초 다른 UDP, 3초 역 TCP | --max-flows 1에서 UDP만 untracked, 기존 TCP ID 유지 |

전체 테스트 101개와 별도 CLI 실행으로 확인했다. [A2 실행 기록](../../docs/a2-validation-2026-11-06.json)에 실제 출력과 세 PCAP의 해시를 저장했다.

실행 예시는 루트 README를 참고한다. 2026-11-05 C++ fixture writer로 PCAP 5종을 생성하고 실제 libpcap 읽기와 CLI 동작을 확인했다. normal은 TCP·UDP 각 1개를 처리했고, mixed는 손상 패킷을 건너뛰고 다음 UDP를 처리했다. truncated와 unsupported는 종료 코드 1로 실패 원인을 보고했다. [A1 실행 기록](../../docs/a1-validation-2026-11-05-linux.json)에 명령·출력과 fixture 해시를 보관한다.
