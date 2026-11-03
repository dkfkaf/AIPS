# A1 고정 입력

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

실행 예시는 루트 README를 참고한다. 현재 C++ fixture writer와 libpcap 읽기를 실제 실행한 증거는 없으며, 파일 작성과 테스트 통과를 구분한다.
