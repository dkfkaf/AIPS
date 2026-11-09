# 기존 C++ Flow 관찰 인터페이스

A8에서 이미 구현된 통계를 설명한다. Python 특징 추출·정규화·16특징 벡터·UDS는 후속 단계이며 이 문서가 구현 완료를 뜻하지 않는다.

| 인터페이스 | 관찰 시점과 소유권 |
| --- | --- |
| Engine::inspect(PacketEnvelope) → PacketResult | 패킷별 동기 검사. packet/flow/reassembly/decision/expired 결과는 소유 메타데이터이며 원본 바이트 span을 보관하지 않는다. |
| PacketResult.flow의 FlowObservation | 갱신 후 FlowSnapshot, 현재 방향과 created 여부. FlowError::CapacityExceeded도 가능하다. 파싱 실패에는 정상 Flow 관측이 없다. |
| PacketResult.expired | 이번 입력의 watermark로 만료된 FlowEnd 목록. 원인/마지막 통계/재조립 불완전 요약을 소유한다. |
| Engine::finish(Eof/Stopped/Aborted) → FinishResult | 최초 호출에 남은 FlowEnd를 Flow ID 순으로 반환하고 TCP/룰 상태를 해제한다. 반복 호출은 FlowEnd를 재발행하지 않는다. finish 뒤 inspect는 사용하지 않는다. |
| Engine::stats() | 현재 누적 카운터의 값 복사. flow.active는 finish 시점 남았던 테이블 개수를 포함하므로 TCP 상태 메모리0과 모순이 아니다. |
| FlowTable::find/visit | 독립 FlowTable 사용 시 소유 snapshot 조회/동기 순회. visit/만료 callback에서 테이블을 변경하거나 재진입하지 않는다. 내부 순회 순서는 고정하지 않는다. |

실제 선언: [engine.hpp](../include/miniips/engine.hpp), [flow.hpp](../include/miniips/flow.hpp), [flow_table.hpp](../include/miniips/flow_table.hpp). Engine은 내부 FlowTable을 외부에 노출하지 않으므로 일반 소비자는 PacketResult/FinishResult를 사용한다.

| 필드 | 의미·단위·주의 |
| --- | --- |
| key | 두 endpoint를 정렬한 IP/port/protocol의 양방향 키. UDP/TCP는 별도다. |
| first_source, fwd/bwd | 최초 관측 패킷의 source가 forward다. IP 정렬 순서나 실제 client/server 역할과 같다고 가정하지 않는다. |
| flow_id | Engine/FlowTable 인스턴스 내 증가 ID. 실행 간 전역 ID가 아니며 만료 뒤 같은 tuple은 새 ID다. |
| first_seen/last_seen | 관측한 최소/최대 시각, microseconds. PCAP/live는 capture, inline은 사용자 공간 callback receive 시각이다. |
| direction.packets/bytes | 파싱·추적된 IP 패킷 수와 IPv4 total length 합계. Ethernet 헤더나 payload만의 합계가 아니다. TCP 재전송도 관측 패킷으로 집계된다. |
| iat_sum_us/iat_samples | 방향별 첫 관측 이후 간격 합/샘플 수. 역행 시각의 간격은0으로 제한하고 last_seen은 뒤로 가지 않는다. 샘플0일 때 평균 계산은 후속 계약에서 명시해야 한다. |
| syn/ack/fin/rst/psh_count | 관측된 TCP flag 횟수. UDP는0, 재전송도 포함하며 완전한 TCP endpoint 상태와 같지 않다. |
| tcp_state | 관측 SYN/ACK/FIN/RST에 따른 제한된 상태. 실제 연결 성립·종료의 절대 증거가 아니다. |

Flow 만료는 단조 capture watermark와 last_activity에 따른 idle timeout이다. 무입력 중 벽시계만으로 만료시키지 않는다. 추적 개수·TCP 메모리/깊이·룰 상태 제한과 parse skip/불완전은 [한계](known-limitations.md)를 함께 해석한다. 오류·미지원 입력을 정상0특징으로 치환하지 않는다.

후속 B1/C단계에서는 동일 packet/시점 정책으로 오프라인·온라인 특징의 단위/순서/방향/샘플0 처리를 고정해야 한다. A8의 성능 및 합성 룰은 AI 탐지율의 증거가 아니다.
