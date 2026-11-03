# 설계 결정

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
