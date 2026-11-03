# MiniSuricata-AI

C++20 경량 IDS/IPS 엔진과 후속 Python/PyTorch 보조 탐지기를 만드는 교육·연구용 프로젝트다. Suricata에서 영감을 얻은 독립 구현이다.

**현재 상태(2026-11-03): A0 보류, A1 구현 작성·실행 검증 대기.** 사용자가 A0를 보류하고 A1 구현을 진행하도록 명시적으로 지시했다. A0를 완료 처리하지 않았으며, A1도 빌드·테스트 성공을 아직 확인하지 못했다. [검증 기록](docs/test-plan.md)을 참고한다.

작업 규칙은 [AGENTS.md](AGENTS.md), 기능 계약은 [PROJECT_SPEC.md](PROJECT_SPEC.md), 개발 단계는 [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), 코드 규칙은 [CODING_STYLE.md](CODING_STYLE.md)를 따른다.

## 현재 작성된 기능

- CMake/Ninja, C++20, Linux 시스템 의존성 탐색, 포맷·정적 분석·sanitizer 옵션과 Ubuntu CI.
- 기존 `--help`, `--version`과 A1 `--mode pcap --input PATH`.
- libpcap 오프라인 입력, Ethernet/IPv4/TCP/UDP 길이 검사 및 메타데이터 출력.
- 원인별 파싱 오류와 분석 건수 요약. 원시 payload는 출력하지 않는다.
- GoogleTest 55개와 CTest 프로세스 검사·fixture 준비 12개를 작성했다. 총 67개는 **기대 등록 수**이며 통과 수가 아니다.

Flow 추적·TCP 재조립·룰 탐지·JSONL 이벤트·라이브 수집·차단·AI·IPC는 후속 단계다.

## Linux 개발 의존성

대상은 Ubuntu 24.04 LTS 또는 호환 Linux, GCC/Clang C++20, CMake >= 3.22다. Windows 네이티브 빌드는 지원하지 않는다. 이번 요청에서는 WSL 복구나 전역 도구 설치를 진행하지 않았다.

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkg-config \
  libpcap-dev libnetfilter-queue-dev nlohmann-json3-dev \
  libspdlog-dev libgtest-dev clang-format-18 clang-tidy-18
```

libpcap(>= 1.5.1)과 libnetfilter_queue는 pkg-config로, nlohmann/json·spdlog·GoogleTest는 시스템 CMake 패키지로 찾는다. CMake에서 의존성을 다운로드하지 않는다. 일반 빌드·테스트에는 관리자 권한이 필요 없으며 호스트 방화벽을 변경하지 않는다.

## 빌드·테스트

프로젝트 루트에서 Linux 셸로 실행한다. 아래 명령의 성공은 현재 세션에서 확인하지 못했다.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --no-tests=error
./build/miniips --help
./build/miniips --version
```

CTest는 테스트용 PCAP을 빌드 디렉터리에 생성한다. 원본 캡처 파일이나 외부 데이터셋 다운로드는 필요 없다.

## A1 실행 예시

테스트용 파일을 직접 생성하고 분석하려면:

```bash
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input ./build/tests/fixtures/normal.pcap
```

`normal.pcap`에는 고정 TCP/UDP 패킷이 각각 한 개씩 있다. 기대 출력에는 다음 메타데이터가 포함된다(실제 실행 결과가 아닌 예시).

```text
packet=1 timestamp_us=1250000 protocol=tcp src_ip=192.0.2.1 src_port=12345 dst_ip=198.51.100.2 dst_port=8080 ...
packet=2 timestamp_us=1250000 protocol=udp src_ip=192.0.2.1 src_port=53 dst_ip=198.51.100.2 dst_port=54321 ...
pcap_summary packets=2 parsed=2 skipped=0
```

본인에게 분석 권한이 있는 PCAP은 다음과 같이 입력한다.

```bash
./build/miniips --mode pcap --input /path/to/capture.pcap
```

옵션 순서는 바꿀 수 있다. `--mode`와 `--input`은 한 번씩 필요하며, `--rules`, `--log`, live/inline 모드는 아직 지원하지 않는다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | 도움말·버전 출력 또는 파일을 EOF까지 분석 완료. skipped가 0이라는 뜻은 아니다. |
| 1 | 파일 열기·읽기·미지원 링크·타임스탬프·출력 오류 |
| 2 | 필수 인자 누락·알 수 없는 옵션·중복 옵션 등 사용법 오류 |

개별 패킷의 손상·미지원 입력은 stderr에 `parse_error packet=N reason=...`를 출력하고 다음 레코드를 읽는다. PCAP 컨테이너가 손상되어 더 읽을 수 없으면 `capture_error:`와 함께 실패한다. 이 출력은 A5의 JSONL 이벤트 스키마가 아니다.

## A1 지원 범위·한계

- Ethernet(DLT_EN10MB)의 IPv4 TCP/UDP만 지원한다. IPv6·ARP·VLAN·다른 IP 프로토콜·fragment는 분석하지 않고 원인을 구분한다.
- 헤더 필드를 읽기 전에 실제 캡처 바이트 수를 검사한다. IPv4 Total Length 바깥의 Ethernet padding은 payload에서 제외한다.
- 캡처 길이가 원본 프레임 길이보다 짧으면 보수적으로 전체 패킷을 건너뛴다.
- IPv4 IHL과 TCP Data Offset으로 옵션 영역의 길이는 건너뛰지만 옵션 내용은 해석하지 않는다.
- 비조각 UDP의 Length는 IP payload 길이와 같아야 한다. IP/TCP/UDP 체크섬은 검증하지 않는다.
- libpcap에 마이크로초 타임스탬프를 요청한다. 나노초 파일은 마이크로초로 변환되며 미만 정밀도는 보존하지 않는다.
- libpcap이 보고한 snapshot은 최대 262144 bytes다. 콜백의 바이트 뷰는 호출 중에만 유효하다.
- stdin 경로 `-`는 지원하지 않는다. 외부 파일에는 libpcap 자체의 파일 처리도 적용되며, PCAPNG·버전별 oversized record 처리 차이는 미검증이다.
- 패킷을 탐지·허용·차단했다고 주장하지 않는다. A1은 오프라인 구조 해석 단계다.

## 품질 검사

포맷 검사:

```bash
cmake --build build --target format-check
```

clang-tidy를 포함한 별도 빌드:

```bash
cmake -S . -B build-tidy -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_CLANG_TIDY=ON
cmake --build build-tidy --parallel 2
ctest --test-dir build-tidy --output-on-failure --no-tests=error
```

ASan/UBSan:

```bash
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel 2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-sanitize --output-on-failure --no-tests=error
```

Release:

```bash
cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-release --parallel 2
ctest --test-dir build-release --output-on-failure --no-tests=error
```

`format-check`는 clang-format이 있을 때 생성된다. 정적 분석 옵션을 켰는데 clang-tidy가 없으면 configure가 실패한다. [CI](.github/workflows/ci.yml)에도 연결되어 있지만 실제 CI 실행 결과는 없다.

## 기록

- [설계 결정과 사용자 승인 예외](docs/design-decisions.md)
- [알려진 한계](docs/known-limitations.md)
- [테스트 계획·실행 결과](docs/test-plan.md)
- [A0 명령 원본 결과](docs/a0-validation.json)
- [A1 명령 원본 결과](docs/a1-validation.json)
- [A1 구현 계획](docs/superpowers/plans/2026-11-03-a1.md)
- [고정 테스트 바이트 설명](tests/fixtures/README.md)

A0는 보류 상태로 유지한다. A1 인수 기준의 실제 검증과 사용자 지시 없이 A2를 시작하지 않는다.
