# 테스트 계획과 실제 검증

## A1 판정 — 2026-11-03

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
