# MiniSuricata-AI

C++20 경량 IDS/IPS 엔진과 후속 Python/PyTorch 보조 탐지기를 만드는 교육·연구용 프로젝트다. Suricata에서 영감을 얻은 독립 구현이다.

**현재 상태(2026-11-07): A0~A4 검증 완료.** JSON 룰 로딩과 KMP packet/stream 판정을 PCAP에 연결했다. 최종 Debug·Release/clang-tidy·ASan/UBSan에서 동일한 184개가 각각 모두 통과했고 포맷 검사도 통과했다. A4 독립 리뷰 중요2건은 회귀 테스트로 수정했고 경미3건은 [알려진 한계](docs/known-limitations.md)에 보류했다. [검증 기록](docs/test-plan.md)과 [A4 실행 증거](docs/a4-validation-2026-11-07.json)를 참고한다. IPS 전체 완성과 사용자 자체 테스트는 앞으로의 단계다.

앞서 발생했던 WSL 설치 오류와 도구 부재는 [환경 복구 전 기록](docs/a0-validation-2026-11-05.json)에, 복구 후 실제 명령과 결과는 [Linux 실행 기록](docs/a0-validation-2026-11-05-linux.json)에 보관한다.

작업 규칙은 [AGENTS.md](AGENTS.md), 기능 계약은 [PROJECT_SPEC.md](PROJECT_SPEC.md), 개발 단계는 [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), 코드 규칙은 [CODING_STYLE.md](CODING_STYLE.md)를 따른다.

## A4 JSON 룰 엔진 — 2026-11-07

JSON 룰 로더와 KMP 기반 packet/stream 룰 엔진을 구현했다. 중요 리뷰 수정 뒤 Debug·Release/clang-tidy·ASan/UBSan에서 각각184/184와 포맷 검사를 통과했다. A4는 PCAP 시뮬레이션이고 실제 IPS 전체 완성이 아니다. 경미 보류와 실행 한계는 [테스트 기록](docs/test-plan.md)에 명시한다.

```bash
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input ./build/tests/fixtures/reassembly_hello.pcap --rules rules/example.json
./build/miniips --mode pcap --input ./build/tests/fixtures/rules_packet.pcap --rules rules/example.json
```

첫 예시는 HEL+LO의 stream alert로 Allow, 두 번째는 BLOCKME packet drop의 시뮬레이션이다. 모든 룰 판정에 `mode=pcap enforced=false`를 표시한다. 옵션을 생략하면 기존 A3 분석을 유지한다.

- JSON은 전체 검증 후 사용한다. 잘못된 한 룰·중복 SID/키·알 수 없는 필드도 파일 전체 실패다. 파일1 MiB/1024룰/content1~4096 printable ASCII/message1~1024 UTF-8 bytes/depth8 상한을 둔다.
- sid는 양의 uint32, priority는 int32, 포트는0~65535다. stream은 tcp만 허용한다. 상세 스키마는 [승인 설계](docs/superpowers/specs/2026-11-07-a4-design.md)를 참고한다.
- priority, 같은 값이면 sid 순서다. alert는 계속 검사하고 pass/drop은 현재 관측의 Allow/Drop을 확정한다. 매치가 없으면 Allow이며 Flow 전체 영구 pass/drop 캐시는 아니다.
- 현재 payload와 새 연속 구간에 관련된 패턴만 stream 판정한다. 재전송은 이벤트를 억제해도 Drop을 유지하고, payload 없는 ACK에는 과거 패턴을 반복 적용하지 않는다. 물리적으로 앞서 지나간 패킷을 소급 차단하지 않는다.
- `--rule-state-bytes N`은 stream 룰별 방향 watermark 배열 예산(기본33554432)이다. --rules와 함께 사용한다. 첫 stream 이벤트에서 할당하고 만료/EOF에 해제한다. 부족하면 detection_error와 코드1로 종료한다. 전체 RSS 상한은 아니다.
- KMP는 룰마다 검색하므로 룰 수에 비례한 비용이 있다. Aho–Corasick과의 성능 비교는 미실행이며 처리량을 보장하지 않는다. message는 ASCII JSON 문자열로 표시해 Unicode 제어/줄 구분자도 escape한다. 콘솔 출력은 A5 JSONL 형식이 아니다.

## 현재 작성된 기능

**진행 순서(사용자 결정, 2026-11-07): IPS 완성(A0~A8) → 사용자 자체 테스트 → 결과 확인·AI 착수 지시 → AI 모델 개발(B0~B5) → 연동(C단계).** 개발자 검증을 통과해도 사용자 테스트 전에 AI 개발로 자동 전환하지 않는다.

- CMake/Ninja, C++20, Linux 시스템 의존성 탐색, 포맷·정적 분석·sanitizer 옵션과 Ubuntu CI.
- 기존 `--help`, `--version`과 A1 `--mode pcap --input PATH`.
- libpcap 오프라인 입력, Ethernet/IPv4/TCP/UDP 길이 검사 및 메타데이터 출력.
- 원인별 파싱 오류와 분석 건수 요약. 원시 payload는 출력하지 않는다.
- 정규화된 5-tuple의 양방향 Flow ID, 최초 관측 기준 방향, 방향별 IP 바이트·패킷·IAT·TCP flag 집계와 관측 기반 TCP 상태.
- 최대 10,000개·유휴 120초 기본값, 설정 가능한 개수·시간 제한과 추적 거부 표시.
- 방향별 TCP 순서 복원·중복 제거·first-seen 겹침 처리·불완전 사유와 버퍼/깊이 제한. EOF·유휴 만료·RST 정리.
- JSON 전체 검증·KMP 검색·우선순위 alert/pass/drop·재전송 이벤트 억제와 제한된 상태 정리.
- GoogleTest 169개와 CTest 프로세스 검사·fixture 준비 15개, 총184개를 Debug·Release·ASan/UBSan에서 각각 실행해 모두 통과했다.

룰 탐지·JSONL 이벤트·라이브 수집·차단·AI·IPC는 후속 단계다.

## Linux 개발 의존성

대상은 Ubuntu 24.04 LTS 또는 호환 Linux, GCC/Clang C++20, CMake >= 3.22다. Windows 네이티브 빌드는 지원하지 않는다. 2026-11-05 검증에는 WSL2의 Ubuntu 24.04.5 LTS, GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1과 clang 도구 18.1.3을 사용했다. 초기 설치와 전체 테스트는 Linux root 계정으로 실행했고, 정상 PCAP의 CLI 실행은 비특권 계정(uid 65534)에서도 확인했다. 일반 개발 계정의 설정과 전체 테스트 실행 권한은 별도 확인하지 않았다.

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkg-config \
  libpcap-dev libnetfilter-queue-dev nlohmann-json3-dev \
  libspdlog-dev libgtest-dev clang-format-18 clang-tidy-18
```

libpcap(>= 1.5.1)과 libnetfilter_queue는 pkg-config로, nlohmann/json·spdlog·GoogleTest는 시스템 CMake 패키지로 찾는다. CMake에서 의존성을 다운로드하지 않는다. 일반 빌드·테스트에는 관리자 권한이 필요 없으며 호스트 방화벽을 변경하지 않는다.

## 빌드·테스트

프로젝트 루트에서 Linux 셸로 실행한다. 2026-11-07 WSL Ubuntu에서 Debug 빌드와 전체 테스트 성공을 확인했다.

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

`normal.pcap`에는 고정 TCP/UDP 패킷이 각각 한 개씩 있다. 2026-11-05 실제 실행에서 확인한 주요 메타데이터는 다음과 같다(일부 필드 생략).

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
| 0 | 도움말·버전 출력 또는 파일을 EOF까지 분석 완료. skipped·rejected·재조립 불완전 사유가 없다는 뜻은 아니다. |
| 1 | 파일 열기·읽기·미지원 링크·타임스탬프·출력 오류 |
| 2 | 필수 인자 누락·알 수 없는 옵션·중복 옵션 등 사용법 오류 |

개별 패킷의 손상·미지원 입력은 stderr에 `parse_error packet=N reason=...`를 출력하고 다음 레코드를 읽는다. PCAP 컨테이너가 손상되어 더 읽을 수 없으면 `capture_error:`와 함께 실패한다. 이 출력은 A5의 JSONL 이벤트 스키마가 아니다.

## A2 양방향 Flow 추적

```bash
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input ./build/tests/fixtures/flow_bidirectional.pcap
```

주요 Flow 출력은 다음과 같다(앞부분의 패킷 메타데이터 생략).

```text
packet=1 ... flow_id=1 direction=fwd fwd_packets=1 bwd_packets=0 fwd_bytes=45 bwd_bytes=0
packet=2 ... flow_id=1 direction=bwd fwd_packets=1 bwd_packets=1 fwd_bytes=45 bwd_bytes=45
packet=3 ... flow_id=1 direction=fwd fwd_packets=2 bwd_packets=1 fwd_bytes=90 bwd_bytes=45
flow_summary created=1 active=1 expired=0 rejected=0
```

- 키는 숫자 IPv4·포트 endpoint를 정렬하고 프로토콜을 포함한다. 통계의 `fwd`는 처음 관측한 방향이다.
- 바이트 합계는 IPv4 Total Length이며 프레임 길이나 payload 길이가 아니다. ID는 테이블 수명 동안 재사용하지 않으며 각 CLI 실행의 새 테이블은 1부터 시작한다.
- `--max-flows N`의 기본값은 10000, `--flow-idle-timeout-seconds N`은 120이다. 양의 정수만 허용하고 중복·범위 초과는 종료 코드 2로 거부한다.
- 만료는 PCAP 캡처 시각의 최댓값을 시계로 삼고 유휴 간격이 설정값 이상일 때 처리한다. 역순 시각은 시계를 되돌리지 않는다. 손상 패킷도 유효한 캡처 시각으로 만료 시계를 진행시키지만 Flow를 생성하지 않는다.
- 용량이 차면 기존 Flow를 유지하고 새 키의 추적을 거부한다. 해당 패킷은 `flow_id=untracked direction=unknown`, stderr의 `flow_error ... reason=capacity_exceeded`, 요약의 `rejected`에 표시한다. 이는 네트워크 패킷 DROP이 아니다.
- 종료 시 `active`는 마지막 캡처 시각에서 남은 Flow 수다. EOF에 임의로 시간을 더하지 않으며 메모리는 테이블 소멸 시 정리한다.

만료와 제한을 재현하려면:

```bash
./build/miniips --mode pcap --input ./build/tests/fixtures/flow_expired.pcap
./build/miniips --mode pcap --input ./build/tests/fixtures/flow_capacity.pcap --max-flows 1
```

첫 파일은 2초의 마지막 활동 뒤 122초에 같은 tuple이 나타나 ID 2를 새로 만들고 `expired=1`이 된다. 두 번째는 새 UDP Flow 1개를 거부하면서 기존 TCP의 역방향 패킷을 계속 추적한다.

Flow는 payload 없이 고정 크기 상태만 보관하지만, 매 패킷의 만료 검사는 활성 Flow 수에 비례한다. TCP 상태는 관측된 flags와 handshake의 추정이며 시퀀스/ACK 번호를 검증하지 않는다. FIN/RST로 즉시 엔트리를 지우지 않아 유휴 만료 전 같은 tuple을 다시 쓰는 연결이 합쳐질 수 있다. 역순 IAT는 0으로 집계하고 방향별 마지막 시각을 되돌리지 않는다.

## A3 TCP prefix 재조립

```bash
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input ./build/tests/fixtures/reassembly_hello.pcap
./build/miniips --mode pcap --input ./build/tests/fixtures/reassembly_gap.pcap
```

`reassembly_hello.pcap`은 SYN → `LO` → `HEL` → FIN 순서다. 먼저 받은 `LO`는 pending 2바이트이고, `HEL`이 도착한 관측에서 5바이트가 한 번에 연속 데이터가 된다. 단위 테스트에서 실제 바이트 `HELLO`를 확인하며 CLI는 payload 원문을 출력하지 않는다. 정상 예시의 최종 출력은 다음과 같다.

```text
reassembly_end flow_id=1 direction=fwd reason=capture_end stream_bytes=5 stream_new_bytes=0 stream_pending_bytes=0 stream_closed=1 issues=none
reassembly_summary bytes_emitted=5 overlap_conflicts=0 rejected=0 active=0 memory_bytes=0 peak_memory_bytes=73728
```

- 두 방향의 시퀀스/데이터를 분리하고 SYN·FIN의 시퀀스 소비와 32비트 순환을 처리한다. 중복은 새 바이트로 다시 내보내지 않으며 내용이 다른 overlap은 처음 받은 바이트를 유지하고 이벤트를 남긴다.
- SYN 없이 시작하면 `midstream`, 영구 누락은 종료 시 `gap`으로 표시한다. 중간부터 본 스트림 앞에 뒤늦은 과거 데이터를 소급 붙이지 않는다. `stream_closed`는 관측 FIN 앞의 갭이 없다는 뜻이며 전체 세션·완전한 보안 검사의 성공이 아니다.
- `--tcp-stream-bytes N`은 방향별 첫 N바이트의 검사 깊이와 payload 보관 상한을 함께 정한다. 기본 65536이며 범위는 1~2147483647이다. 깊이 밖은 `depth_limit`이다. 이미 내보낸 앞부분도 이 깊이 안에서는 overlap 비교를 위해 유지한다.
- `--tcp-memory-bytes N`은 payload 배열과 존재 비트맵의 전체 합계 예산이다. 기본 134217728이며 방향당 기본 할당은 65536+8192=73728바이트다. 첫 허용 payload에서 할당하고 부족하면 `memory_limit` 후 해당 방향을 재시작하지 않는다. Flow 메타데이터는 `--max-flows`로 제한하며 전체 RSS 상한을 보장하지 않는다.
- `reassembly_event`의 reason과 패킷/종료 줄의 `issues`에 관측 한계를 표시한다. 실제 TCP 수신자와 같은 OS 정규화·ACK/window 검증은 하지 않는다. 출력은 A5 JSONL 형식이 아니다.
- Flow 만료 시 해당 버퍼를 제거한다. RST는 양방향 배열을 즉시 해제하고 EOF는 남은 상태를 모두 정리한다. Flow 요약의 active는 마지막 시각의 Flow 수이고, 재조립 요약의 active/memory_bytes는 EOF 정리 뒤 값이다.
- 현재 룰이나 DROP은 없다. 향후 stream 룰이 나누어진 데이터를 탐지해도 이미 통과한 앞 패킷은 소급 차단할 수 없다.

제한을 재현하려면 정상 예시에 `--tcp-stream-bytes 4 --tcp-memory-bytes 5` 또는 `--tcp-memory-bytes 1`을 추가한다. 앞의 경우 4바이트 prefix와 depth_limit을, 뒤의 경우 배열 미할당과 memory_limit을 확인할 수 있다. 두 경우 모두 파일 EOF 성공이 완전한 스트림 검사를 의미하지 않는다.

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

clang-tidy를 포함한 Release 빌드:

```bash
cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_CLANG_TIDY=ON
cmake --build build-release --parallel 2
ctest --test-dir build-release --output-on-failure --no-tests=error
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

`format-check`는 clang-format이 있을 때 생성된다. 정적 분석 옵션을 켰는데 clang-tidy가 없으면 configure가 실패한다. [CI](.github/workflows/ci.yml)에도 연결되어 있지만 실제 CI 실행 결과는 없다.

## 기록

- [설계 결정과 사용자 승인 예외](docs/design-decisions.md)
- [알려진 한계](docs/known-limitations.md)
- [테스트 계획·실행 결과](docs/test-plan.md)
- [A0 명령 원본 결과](docs/a0-validation.json)
- [A0 Linux 빌드·검사 결과(2026-11-05)](docs/a0-validation-2026-11-05-linux.json)
- [A1 명령 원본 결과](docs/a1-validation.json)
- [A1 인수 검토·Linux 실행 결과(2026-11-05)](docs/a1-validation-2026-11-05-linux.json)
- [A1 구현 계획](docs/superpowers/plans/2026-11-03-a1.md)
- [A2 승인 설계](docs/superpowers/specs/2026-11-05-a2-design.md)
- [A3 승인 설계](docs/superpowers/specs/2026-11-07-a3-design.md)
- [A3 실행 계획](docs/superpowers/plans/2026-11-07-a3.md)
- [A3 실행 증거](docs/a3-validation-2026-11-07.json)
- [A4 승인 설계](docs/superpowers/specs/2026-11-07-a4-design.md)
- [A4 실행 계획](docs/superpowers/plans/2026-11-07-a4.md)
- [A4 실행 증거](docs/a4-validation-2026-11-07.json)
- [A2 구현 계획](docs/superpowers/plans/2026-11-06-a2.md)
- [A2 실행 결과](docs/a2-validation-2026-11-06.json)
- [고정 테스트 바이트 설명](tests/fixtures/README.md)

A0~A4는 인수 검증을 완료했다. 다음 A5 JSONL 로그·파이프라인 통합은 별도 사용자 지시 후 진행한다. A8까지 IPS를 먼저 완성하고 사용자 자체 테스트 뒤 AI 착수 지시를 기다린다.
