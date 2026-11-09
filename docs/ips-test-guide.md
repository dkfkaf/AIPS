# IPS 사용자 자체 테스트 가이드

대상: A0~A8 C++ 엔진. AI 모델·추론 서버·UDS는 필요하지 않다. Windows에서는 프로젝트를 WSL Ubuntu의 Linux 경로로 연다. 일반 PCAP 검사에는 root 권한이 필요 없다. 실제 수집/차단 검사는 아래처럼 새 network namespace 안에서만 실행한다.

## 1. 빌드와 기본 검사

Ubuntu24.04 호환 환경에서 README의 개발 의존성 설치 후 저장소 루트에서 실행한다. Python3는 프로세스/안전 검증기에 필요하다. 측정에는 별도 GNU time 실행 파일(/usr/bin/time)이 필요하며 없으면 Ubuntu의 time 패키지를 준비한다.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --no-tests=error
cmake --build build --target format-check
./build/miniips --help
./build/miniips --version
```

Python3가 있는 전체 기본 CTest 수는 A8 기준262개다. 권한이 필요한 실제 수집·차단 검사는 이 수에 포함하지 않는다. 종료0/실패0/disabled0/skip0을 확인한다. 의존성/커널/권한 실패를 탐지 코드의 성공으로 기록하지 않는다.

## 2. 먼저 PCAP으로 확인

```bash
./build/tests/miniips_fixture_writer ./build/tests/fixtures
./build/miniips --mode pcap --input build/tests/fixtures/rules_packet.pcap \
  --rules rules/example.json --log -
./build/miniips --mode pcap --input build/tests/fixtures/jsonl_pipeline.pcap \
  --rules rules/a5-demo.json --max-flows 1 --tcp-stream-bytes 16 --log -
```

첫 예제는 BLOCKME의 시뮬레이션 Drop이다. 둘째는 이벤트7종, 탐지2, 시뮬레이션 Drop3을 확인하는 고정 입력이다. **PCAP/live의 Drop은 실제 차단이 아니며 enforced=false, actual_drop_packets=0이다.** 로컬 PCAP 경로로 바꿔 반복할 수 있지만 입력을 검사 가능한 범위로 제한한다.

파일 로그는 --log NEW_PATH로 새 파일을 지정한다. 기존 파일은 보존을 위해 거부한다. 줄마다 JSON 객체가 하나인지 확인한다. stdout JSONL 사용 시 사람용 요약은 stderr로 나온다. JSON stats의 log_status_at_emit는 그 행 생성 시점이고, 최종 flush/close 성공은 stderr의 logger_summary log_complete=1 및 종료 코드로 확인한다.

## 3. 격리 라이브 IDS

다음 명령은 root 또는 새 namespace/링크를 생성하고 캡처할 수 있는 권한이 필요하다. 호스트 token은 unshare 전에 읽는다. 스크립트는 같은 namespace나 최적화된 Python 실행을 거부한다. 호스트 인터페이스 이름을 넣을 필요가 없다.

```bash
export MINIIPS_A6_HOST_NETNS=$(readlink /proc/self/ns/net)
sudo --preserve-env=MINIIPS_A6_HOST_NETNS unshare --net -- \
  python3 tests/check_live_process.py build/miniips build/tests/fixtures rules/a5-demo.json
```

root Linux 셸이라면 sudo --preserve-env=... 부분을 생략한다. 예상 결과는 cases11/failed0/isolated=true, 실제 차단0이다. 외부 연결 없이 스크립트 전용 veth에서 검사하고 namespace 종료로 링크가 사라진다.

## 4. 격리 실제 차단

커널 NFQUEUE/nft_queue와 nft 실행 파일이 필요하다. nft가 없으면 [README](../README.md)의 패키지 다운로드/추출 예시를 사용한다. 서비스 설치나 호스트 ruleset flush를 하지 않는다. 아래는 A7에서 추출한 도구를 재사용하는 예시다. 시스템 nft를 쓰면 nft 경로를 /usr/sbin/nft로 바꾸고 LD_LIBRARY_PATH를 생략한다.

```bash
export LD_LIBRARY_PATH="$PWD/build-a7-work/tools/root/usr/lib/x86_64-linux-gnu"
export MINIIPS_A7_HOST_NETNS=$(readlink /proc/self/ns/net)
sudo --preserve-env=MINIIPS_A7_HOST_NETNS,LD_LIBRARY_PATH unshare --net -- \
  python3 tests/check_inline_process.py build/miniips rules/a7-demo.json \
  build-a7-work/tools/root/usr/sbin/nft
sudo --preserve-env=MINIIPS_A7_HOST_NETNS,LD_LIBRARY_PATH unshare --net -- \
  python3 tests/check_inline_tcp.py build/miniips rules/a8-baseline.json \
  build-a7-work/tools/root/usr/sbin/nft
```

sudo 정책이 LD_LIBRARY_PATH 보존을 금지하면 root Linux 셸에서 위 환경 변수를 설정한 뒤 sudo 부분을 생략한다. 검증에 사용한 경로는 root WSL 셸이며 sudo 경로는 환경별 별도 확인이 필요하다.

첫 검사는 cases14/failed0, 표준 UDP4개 중 실제3허용/1차단이다. 두 번째는 TCP 정상·Pass·Alert, packet Drop, HEL 전달 후 LO stream Drop, 제한된 수신 소켓 압박의4시나리오다. TCP 재전송 때문에 실제 Drop 횟수는1보다 클 수 있다. 이미 전달된 HEL을 소급 차단했다고 해석하지 않는다.

압박 시나리오는 reader를 잠시 멈추고 합성 UDP16384개를 보낸다. 의도적인 수신 오류로 자식 miniips는 코드1/불완료를 보고해야 하며, 검증기 전체는 이 기대 동작을 확인한 후 성공한다. 무손실/자동 복구를 입증하는 시험이 아니다. finally에서 자식을 정리하고 전용 table만 삭제한다. 예외나 강제 종료로 프로세스가 남았다면 해당 시험 프로세스만 종료한다. 호스트 방화벽 복구 명령이나 전체 flush는 사용하지 않는다.

## 5. Release·sanitizer와 기준 성능

```bash
cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_CLANG_TIDY=ON
cmake --build build-release --parallel 2
ctest --test-dir build-release --output-on-failure --no-tests=error
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DMINIIPS_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel 1
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-sanitize --output-on-failure --no-tests=error
mkdir -p build-user-test
python3 tools/benchmark_pipeline.py build-release/miniips rules/a8-baseline.json \
  build-user-test/performance-new.json --packets 50000 --repeats 5
```

실제 격리 검증기도 binary/fixture 경로를 각 빌드로 바꿔 반복한다. sanitizer의 위 두 환경 변수는 해당 자식 프로세스까지 export한다. 성능 측정은 다른 빌드/테스트 부하가 끝난 후 실행한다. 결과는 합성 PCAP/로그 직렬화/프로세스 시작을 포함한 로컬 기준이다. wall/N 평균 환산 비용은 개별 패킷 지연이나 p99가 아니다. 보고서가 이미 있으면 새 이름을 사용한다.

## 6. 결과를 전달할 때

- 소스 커밋/변경 여부, Linux·커널·CPU·메모리와 빌드 종류
- 실행 명령, 입력 PCAP/룰 해시, 기대 결과와 실제 결과
- 종료 코드, stderr 요약, 필요 최소 JSONL 이벤트(민감한 원본 payload는 제외)
- 재현 빈도, 최초 실패 시점, 성능 보고서 및 미실행 항목

사용자 자체 테스트 결과를 확인하고 AI 단계 착수 지시를 받기 전에는 데이터셋 준비나 모델 학습을 시작하지 않는다. [완료 증거](a8-validation-2026-11-09.json), [알려진 한계](known-limitations.md), [Flow 관찰 계약](flow-observation.md)을 함께 참고한다.
