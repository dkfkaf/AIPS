# PROJECT_SPEC.md — MiniSuricata-AI 기능·아키텍처 명세

> **버전:** 2.4 · 2026-10-30 · Precision AI 참고형 하이브리드 탐지 설계 추가  
> **개발 목표:** Suricata에서 착안한 **독립 C++20 경량 IDS/IPS 6기능** + 기존 룰의 미탐을 보완하는 **Python/PyTorch AI** + **UDS 연동**  
> **확정 요구:** **C++ 엔진 → AI 학습 → 연동** 순서 · AI는 첫 단계에서 경고만 출력 · 자동 차단은 성능 검증 후 선택  
> **AI 코딩 작업 규칙:** [`AGENTS.md`](AGENTS.md)  
> **코딩 컨벤션·안전 코딩:** [`CODING_STYLE.md`](CODING_STYLE.md)  
> **단계별 구현 순서/검증/프롬프트:** [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)

**명세의 경계:** 기능 계약과 시스템 설계는 이 문서가 정의하며, 개발 작업 순서 및 진행 허가는 `IMPLEMENTATION_PLAN.md`가 정의한다. 실제 구현 가능성이 검증되지 않은 데이터셋 매칭/AI 탐지 성능/실시간 차단은 **미확정**이다.

**외부 설계 참고:** Palo Alto Networks의 Precision AI / Advanced Threat Prevention에서 공개한 **시그니처 기반 탐지와 로컬 딥러닝의 보완적 결합**이라는 설계 원칙을 참고한다. 공개되지 않은 모델 구조·학습 데이터·가중치·상용 기능을 재현했다고 주장하지 않는다.

---

## 1. 프로젝트 목표와 범위

### 1.1 필수 기능

| ID | 핵심 기능 | 구현 완료 기준 |
|---|---|---|
| F-01 | 패킷 수집 및 파싱 | PCAP 파일과 네트워크 인터페이스에서 IPv4 TCP/UDP 패킷을 읽고 헤더/페이로드를 안전하게 파싱한다. |
| F-02 | 연결별 Flow 추적 | 출발지/목적지 IP·포트·프로토콜에 따라 양방향 통신을 동일 Flow로 관리하고 타임아웃으로 정리한다. |
| F-03 | TCP 세션 재조립 | TCP 시퀀스 번호를 고려해 방향별 데이터 순서를 복원하고 분할·재전송·순서 뒤바뀜을 제한적으로 처리한다. |
| F-04 | 룰 기반 악성 트래픽 탐지 | 직접 정의한 **JSON 룰 형식**으로 헤더 조건 및 페이로드의 바이트 패턴을 검사한다. |
| F-05 | Inline 패킷 차단 및 허용 | Linux NFQUEUE에서 룰 결과에 따라 `ACCEPT`/`DROP` verdict를 내려 실제 패킷 처리에 반영한다. |
| F-06 | 탐지 이벤트·로그 생성 | 탐지, 허용/차단, 오류, 통계 이벤트를 JSON Lines 파일로 기록한다. |

### 1.2 프로젝트 최종 목표: 규칙 탐지 + AI 추가 탐지

- **룰 엔진:** 사람이 작성한 룰과 정확히 일치하는 패턴을 탐지하고, 테스트 환경에서 패킷을 차단한다.
- **AI 엔진:** 룰만으로 탐지하지 못한 *추가적인 악성 Flow/행동*을 확률 또는 이상점수로 탐지한다.
- **연동:** C++ 엔진의 Flow 통계를 Python 추론 서비스에 전달하고, AI 결과를 별도 탐지 이벤트로 기록한다. AI에 의한 Inline 차단은 검증 뒤에만 옵션으로 허용한다.
- **정직한 성능 주장:** 탐지율 향상은 반드시 **동일한 평가 데이터에서 룰 단독과 룰+AI를 비교**해서 증명한다. 새 공격(미학습 공격) 탐지는 별도 검증 없이는 주장하지 않는다.

#### 1.2.1 Precision AI에서 참고하는 원칙과 제외 범위

| 공개된 설계 방향에서 참고할 요소 | 우리 프로젝트의 대응 | 구현 단계 |
|---|---|---|
| 시그니처 기반 기존 공격 탐지 | C++20 `RuleEngine`이 탐지·기본 verdict 소유 | A단계 필수 |
| 딥러닝을 활용한 추가 탐지 | Python/PyTorch가 룰의 미탐을 **Flow 통계 기반으로 보완** | B/C단계 필수 |
| 로컬 추론으로 주 처리 경로와 분석 분리 | UDS를 통한 별도 Python 프로세스, 비동기·bounded queue | C단계 필수 |
| 의심 트래픽 선별 분석 | **후속 최적화 후보**: AI 후보 Flow 선별 게이트 | C4 실측 후 선택 |
| 더 복잡한 순차 통신 패턴 분석 | 1D-CNN/GRU 등 시퀀스 모델 **후속 연구 후보** | MVP 이후 선택 |

**중요한 차이:** 우리는 상용 Precision AI를 복제하지 않으며, 벤더의 비공개 모델을 사용하지 않는다. 최초 MVP는 **16개 통계 특징의 MLP**와 **AI 경고 전용(shadow/alert)**이다. 클라우드 분석, 지능형 제로데이 탐지, 페이로드 기반 SQL/Command Injection 판정, AI 즉시 차단은 현재 요구사항이 아니다.

### 1.3 의도적으로 제외할 범위

- IPv6, IP 조각(fragment) 재조립, HTTP/DNS/TLS 전문 파서, TLS 복호화
- QUIC, HTTP/2, SSH 등의 응용계층 복호·파싱
- Suricata `.rules` 전체 문법, PCRE, 다중 패턴 매칭 엔진(Hyperscan 등)
- 커널 eBPF/XDP/DPDK/AF_XDP, GPU·멀티프로세스 최적화
- 분산 수집, 웹 대시보드, 데이터베이스, 사용자 계정·권한 관리
- 고가용성, 무손실 처리, 기업·상용망 수준의 우회 방지·성능 보장
- AI를 통한 악성코드 파일 분석, 자동 룰 생성, LLM 판정, 실서비스 자동 차단 보장

**범위 밖 트래픽에 대한 정책:** 미지원 링크 계층, IPv6, IPv4 fragment, 잘못된 패킷은 원인을 이벤트로 기록한다. MVP 기본 정책은 **허용 또는 분석 건너뛰기**이며, 이러한 트래픽을 탐지·차단했다고 주장하지 않는다. 실제 운영망에는 이 상태로 배포하지 않는다.

---

## 2. 기술 스택과 실행 환경

| 계층 | 선택 기술 | 용도 |
|---|---|---|
| 언어 | **C++20** | 패킷 처리·Flow·재조립·룰 엔진·로그 전반 |
| AI 개발 언어 | **Python 3 + PyTorch** | Flow 특징 기반 모델 학습·평가·추론 |
| AI 데이터 처리 | pandas, NumPy, scikit-learn | 데이터 전처리·스케일러·지표 계산(모델 학습은 PyTorch) |
| 통신 연동 | Unix Domain Socket + 버전형 JSONL 프로토콜 | C++ 프로세스와 Python 추론 서버 분리 |
| 운영체제 | Ubuntu 24.04 LTS 또는 호환 Linux | 개발/테스트 |
| 빌드 | CMake ≥ 3.22, Ninja, GCC/Clang | 빌드·의존성 관리 |
| 패킷 수집 | **libpcap** | 오프라인 PCAP, 라이브 IDS |
| 실제 IPS | **libnetfilter_queue + nftables** | NFQUEUE 수신 및 verdict |
| JSON | **nlohmann/json** | 룰 로드, JSON Lines 로그 직렬화 |
| 내부 로그 | **spdlog** | 개발자용 콘솔/오류 출력 |
| 테스트 | **GoogleTest + CTest** | 단위·통합 테스트 |
| 품질 | clang-tidy, clang-format, ASan, UBSan | 정적 검사·메모리 오류 탐지 |
| 버전 관리 | Git, GitHub Actions | 변경 이력 및 CI |

**기본 구현 방침**

- `libpcap`과 `libnetfilter_queue`는 C 라이브러리이므로 **C++ RAII 래퍼**를 둔다.
- 패킷 파싱에 `reinterpret_cast`를 이용한 비정렬 헤더 직접 참조를 피한다. **길이를 검사한 뒤 안전하게 바이트를 읽고** 네트워크 바이트 순서를 변환한다.
- `std::span<const std::byte>`는 **일시적인 읽기 전용 뷰**로 사용한다. 콜백이 끝난 뒤에도 패킷 데이터를 보관해야 한다면 소유 버퍼(`std::vector<std::byte>` 등)에 복사한다.
- `std::unordered_map`으로 Flow를 관리하되, 해시 테이블 크기·사용 메모리에 상한을 둔다.
- 첫 버전은 단일 처리 스레드로 작성한다. 병렬화는 정확성·테스트가 끝난 뒤 고려한다.

---

## 3. 전체 처리 아키텍처

```text
                     [입력 어댑터]
             +-----------+-----------+
             |           |           |
         PCAP 파일   Live libpcap  NFQUEUE
             |           |           |
             +-----------+-----------+
                         |
                   PacketEnvelope
               (L2 / L3 시작점 명시)
                         |
                    PacketParser
             (Ethernet/IPv4/TCP/UDP)
                         |
                     FlowTable
              (양방향 Flow/상태/만료)
                         |
                  TCPReassembler
            (방향별 순서 복원/상한 관리)
                         |
                      RuleEngine
            (packet 범위 + stream 범위)
                         |
                  DetectionDecision
                   /           \
              EventLogger    VerdictAdapter
              JSON Lines       /       \
                           PCAP/IDS   NFQUEUE
                           시뮬레이션  ACCEPT/DROP
```

**C단계에서 추가되는 AI 우회 경로(초기 C++ 데이터 경로는 유지):**

```text
                         C++20 miniips
패킷 → 파싱 → FlowTable → TCP 재조립 → 룰 엔진 → 기본 판정
                   │
                   └→ FlowFeatureExtractor → (유한 큐) → Unix Socket
                                                        │
                                                Python AI Service
                                             전처리 → PyTorch 추론
                                                        │
                             AI 점수/모델 버전 ←──────────┘
                                   │
                         C++ AI Result Handler
                         ├→ ai_alert 로그 (기본: shadow)
                         └→ (검증 이후 선택) 향후 패킷 차단
```

- AI는 **원시 패킷 전체** 대신 재현 가능한 **Flow 통계 벡터**를 받는 것을 기본으로 한다.
- **룰 `drop`은 AI보다 우선한다.** AI 장애는 룰 탐지를 멈추지 못한다.
- 초기 C단계에서 AI는 `shadow`(기록만) 모드다. 자동 차단은 별도 승인·성능 검증 이후의 실험 기능이다.
- Flow가 종료된 후에만 내린 AI 판단은 **사후 탐지**다. 실시간 IPS 성능이라고 표현하지 않는다.
- **초기 C단계에서는 평가 편향을 막기 위해** 스키마에 맞는 Flow 스냅샷을 룰 탐지 여부와 무관하게 AI에 제출한다(유한 큐·샘플링 한도 내). 룰이 탐지한 Flow도 AI 단독·결합 지표 계산에 사용하되 중복 탐지로 세지 않는다.
- 향후 **후보 Flow 선택 게이트**(예: 명시적 `pass` 제외, 위험 통계 기반 우선순위)는 별도 정책으로 추가할 수 있다. 정확도·오탐·커버리지·지연에 미치는 영향을 먼저 비교한다.

**계층별 책임 구분**

- **입력 어댑터:** 패킷을 전달한다. IPS 정책을 결정하지 않는다.
- **PacketParser:** 안전하게 구조를 해석한다. 탐지 룰을 알지 못한다.
- **FlowTable:** 통신 흐름의 식별과 수명주기를 관리한다.
- **TCPReassembler:** 방향별 TCP 데이터 순서를 관리한다.
- **RuleEngine:** 정규화된 메타데이터/바이트 시퀀스를 검사하고 `RuleMatch`를 생성한다.
- **Policy/Decision:** 일치한 룰의 우선순위에 따라 `Allow` 또는 `Drop`을 결정한다.
- **VerdictAdapter:** 실제 OS verdict 전달은 **Inline 모드에서만** 수행한다.
- **EventLogger:** 결과를 기록한다. 실패하더라도 verdict 의무를 방해하지 않는다.

---

## 4. C++ IDS/IPS 6기능 상세 요구사항

### F-01. 패킷 수집 및 파싱

**기본 지원**

1. `--mode pcap --input <file.pcap>`으로 PCAP 파일을 처음부터 끝까지 분석한다.
2. `--mode live --interface <name>`으로 libpcap에서 패킷을 수동 수집한다(IDS 전용).
3. PCAP/Live 입력의 첫 버전은 Ethernet(`DLT_EN10MB`)만 정식 지원한다. 링크 계층 종류가 다르면 지원하지 않는다고 출력한다.
4. NFQUEUE 입력은 보통 **L3 IPv4 패킷**부터 시작한다. Ethernet 헤더가 있다고 가정하지 않는다.
5. IPv4 헤더의 Version, IHL, Total Length, Protocol, 주소를 검사한다.
6. TCP 헤더의 포트, 시퀀스 번호, ACK 번호, Flags, Data Offset 및 페이로드 범위를 검사한다.
7. UDP 헤더의 포트, Length, 페이로드 범위를 검사한다.
8. 캡처 길이보다 큰 오프셋을 절대 읽지 않는다. 잘린 PCAP·깨진 패킷은 오류 이벤트를 남기고 안전하게 건너뛴다.

**테스트:** 정상 TCP/UDP, 비정상 IHL, 잘린 Ethernet/IPv4/TCP/UDP 헤더, 잘못된 UDP 길이, IPv4 fragment, 미지원 Ethernet 타입.

### F-02. 연결별 Flow 추적

- Flow 식별에는 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`을 사용한다.
- 반대 방향의 패킷도 **동일한 양방향 Flow**에 속해야 한다. 단, 스트림 버퍼는 두 방향으로 분리한다.
- 새 Flow에는 고유 `flow_id`, 시작 시각, 마지막 시각, 방향별 패킷/바이트 수를 기록한다. **후속 AI의 Flow 특징을 계산할 수 있게 타임스탬프, 패킷 길이 합계, SYN/ACK/RST/FIN/PSH 카운터, 패킷 간 도착 시간(IAT) 집계 상태도 설계에서 고려**하되, A단계에서는 외부 AI 통신을 구현하지 않는다.
- TCP의 SYN/ACK/FIN/RST를 이용해 **단순화된 연결 상태**를 보관하되, 완전한 TCP 상태 머신인 것처럼 표현하지 않는다.
- 유휴 Flow 제거, 전체 Flow 수 제한, Flow별 메모리 제한을 구현한다.
- 기본값 예시: 최대 Flow **10,000개**, 유휴 만료 **120초**, 방향별 재조립 데이터 **64 KiB**, 전체 재조립 메모리 **128 MiB**. 값은 설정 가능해야 한다.
- IP와 포트를 단순 문자열로 이어붙인 키를 쓰지 않는다. 명시적 구조체와 해시·동등 비교를 구현한다.

**테스트:** 동일 방향 / 반대 방향 / 다른 포트 / 다른 프로토콜 / 만료 / 용량 초과.

### F-03. TCP 세션 재조립

- **방향별** TCP 시퀀스 번호를 추적한다.
- 같은 데이터가 여러 패킷으로 나뉘어 들어와도 이어 붙인 바이트 시퀀스를 검사할 수 있어야 한다.
- 중복 재전송은 동일 바이트를 두 번 추가하지 않는다.
- 순서가 바뀐 세그먼트는 지정된 메모리 범위에서 보관하고, 누락 구간이 도착하면 연결한다.
- 시퀀스 번호 **32비트 wrap-around**를 고려한 비교 함수를 작성하고 경계 테스트를 추가한다.
- 서로 다른 내용이 겹치는 세그먼트(overlap conflict)는 이벤트로 기록하고, **first-seen 정책**을 문서화한다. 복잡한 OS별 TCP 정규화는 구현하지 않는다.
- 버퍼 상한, 재조립 깊이, 유휴 만료 시 보관 데이터를 정리한다.
- 부분 수집(중간에 시작한 TCP 세션), 영구 누락(gap), 비정상 세그먼트는 `reassembly_incomplete` 등으로 표시하고, 완전한 검사인 것처럼 취급하지 않는다.

**중요:** `stream` 룰이 `HEL` + `LO`를 탐지할 수 있어도, 첫 번째 세그먼트가 이미 통과했다면 **두 번째 세그먼트만 DROP**할 수 있다. 프로젝트 완료 보고서와 로그에 이 제약을 명시한다.

**테스트:** 정상 순서, 역순, 중복, 일부 겹침, 내용이 다른 겹침, 누락, wrap-around, 메모리 상한.

### F-04. 룰 기반 악성 트래픽 탐지

Suricata 고유 `.rules`를 흉내 내지 말고 **독립적인 소형 JSON 룰 형식**을 사용한다.

**MVP 룰 필드**

| 필드 | 형식 | 의미 |
|---|---|---|
| `sid` | 양의 정수 | 중복 불가 룰 ID |
| `enabled` | boolean | 룰 사용 여부 |
| `priority` | 정수 | 오름차순 평가 (낮은 수가 먼저) |
| `action` | `alert` / `drop` / `pass` | 경고 / 차단 / 허용 |
| `protocol` | `tcp` / `udp` / `any` | 프로토콜 조건 |
| `src_port`, `dst_port` | 정수 또는 생략 | 포트 조건 |
| `scope` | `packet` / `stream` | 검사 범위 |
| `content` | ASCII 문자열 | 대소문자 구분 바이트 일치 패턴 |
| `message` | 문자열 | 이벤트 설명 |

- `scope=stream`은 **TCP 전용**이다. UDP에 사용된 경우 룰 로딩을 거부한다.
- `protocol=any`라도 `scope=stream`이면 실제 검사는 TCP에서만 수행되도록 검증한다. 혼란을 피하려면 해당 조합은 룰 로딩 시 거부해도 된다(동작을 문서화할 것).
- `content`는 MVP에서 **출력 가능한 ASCII 바이트**만 지원한다. 바이너리 이스케이프와 Unicode 정규화는 제외한다.
- 룰 로드 시 필수 필드·자료형·유효 범위·중복 SID를 검사하고, 잘못된 룰 파일은 **전체 로딩 실패**로 처리한다.
- 정책은 `priority` 오름차순, 같다면 `sid` 오름차순이다. 평가 순서대로 `alert`는 이벤트만 추가하고 계속 검사한다. `drop` 또는 `pass`가 발견되면 결정을 확정하고 평가를 종료한다. 매치가 없으면 `Allow`다.
- `alert`는 경고만 생성하며 단독으로는 패킷을 차단하지 않는다.
- 동일 스트림 검사 영역의 동일 룰이 지나치게 중복 발화하지 않도록 기본 중복 억제 정책을 만든다(예: `flow_id + direction + sid + match end-offset`).

**예시 룰 (`rules/example.json`)**

```json
{
  "rules": [
    {
      "sid": 1001,
      "enabled": true,
      "priority": 100,
      "action": "alert",
      "protocol": "tcp",
      "dst_port": 8080,
      "scope": "stream",
      "content": "HELLO",
      "message": "Demo TCP stream pattern detected"
    },
    {
      "sid": 1002,
      "enabled": true,
      "priority": 200,
      "action": "drop",
      "protocol": "tcp",
      "scope": "packet",
      "content": "BLOCKME",
      "message": "Demo payload block rule"
    }
  ]
}
```

**테스트:** 룰 파싱 실패, SID 중복, 조건 미일치, 경고, 차단, 명시적 허용, 우선순위, 패킷/스트림 검사 차이, 동일 탐지 중복 억제.

### F-05. Inline 패킷 차단 및 허용

**MVP 구현**

1. Linux `libnetfilter_queue`로 지정한 Queue 번호의 IPv4 패킷을 수신한다.
2. 패킷을 PacketParser → FlowTable → Reassembler → RuleEngine으로 전달한다.
3. 결과가 `Drop`이면 NFQUEUE의 `NF_DROP`, 그 외에는 `NF_ACCEPT` verdict를 보낸다.
4. 각 수신 패킷에 대해 **verdict를 정확히 한 번 내리는 제어 흐름**을 설계한다. 로깅 실패나 예외가 verdict 누락으로 이어지지 않아야 한다.
5. `--mode inline`은 **명시적 위험 확인 옵션**(`--enable-inline`)을 요구하고, 관리자 권한·큐 바인딩 실패를 명확히 출력한다.
6. 응용프로그램이 죽거나 큐가 가득 찬 상황의 동작은 nftables 정책과 커널 큐 동작에 좌우된다. `bypass` 옵션 사용 여부, Fail-open/Fail-closed 한계를 **README에 명시**한다.
7. 방화벽 큐 규칙 추가·삭제는 **별도 테스트용 스크립트**로 분리한다. 본 프로그램이 호스트 방화벽 정책을 자동 수정하지 않는다.
8. 테스트 스크립트는 **격리된 network namespace에서만** 실행하며, 생성한 namespace·규칙만 정리한다. 사용자의 기존 호스트 nftables 전체 규칙을 삭제하거나 flush하지 않는다.

**허용할 주장:** 선택한 IPv4 패킷이 테스트 환경에서 NFQUEUE를 경유했고, 지정한 `drop` 룰로 차단되었음을 재현 가능한 통합 테스트로 증명한다.

**허용하지 않을 주장:** 모든 TCP 공격 페이로드 차단, IPv6까지 보호, 네트워크 전 구간 보안 보장, Suricata와 동등한 IPS 성능.

**테스트:** 테스트 namespace 내 정상 통신 허용, `BLOCKME` 패킷 차단, 정책 미일치 허용, 엔진 시작/중지 시 오류 보고, verdict 카운터 일치.

### F-06. 탐지 이벤트·로그 생성

- 로그는 **JSON Lines**: 한 줄에 한 JSON 객체를 저장한다.
- 최소 이벤트 종류: `alert`, `verdict`, `flow`, `parse_error`, `reassembly_warning`, `stats`, `engine_error`. **C단계에서** `ai_alert`, `ai_verdict`, `ai_error`, `ai_stats`를 추가한다.
- 최소 필드: `timestamp`, `event_type`, `flow_id`(해당 시), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `mode`, `action`, `sid`(해당 시), `message`.
- `mode=pcap/live`에서 표시하는 `drop`은 **시뮬레이션 판정**이며 실제 차단이 아님을 `enforced: false`로 구별한다. `mode=inline`에서 실제 verdict에 성공했을 때만 `enforced: true`로 기록한다.
- 로그는 **Suricata EVE JSON과 완전 호환되는 형식이 아니라**, EVE를 참고한 자체 JSON Lines 스키마다.
- 로그에 원본 페이로드 전체를 기본 저장하지 않는다. 패킷 내용은 민감정보가 있을 수 있으므로 최소 메타데이터 위주로 기록한다.
- JSON 출력 실패는 오류 카운터에 반영하고, Inline verdict 처리를 막지 않는다.
- 종료 시 총 패킷 수, 파싱 실패 수, 생성/만료 Flow 수, 탐지 수, 시뮬레이션 차단 수, 실제 NFQUEUE 차단 수를 요약한다.

**예시 이벤트**

```json
{"timestamp":"2026-10-26T11:00:00Z","event_type":"alert","mode":"pcap","enforced":false,"flow_id":"flow-42","src_ip":"10.0.0.2","src_port":55555,"dst_ip":"10.0.0.3","dst_port":8080,"protocol":"tcp","action":"alert","sid":1001,"message":"Demo TCP stream pattern detected"}
```

---

## 5. 프로젝트 디렉터리 구조

```text
mini-suricata/
├── AGENTS.md
├── CODING_STYLE.md
├── PROJECT_SPEC.md
├── IMPLEMENTATION_PLAN.md
├── CMakeLists.txt
├── README.md
├── .clang-format
├── .clang-tidy
├── .gitignore
├── .github/
│   └── workflows/ci.yml
├── include/miniips/
│   ├── packet.hpp
│   ├── packet_parser.hpp
│   ├── capture_source.hpp
│   ├── flow.hpp
│   ├── flow_table.hpp
│   ├── tcp_reassembler.hpp
│   ├── rule.hpp
│   ├── rule_engine.hpp
│   ├── detection_decision.hpp
│   ├── event_logger.hpp
│   └── engine.hpp
├── src/
│   ├── main.cpp
│   ├── packet_parser.cpp
│   ├── pcap_source.cpp
│   ├── live_pcap_source.cpp
│   ├── nfqueue_source.cpp
│   ├── flow_table.cpp
│   ├── tcp_reassembler.cpp
│   ├── rule_engine.cpp
│   ├── event_logger.cpp
│   └── engine.cpp
├── rules/
│   └── example.json
├── config/
│   └── default.json
├── tests/
│   ├── test_packet_parser.cpp
│   ├── test_flow_table.cpp
│   ├── test_tcp_reassembler.cpp
│   ├── test_rule_engine.cpp
│   ├── test_event_logger.cpp
│   └── test_pipeline.cpp
├── tests/fixtures/
│   └── README.md
├── scripts/
│   ├── setup_dev.sh
│   ├── run_tests.sh
│   └── run_inline_netns_test.sh
├── ai/                           # B단계에서만 생성
│   ├── pyproject.toml
│   ├── README.md
│   ├── configs/train.yaml
│   ├── src/miniips_ai/
│   │   ├── features.py
│   │   ├── dataset.py
│   │   ├── model.py
│   │   ├── train.py
│   │   ├── evaluate.py
│   │   ├── inference.py
│   │   └── server.py             # C단계에서 구현
│   ├── tests/
│   │   ├── test_features.py
│   │   ├── test_preprocess.py
│   │   └── test_inference.py
│   └── artifacts/                # Git 추적 제외
├── protocol/                     # C단계: 양측의 공통 스키마
│   ├── flow_features.schema.json
│   ├── ai_request.schema.json
│   └── ai_response.schema.json
├── integration_tests/            # C단계에서만 생성
│   ├── test_ai_ipc.py
│   └── fixtures/
└── docs/
    ├── architecture.md
    ├── design-decisions.md
    ├── test-plan.md
    ├── known-limitations.md
    ├── ai-data-card.md           # 데이터 출처·라이선스·한계
    ├── ai-evaluation.md          # 룰 단독 대비 추가 탐지 검증
    └── integration-protocol.md
```

**디렉터리 원칙:** 헤더는 인터페이스, `src/`는 구현, `tests/`는 검증, `docs/`는 설계·한계 기록으로 구분한다. 빌드 산출물, 원본/가공 PCAP, CSV 대용량 데이터, 학습 모델, 비밀정보, 대용량 로그는 Git에 커밋하지 않는다. `ai/`는 A단계 진행 중 미리 구현하지 않는다.

---

## 6. CLI·설정 및 입출력 계약

### 6.1 실행 인터페이스

```bash
# 1. 가장 먼저 구현: 오프라인 탐지 및 시뮬레이션
./miniips --mode pcap \
  --input tests/fixtures/demo.pcap \
  --rules rules/example.json \
  --log events.jsonl

# 2. 수동 IDS: 실제 차단 없음
./miniips --mode live \
  --interface eth0 \
  --rules rules/example.json \
  --log events.jsonl

# 3. 격리 테스트 환경에서만 사용: 실제 Inline 차단
sudo ./miniips --mode inline \
  --queue-num 0 \
  --rules rules/example.json \
  --log events.jsonl \
  --enable-inline
```

- `pcap`에서 `--input`은 필수, `live`에서 `--interface`는 필수, `inline`에서 `--queue-num`과 `--enable-inline`은 필수다.
- 실행 전 규칙 파일·로그 경로 유효성을 검사하고, 사용자에게 명확한 사용법을 표시한다.
- `--help`, `--version`을 제공한다.

### 6.2 예시 설정 (`config/default.json`)

```json
{
  "flow": {
    "max_entries": 10000,
    "idle_timeout_seconds": 120
  },
  "reassembly": {
    "max_bytes_per_direction": 65536,
    "max_total_bytes": 134217728
  },
  "logging": {
    "log_payload": false,
    "stats_interval_seconds": 30
  }
}
```

- 설정 검증은 룰 검증과 분리한다. 알 수 없는 설정 키를 무시할지 거부할지 **명확히 정하고 문서화**한다(기본 권장: 거부).
- `parse_error`에 대한 최초 정책은 `Allow + 경고`로 하되, 탐지 한계 및 위험성을 README에 명시한다.

---

## 7. AI의 역할과 모델 기준

### B-01. 핵심 목표 및 책임

> **AI의 역할:** 이미 정의된 문자열/헤더 룰이 찾아내지 못하는 **악성 네트워크 통신의 통계적·행동적 징후**를 Flow 단위로 추가 탐지한다. AI는 기존 규칙 엔진을 대체하지 않고, **룰의 미탐(FN)을 줄이는 보조 탐지기**다.

- **입력:** 패킷의 실제 내용 전체 대신 C++ 엔진이 생성하는 양방향 Flow 특징 벡터(계약은 이 문서 8절).
- **출력:** 악성 추정 점수 `score` (0~1), 임계값에 따른 `suspicious`, 모델/특징 버전, 처리 정보.
- **탐지 단위:** `flow_id + snapshot_id`로 구분되는 Flow 통계 스냅샷.
- **기본 분류:** 정상(0) / 공격(1) **이진 분류**를 최초 기준 모델로 사용한다.
- **최종 행동:** B단계는 학습과 오프라인 성능 검증만 한다. C단계 연동 기본 정책은 **AI 경고 로그만 기록하는 `shadow` 모드**다.
- **필수 조건:** AI 추론기가 꺼져도 엔진의 기존 6가지 기능은 그대로 동작한다.

### B-02. 반드시 구분할 두 가지 AI 목표

| 목표 | 의미 | 적합한 기본 접근 | 주의점 |
|---|---|---|---|
| **A안: 시그니처 미탐 보완** | 룰이 놓친, **학습 데이터에 존재하는 공격 패턴**을 추가 탐지 | 지도학습 이진 분류(Multilayer Perceptron) | 학습하지 않은 공격 유형까지 잡는다는 보장은 없음 |
| **B안: 미지의 공격 탐지 연구** | 정상 Flow와 다른 행동을 이상으로 표시하여 **훈련에 포함되지 않은 공격 유형**도 시험 | 정상 데이터 중심 Autoencoder 등 이상 탐지 | 오탐 증가 가능성, 미지 공격 평가용 유형별 holdout 필수 |

**확정된 선택: A안.** 기존 IDS/IPS 룰이 놓친, **학습 데이터에 등장하는 공격 유형**을 추가 탐지한다. A단계에서 확정한 룰을 학습 및 평가 기간 내 고정하고, 전체 라벨 데이터로 지도학습한 뒤 **룰이 놓친 Flow 집합을 독립 테스트셋에서 따로 평가**한다. 단, 룰을 이미 맞힌 Flow를 인위적으로 제거해서 얻은 AI 수치를 전체 성능인 것처럼 보고하지 않는다. **B안(미학습 공격 제로데이 탐지)은 이번 버전의 요구사항이 아니며, 그 성능을 주장하지 않는다.**

### B-03. 탐지 대상과 비대상

- 초기 입력 프로토콜: **IPv4 TCP/UDP** (A단계에서 파싱하는 범위).
- AI가 관찰할 수 있는 신호: 양방향 패킷 수, 바이트 수, 흐름 지속시간, 패킷 간 간격(IAT), 패킷 길이 통계, TCP flag 빈도 등.
- 통계만으로 명확하게 구분하기 어려운 공격(페이로드 의미·암호화된 애플리케이션 내부 동작 등)은 **AI가 반드시 잡는다고 주장하지 않는다**.
- 실시간 네트워크 통계로 해결할 수 없는 공격은 입력 신호 부족을 우선 의심한다. 모델 크기를 키우는 것으로 자동 해결된다고 생각하지 않는다.
- **AI 학습·추론에 사용한 것과 동일한 특징 정의**가 온라인 C++ 구현과 오프라인 Python 추출기에서 성립해야 한다.

### B-04. 모델의 첫 번째 베이스라인

- 구현 언어: **Python 3**, 학습 프레임워크: **PyTorch**.
- 최초 신경망 모델: 작은 **MLP 이진 분류기** (예: 2~3 Dense 층, ReLU, Dropout, 1개 Logit).
- 학습 손실: `BCEWithLogitsLoss`; 클래스 불균형을 고려해 class weight/`pos_weight`를 실험하되 **검증 세트에서만** 채택한다.
- 손실 계산 전에 `sigmoid`를 중복 적용하지 않는다. 추론 출력 점수에는 sigmoid를 적용한다.
- 전처리: 학습 데이터에만 fit한 누락값 처리기/표준화 파라미터를 저장하고, 검증·테스트·서비스에서는 해당 변환을 재사용한다.
- 비교 기준: 단순 규칙 기반 baseline, **다수 클래스 예측이 아닌 이진 분류** 기준, 필요 시 로지스틱 회귀 같은 얕은 ML 비교 모델을 리포트에만 사용한다(주요 실제 서비스 모델은 PyTorch).
- 학습 후 `model.eval()` 및 `torch.inference_mode()`를 함께 사용한다. (`inference_mode`는 평가 모드 전환을 대신하지 않음.)
- 모델 버전마다 무작위 시드, 환경 의존성 잠금, 특징 목록과 순서, 전처리기, 의사결정 임계값, 학습 코드 커밋 ID를 기록한다.
- 정확도(accuracy) **한 지표만**으로 학습 성공을 판정하지 않는다.

### B-05. Precision AI 참고형 평가·운영 원칙

- **기본 모델 변경 없음:** 16개 Flow 통계 특징을 이용하는 **이진 분류 MLP**를 첫 모델로 유지한다.
- **AI 역할 유지:** RuleEngine이 명시적 공격으로 탐지하지 못한 **공격 Flow에 대한 추가 경고**를 목표로 한다. AI가 룰을 이미 맞힌 Flow를 맞혔다고 해서 추가 TP로 집계하지 않는다.
- **검증 우선:** 정상 Flow의 추가 오탐 비용을 기준으로 Validation에서 임계값을 선택한다. 공격 검출율만 높이기 위한 임의 threshold 하향은 금지한다.
- **선별의 효과 검증:** 처음부터 룰 미탐 Flow만 AI로 보내면 AI 단독 성능·선별 누락을 관찰하기 어렵다. C단계 기본 shadow에서 **후보 전체**를 평가하고, 이후 별도 후보 게이트를 비교 실험한다.
- **운영 표현 주의:** `suspicious=true`는 모델의 추정이지 공격의 확정 증거나 제로데이 판정이 아니다.

### B-06. 후속 연구 후보 — 시퀀스 기반 탐지 (MVP 비필수)

- **검토 조건:** C4 결과에서 MLP의 추가 탐지 이득이 제한적이고, 그 원인이 시간 순서 정보 손실이라는 실증 근거가 있을 때만 추진한다.
- **후보 모델:** 짧은 패킷/Flow 스냅샷 **시퀀스**를 입력으로 하는 1D-CNN 또는 GRU. 어느 쪽도 성능 우위를 미리 가정하지 않는다.
- **추가 요구:** 시퀀스 길이·마스킹·패딩·샘플링, 시간/방향 정보, 패킷 순서 보존, 학습/추론 스키마 버전 추가, C++ 수집 측 구현과 Python 학습 측 **동일성 테스트**.
- **주의:** 기존 16개 통계 특징을 단순히 모양만 바꿔 시퀀스 모델에 넣어도 사라진 시간 정보가 복원되지 않는다. TCP 페이로드 복호화 또는 C2·SQL Injection 탐지를 자동으로 보장하지 않는다.
- **개발 위치:** A/B/C 필수 일정에는 넣지 않는다. 필요 시 **MVP 통합 평가 완료 이후** 별도 요구사항 승인으로 진행한다.

---

## 8. Flow 특징 스키마와 데이터셋 전략

### 8.1 특징은 **C++에서 실제 추출 가능한 것만** 사용

**아래 16개를 MVP 후보 특징으로 고정**한다. 최종 확정 전에 데이터셋의 원본 PCAP 및 라벨과 대조해 실현 가능성을 확인한다.

| 순서 | 특징 이름 | 의미 / 단위 | 추출 시점 |
|---:|---|---|---|
| 1 | `duration_ms` | Flow 첫 관측~현재 스냅샷 / ms | 진행 중 |
| 2 | `fwd_packets` | 최초 방향 패킷 수 | 진행 중 |
| 3 | `bwd_packets` | 반대 방향 패킷 수 | 진행 중 |
| 4 | `fwd_bytes` | 최초 방향 IP 계층 기준 패킷 바이트 합계 | 진행 중 |
| 5 | `bwd_bytes` | 반대 방향 IP 계층 기준 패킷 바이트 합계 | 진행 중 |
| 6 | `fwd_pkt_len_mean` | 최초 방향 IP 계층 패킷 길이 평균 / bytes | 진행 중 |
| 7 | `bwd_pkt_len_mean` | 반대 방향 IP 계층 패킷 길이 평균 / bytes | 진행 중 |
| 8 | `fwd_iat_mean_ms` | 최초 방향 패킷 간 평균 관측 시간 차 / ms | 진행 중 |
| 9 | `bwd_iat_mean_ms` | 반대 방향 패킷 간 평균 관측 시간 차 / ms | 진행 중 |
| 10 | `syn_count` | Flow 전체 TCP SYN 비트가 있는 패킷 수 | 진행 중 |
| 11 | `ack_count` | Flow 전체 TCP ACK 비트가 있는 패킷 수 | 진행 중 |
| 12 | `fin_count` | Flow 전체 TCP FIN 비트가 있는 패킷 수 | 진행 중 |
| 13 | `rst_count` | Flow 전체 TCP RST 비트가 있는 패킷 수 | 진행 중 |
| 14 | `psh_count` | Flow 전체 TCP PSH 비트가 있는 패킷 수 | 진행 중 |
| 15 | `packets_per_second` | `(fwd_packets+bwd_packets)/max(duration_s, epsilon)` | 진행 중 |
| 16 | `bytes_per_second` | `(fwd_bytes+bwd_bytes)/max(duration_s, epsilon)` | 진행 중 |

**특징 계약 주의사항**

1. `fwd`는 실제 클라이언트라는 뜻이 아니라 **처음 관측한 패킷 방향**이다. 처음 관측이 서버 응답이었다면 그 방향을 `fwd`로 삼는다. 역방향 패킷은 `bwd`다.
2. `duration_ms`와 IAT는 PCAP **캡처 타임스탬프**(오프라인) 또는 라이브 캡처 타임스탬프를 기준으로 계산하고 음수/역순 타임스탬프 처리 정책을 테스트한다.
3. `*_bytes`는 **IP 전체 길이** 기준이며 Ethernet 길이와 TCP payload 길이와 혼동하지 않는다. 학습 데이터셋 CSV의 비슷한 이름이 같은 정의임을 의미하지 않는다.
4. UDP의 TCP flag 특징은 0으로 채운다. 결측이라는 의미와 0이라는 의미를 혼동하지 않도록 `protocol`별 성능을 따로 보고한다.
5. 패킷 1개뿐인 방향의 IAT 평균은 `0`으로 정의하고 `zero-duration` rate는 `epsilon`을 적용한다. 선택한 `epsilon` 값은 스키마 버전에 고정한다.
6. 순서, 단위, dtype, float 허용 범위, 결측 정책은 `protocol/flow_features.schema.json` 및 Python 테스트에 **동일하게** 정의한다.
7. **훈련에만 존재하는 값**(예: 공격 정답 라벨, 종단에서만 알 수 있는 최종 길이·완료 여부, 임의 패킷 페이로드, 현재 룰 결과)을 신경망 입력에 넣지 않는다.
8. 특징의 **스냅샷 시점**을 포함해 버전화한다. 같은 이름의 'Flow Duration'이라도 전체 Flow 종료 수치와 도중 수치는 다른 분포다.
9. 향후 TCP 재조립 이상 징후(중복·gap 등)는 **별도 모델/특징 스키마 버전**에서 추가할 수 있다. 최초 16개에 조용히 끼워 넣지 않는다.

### 8.2 데이터셋 권장 기본안 (B0에서 검증)

**권장 기본안: CIC-IDS2017 원본 PCAP + Improved CIC-IDS2017 수정 라벨/검증 결과.** 데이터 확보와 Flow 매칭이 실제로 가능해야 B1로 넘어갈 수 있다. 2017년 수집 데이터는 오늘날 인터넷의 완전한 대표 표본이 아니므로 **기능 검증 및 교육·연구용 벤치마크**로 사용한다.

| 역할 | 데이터 출처 | 사용 방법 |
|---|---|---|
| 원시 패킷 | [CIC-IDS2017 (UNB)](https://www.unb.ca/cic/datasets/ids-2017.html) | **PCAP에서 직접** IPv4/TCP/UDP Flow와 중간 스냅샷을 추출 |
| 정답 라벨(우선) | [Improved CIC-IDS2017 (CNS 2022)](https://intrusion-detection.distrinet-research.be/CNS2022/index.html) | 수정 라벨과 문서화된 수정 내역을 조사하고 **확인 가능한 Flow에만** 붙임 |
| CSV 참고 | UNB 또는 개선판에서 제공하는 Flow CSV | 분포·라벨·매칭 품질 확인에만 사용. 유사 컬럼명을 임의로 실시간 특징에 치환하지 않음 |
| 후속 교차 검증(옵션) | [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | 첫 모델 안정화 이후 별도 실험. 라벨/특징·캡처 환경이 달라 **재검증 없이 합쳐 학습 금지** |
| 대규모 확장(후순위) | [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | 데이터 규모와 환경 복잡성 때문에 첫 버전에서는 제외 |

**데이터 출처 선택 근거:** UNB 원본은 PCAP과 라벨 Flow CSV를 모두 제공한다. 하지만 기존 CICIDS2017/2018에는 라벨링·특징 추출·시나리오 관련 알려진 문제가 있어, 2022년 연구에서 공개한 개선 자료를 우선 참고한다. 이 개선 자료가 **우리의 C++ Flow 기준과 자동으로 1:1로 호환된다는 뜻은 아니다.** PCAP/수정 라벨 결합이 재현 가능하지 않으면 품질 기준을 낮추지 말고 매칭 실패 현황을 보고한다.

**특별 주의 — `Attempted` 라벨:** 개선 데이터에는 공격을 시도했더라도 실제 악성 행위가 관측되지 않은 Flow를 가리키는 `Attempted` 라벨이 존재할 수 있다. 최초 **이진 분류의 주 평가셋에서는 `Attempted`를 제외하고 건수를 기록**한다. 이후 민감도 분석에서는 원 저자 문서의 권고를 참고해 `Benign`으로 다시 매핑한 결과도 별도로 기록할 수 있다. `Attempted`를 별도 정답 클래스나 확정적인 공격(1)로 취급하지 않는다.

**샘플 개발 순서(권장):**

1. 정상 PCAP 일부와 공격 PCAP 일부를 **소규모로 확보**한다. 예시로 DoS 계열 1종 + 정상 Flow부터 검증하되, 평가용 분할 기준을 확정하기 전에 공격 유형을 폭넓게 조사한다.
2. Flow 방향, timeout, TCP 재전송/재조립, IP 패킷 길이의 **특징 계산 정의**가 실제 PCAP에 일관되게 적용되는지 점검한다.
3. Flow 식별자 + PCAP 파일 + 시작/종료 시간 구간으로 **수정 라벨과 매칭**한다. 충돌·불일치·불명 라벨은 제외량을 기록한다.
4. 데이터 카드에 출처/버전/라이선스/인용/파일 해시/캡처 구간/클래스 수/매칭률/제외량을 기록한다.
5. **같은 Flow나 동일한 공격 실행 세션**이 훈련·검증·테스트에 혼입되지 않도록 그룹 기반 분할한다. 원본 특정 날짜에만 특정 공격이 존재하므로 무분별한 시간·날짜 홀드아웃도 분포 불일치를 일으킬 수 있다. 분할별 클래스 및 시나리오 분포를 검증한다.

**성공 기준:** 우선 선정한 소규모 PCAP 구간에서 라벨 결합 규칙이 재현되고, 불명확한 행을 자동으로 정상으로 넣지 않으며, 독립 테스트셋을 보존한다. **다운로드/라이선스/매칭이 실패하면 차단 없이 보고하고 B0 미완료로 남긴다.**

### 8.3 CSV만 보고 학습하는 방식의 함정

> **중요:** CIC-IDS2017/2018 등에서 이미 계산된 Flow CSV를 모델에 그대로 학습시키면서 C++이 만든 16개 특징으로 실시간 추론하면, **계산법이 다르거나 완료 시점이 달라 결과가 성립하지 않을 수 있다.**

**따라서 다음 두 가지 중 하나를 반드시 만족**해야 한다.

- **권장 경로 (실시간 목표):** 라벨이 신뢰 가능한 **PCAP에서 C++과 동일한 정의로 중간 Flow 스냅샷 특징을 추출**, 검증 가능한 방법으로 원래 공격 라벨을 연결한 뒤 모델을 학습한다. 실시간에서 동일 스냅샷 주기로 C++이 제공한다.
- **한시적 베이스라인 (사후 탐지 목표):** 공개 CSV의 종료된 Flow 특징으로 모델을 먼저 학습할 수 있으나 이는 **별도의 오프라인 실험**이며, 실시간 Inline AI 탐지 성과로 보고하지 않는다. 실제 C++ 실시간 특징과 동등함을 증명하기 전 서비스 모델로 사용하지 않는다.

**라벨 결합 원칙:** 단순히 같은 행번호로 CSV·PCAP을 묶지 않는다. Flow 5-tuple+시간범위+방향 정의+캡처 파일 등으로 대조하고, 매칭률 및 불명확한 라벨의 제외량을 보고한다. PCAP과 라벨의 신뢰성 있는 매칭이 어려우면 임의로 정상/악성 라벨을 붙이지 않고, **직접 제어하는 격리 실험 PCAP 및 정답 로그**로 통합 검증한다.

### 8.4 훈련/검증/테스트 분할 및 누수 방지

- **패킷이나 중간 스냅샷을 무작위로 행 단위 분할하지 않는다.** 같은 `flow_id`·같은 실험 시나리오가 train/test에 양쪽 나타나면 과대평가된다.
- 최소 **Flow 그룹 단위**로 격리하고, 가능하면 날짜·수집 세션·실험 시나리오 등 더 강한 그룹 분할도 평가한다.
- StandardScaler 같은 변환은 **train에서만 fit** 후 validation/test/serving에서 재사용한다.
- 전체 데이터의 `ip`, 시간, 레코드 순서, 공격 시나리오별 특수 식별자 때문에 라벨이 누출되지 않도록 의심 특징은 제외한다.
- **Threshold는 validation으로 결정**, test는 최종 1회 평가에 사용한다.
- 정상/악성 건수와 공격 유형별 건수를 파악하고, 과소 대표 유형을 분리 평가한다.
- `NaN`, `Inf`, 0분모, 음수 시간, 중복 레코드, 충돌 라벨은 무조건 가시적인 품질 리포트로 남긴다.
- **데이터셋의 공격 종류가 곧 실환경 탐지 가능 공격 목록이라고 단정하지 않는다.**

### 8.5 중간 스냅샷 정책 — 검증할 기본안

- 기본 후보: Flow마다 **2초 간격 또는 20개 신규 패킷 누적 중 먼저 충족하는 시점**에 특징 스냅샷 발생(실험 설정으로 변경 가능).
- 시간 기준 발행은 Flow 활동/타이머 정책에 따라 수행하며, 종료 시 최종 스냅샷을 남긴다.
- 공격 탐지 지연과 연산량의 절충을 따지기 전에는 **임계값과 간격을 확정하지 않는다**.
- 모델은 실제로 발행되는 스냅샷 분포에서 학습/평가해야 하며, 종료된 Flow만 학습한 모델을 중간 스냅샷에 쓰지 않는다.
- Flow당 스냅샷을 너무 많이 보내서 다량의 트래픽이 AI 서버를 마비시키지 않도록 최소 간격, 큐 한도, 우선순위 정책을 둔다.

### 8.6 공격 유형별 Flow 정보의 한계

**첫 16개 특징은 단일 Flow의 통계값만 포함**한다. 따라서 높은 전송량·빈번한 패킷 등으로 드러나는 일부 공격은 비교적 잘 표현될 수 있지만, **여러 연결을 조합해서야 드러나는 Port Scan·Brute Force**는 단일 Flow 특징으로 판별하기 어려울 수 있다.

- **MVP에서는 16개 특징을 그대로 유지**해 모델과 엔진의 일치부터 증명한다.
- 공격 유형별 성능이 낮으면 모델만 키우지 말고 **관측 정보 부족**을 먼저 분석한다.
- 필요 시 후속 `flow-v2`에 별도 연결 집계 특징(예: 최근 N초 동안 동일 송신원의 신규 연결 수, 서로 다른 목적 포트 수, SYN 대비 연결 성립 비율)을 추가한다. **이는 C++ FlowTable에서 연산 가능해야 하며, AI 학습 데이터에도 같은 조건으로 반영**해야 한다.
- `flow-v1` 모델에서 확실하게 탐지했다고 입증하지 않은 공격 유형을 기능 설명서에 탐지 가능하다고 적지 않는다.


---

## 9. C++ 엔진–Python AI 연동 계약

### 9.1 연결 방식

**초안 기본 기술:** 로컬 **Unix Domain Socket(UDS)**을 사용하는 별도 Python 추론 프로세스.

- **C++20 프로세스:** PCAP/Live/NFQUEUE 수집, 파싱, Flow 상태, 룰 판단, AI용 특징 생성, 최종 패킷 verdict 소유.
- **Python/PyTorch 프로세스:** 학습한 모델/스케일러 로드, 특징 검증, 추론, 점수와 이상 판단 반환. **직접 NFQUEUE 패킷을 차단할 권한은 없다.**
- **이유:** C++ 엔진에 Python 런타임과 모델 메모리를 직접 임베딩하지 않아 고장 격리·개발·테스트가 쉬움.
- **비교 대안:** gRPC, C API 임베딩/pybind11, TorchScript/LibTorch, ONNX Runtime은 향후 성능 측정이 필요할 때 검토. 최초 단계에서는 복잡한 다중 프레임워크를 섞지 않는다.
- **접근 제어:** UDS는 `0600` 또는 별도 서비스 그룹 권한, 허용된 로컬 경로만 사용. 외부 TCP 포트로 API를 노출하지 않는다.
- **입력 상한:** 메시지 최대 16 KiB(초안), 큐에 대기 가능한 요청 개수 제한, 최대 특징 개수·범위·JSON 깊이 검증.
- **IPC 연결 실패:** 엔진은 AI 비가용성 로그/카운터를 남기고 **룰 기반 탐지/차단을 계속**한다.

### 9.2 요청·응답 프로토콜(예시)

**요청 — 하나의 JSON 객체 + 개행(LF), UTF-8:**

```json
{
  "schema_version": "1.0",
  "request_id": "req-000123",
  "flow_id": "flow-42",
  "snapshot_id": 3,
  "captured_at_ms": 1793000000123,
  "protocol": "tcp",
  "feature_schema": "flow-v1",
  "features": {
    "duration_ms": 2100.0,
    "fwd_packets": 10,
    "bwd_packets": 6,
    "fwd_bytes": 5420,
    "bwd_bytes": 3100,
    "fwd_pkt_len_mean": 542.0,
    "bwd_pkt_len_mean": 516.6667,
    "fwd_iat_mean_ms": 210.0,
    "bwd_iat_mean_ms": 350.0,
    "syn_count": 1,
    "ack_count": 12,
    "fin_count": 0,
    "rst_count": 0,
    "psh_count": 5,
    "packets_per_second": 7.619,
    "bytes_per_second": 4057.143
  }
}
```

**응답:**

```json
{
  "schema_version": "1.0",
  "request_id": "req-000123",
  "flow_id": "flow-42",
  "snapshot_id": 3,
  "model_version": "mlp-flow-v1",
  "feature_schema": "flow-v1",
  "score": 0.973,
  "threshold": 0.95,
  "suspicious": true,
  "status": "ok"
}
```

- `score`와 `threshold`는 [0,1] 범위의 유한한 숫자만 허용한다. `suspicious`는 `score >= threshold`로 계산하고 수신 측에서도 모순을 검증한다.
- 응답은 요청의 `request_id`, `flow_id`, `snapshot_id`, `schema_version`, `feature_schema`와 정확히 일치해야 한다. 늦게 온 다른 Flow 응답은 버린다.
- `model_version` 변경 시 기존 임계값·전처리 버전 호환성을 확인하고 경고 없이 교체하지 않는다.
- JSONL은 **연결이 유지되는 스트림**에서 개행으로 프레이밍하며, 수신 버퍼가 여러 메시지/부분 메시지를 처리하도록 구현한다.
- 비정상 입력에 `status:error` 또는 연결 차단, 자세한 내부 오류는 서버 로그에 남기고 패킷 흐름은 유지한다.
- **전체 네트워크 페이로드, 비밀번호, 인증 토큰, 개인 식별 정보**를 AI 메시지에 넣지 않는다.

### 9.3 모델 호출 시점·백프레셔

- **패킷마다 Python을 동기 호출하지 않는다.** FlowFeatureExtractor가 확정된 중간 스냅샷 단위로 유한 큐에 제출한다.
- C++ 패킷 처리 경로에서는 대기 중인 소켓 응답으로 인해 무제한 블로킹되지 않도록 한다. 네트워크 verdict를 발행하는 스레드는 **AI 응답을 기다리지 않는다**(shadow 및 초기 alert 동작).
- 초안 한도: 대기 큐 1,024건, 같은 Flow 최대 1개 미완료 요청(추가 스냅샷은 최신 값으로 교체 가능), 응답 타임아웃 100ms(테스트에서 조정).
- 큐가 가득 차면 `ai_backpressure`/`ai_skipped`를 기록하고 **룰 탐지를 계속**한다. 새로운 Flow를 무한하게 메모리에 쌓지 않는다.
- 느린 응답, 소켓 접속 끊김, AI 프로세스 종료, 스키마 오류, out-of-order 응답을 반복 검증한다.
- 추론 지연이 100ms를 넘는 것만으로 네트워크가 DROP 되지 않는다. AI 정책이 `shadow`라면 메인 데이터 경로에 영향을 주지 않는다.

### 9.3.1 AI 후보 Flow 선별 정책과 성능 비교

**초기 정책(필수):** `ai_candidate_policy=all_eligible`. 지원 프로토콜·유효 스키마·발행 간격 조건을 만족한 스냅샷은 **룰 탐지 여부와 관계없이** AI에 전달한다(9.3의 큐 상한 적용). 이는 AI의 추가 탐지 기여를 **공정하게 평가하기 위한 shadow 데이터 수집 경로**다. `drop` verdict는 AI 결과를 기다리지 않고 즉시 내려지므로 AI에 제출하려면 별도로 보존된 비동기 스냅샷을 사용해야 한다.

**확장 정책(비필수):** `undetected_only` 또는 `risk_priority` 같은 후보 게이트는 **C4의 full-coverage 비교 결과가 확보된 뒤** 선택적으로 시험한다. 룰 판정은 스냅샷별 일시 상태일 수 있으므로, "아직 룰 미탐"과 "Flow 전체 룰 미탐"을 구분한다. 또한 룰 `pass` 예외의 보안 정책을 우회하지 않는다.

후보 게이트 비교 시 **후보 선정률(전체 지원 스냅샷 중 제출 비율), AI 처리 완료율, 놓친 추가 TP, 추가 FP, 추론 자원/지연, 룰 verdict 유지**를 함께 기록한다. 게이트가 빠뜨린 Flow를 AI가 정상이라 판단한 것으로 간주하지 않는다. 미제출·큐 포화·응답 누락은 `not_evaluated`로 별도 관리한다.

### 9.4 결정 규칙 — 기본 정책 표

| 룰 판단 | AI 판단 | 기본 Inline 결과 | 이벤트 |
|---|---|---|---|
| `drop` | 관계없음 | **즉시 DROP** | rule verdict/alert, AI 가능 시 평가 통계 별도 |
| `pass` | 관계없음 | **ACCEPT** | rule pass 기록; **명시적 예외 룰은 AI 자동 차단보다 우선** |
| `alert`만 일치 | `suspicious=true` | **ACCEPT (shadow)** | rule alert + ai_alert |
| 룰 미탐 | `suspicious=true` | **ACCEPT (shadow)** | **AI 추가 탐지** (`detected_by=ai_only`) |
| 룰 미탐 | `suspicious=false` | ACCEPT | 표준 Flow 통계(옵션) |
| 룰 미탐 | AI 시간 초과/오류 | ACCEPT | ai_error, ai_unavailable (룰 엔진 유지) |

**중요한 의미 구분:** 위 표의 AI 결과는 **스냅샷에 대한 비동기 결과**로서, 해당 스냅샷을 만든 패킷의 verdict를 소급 변경할 수 없다. 현재 패킷의 기본 verdict는 룰 엔진이 결정한다. C단계 기본 모드에서는 AI가 패킷을 자동 차단하지 않는다.

**장래 실험용 `enforce` 동작(기본 비활성):** 격리 테스트에서만 AI가 수상하다고 판단한 `flow_id`를 **TTL 있는 차단 목록**에 등록하고, *그 이후 도착하는* 해당 Flow 패킷에 `NF_DROP`을 적용한다. 별도 `--enable-ai-enforce` 확인 옵션을 요구한다. AI 점수가 높아도 현재 이미 전달된 패킷은 차단한 것이 아니다. 평가 데이터·운영 임계값·오탐 허용 수준을 사용자가 명시적으로 승인하기 전에는 구현/활성화하지 않는다. 기존 룰의 `pass` 예외가 AI 차단보다 우선하며, 예외 충돌 테스트가 필수다.

### 9.5 CLI·설정 예시

**C단계에만 다음 옵션을 추가:**

```bash
# 터미널 A: 모델 추론 서비스(비특권 사용자)
python -m miniips_ai.server \
  --model-dir ai/artifacts/mlp-flow-v1 \
  --socket /run/user/$(id -u)/miniips-ai.sock

# 터미널 B: 기존 C++ 엔진 + AI 경고 분석 (실제 AI 차단은 하지 않음)
./miniips --mode pcap \
  --input tests/fixtures/demo.pcap \
  --rules rules/example.json \
  --log events.jsonl \
  --ai-mode shadow \
  --ai-socket /run/user/$(id -u)/miniips-ai.sock
```

- 기본값은 `--ai-mode off`이다. `shadow`는 점수만 로그에 기록한다.
- `alert` 모드는 AI 탐지 경고를 별도 출력하되 실제 차단은 하지 않는다.
- `enforce`는 검증/사용자 승인 이후 별도 구현하는 격리 실험 기능이다.
- PCAP 재생 실행이 종료되기 전에 미완료 AI 응답을 합리적 상한 내에서 정리/집계하고, 처리되지 못한 건수를 보고해야 한다. 결과를 무작정 기다리며 멈추지 않는다.

### 9.6 로그 이벤트 예시

```json
{
  "timestamp": "2026-10-26T11:00:01Z",
  "event_type": "ai_alert",
  "mode": "pcap",
  "enforced": false,
  "detected_by": "ai_only",
  "flow_id": "flow-42",
  "snapshot_id": 3,
  "model_version": "mlp-flow-v1",
  "feature_schema": "flow-v1",
  "ai_score": 0.973,
  "ai_threshold": 0.95,
  "rule_detections_for_flow": 0,
  "message": "AI flagged a flow not flagged by enabled detection rules"
}
```

- `ai_only`는 **로그 시점까지 활성화된 룰이 해당 Flow에서 경고/차단하지 않았음**을 뜻한다. 후속 패킷에서 룰이 탐지할 수 있으므로 **최종 룰 미탐 여부는 Flow/평가 구간 종료 후 재확인**한다. Ground truth 정답을 뜻하지 않는다.
- 테스트 보고서에서만 `ai_only`와 악성 **정답 라벨**을 교차 확인하여 *추가로 맞힌 공격*을 계산한다.
- 평상시 모든 정상 Flow의 특징 벡터를 저장하지 않는다. 로그에는 필요 최소한의 숫자/이벤트만 기록한다.

---

## 10. 성능·안전·운영 요구사항

### 10.1 실제 통합 상태에서 측정할 지표

| 분야 | 지표 | 비교 방식 |
|---|---|---|
| 탐지 품질 | Recall / Precision / FPR / PR-AUC | 룰만 vs AI만 vs 결합 |
| **AI 고유 기여** | 룰 미탐 공격에 대한 추가 TP / 정상 트래픽에 대한 추가 FP | 반드시 정답 라벨과 교차 |
| CPU | C++ CPU 사용량 / Python CPU 사용량 | 동일 PCAP·속도·부하 |
| 메모리 | C++ RSS / Python RSS / Flow 버퍼 상한 | idle/고부하/오류 상황 |
| 처리 성능 | 처리 packets/s, flow snapshots/s, 인입/버린 요청 수 | AI off vs shadow vs alert |
| 추론 지연 | p50/p95/p99 AI 추론·IPC 왕복시간 | warm-up 후 측정 |
| 탐지 지연 | 첫 악성 관측 시각 → 최초 AI 이벤트 시각 | Flow 단위/공격 유형별 |
| 안정성 | AI 사망/복구/큐 포화 시 규칙 verdict 지속 여부 | 격리 재현 실험 |
| AI 후보 선별 | 대상 스냅샷 수, 제출/미제출/스킵 수, 추론 완료율 | 기본 `all_eligible` 및 선택적 게이트 비교 |
| 게이트 영향 | 게이트 도입 전후 추가 TP/FP, 처리량, 미평가 Flow 비율 | 동일 데이터셋·동일 모델·동일 threshold |

수치 목표는 사용자의 **개발 머신 스펙 및 평가 우선순위**에 맞춰 합의한다. CPU 사용률, p95 지연, 오탐률 목표를 임의의 확정 요구사항으로 단정하지 않는다.

### 10.2 실패 모드

1. **Python 서버가 죽음:** `ai_unavailable`, 재연결 정책 및 제한된 재시도. 룰 기반 엔진은 계속 작동.
2. **모델 파일 손상 / 잘못된 스키마:** AI 기동 실패 + 명시적 오류. 모델이 없는 상태로 `suspicious=false`를 정상 판정처럼 위장하지 않음.
3. **비정상 특징 벡터:** 탐지 결과 미생성, 검사 실패 이벤트, 상한 유지. NaN/Inf 값 직접 모델 입력 금지.
4. **AI 응답 지연/순서 뒤바뀜:** 요청 ID와 스냅샷 ID 검증, 구형 답변의 최신 Flow 정책 덮어쓰기 방지.
5. **Flow 만료 후 응답 도착:** 해당 상태가 없으면 폐기 + 별도 카운터. 다른 Flow에 차단 결정 적용 금지.
6. **과부하:** bounded queue, backpressure/skip 측정, AI 관련 메모리 상한.
7. **대량 정상 오탐:** 기본 shadow에서 서비스 장애 없음. 실험적 enforce는 수동 종료 스위치 및 격리 네트워크 정책.
8. **NFQUEUE 자체 장애:** 기존 A단계의 nftables `bypass`/Fail-open/Fail-closed 설정 및 위험을 별도로 문서화. **AI 오류 처리와 NFQUEUE 오류 처리는 다른 문제**다.

### 10.3 안전·재현성 원칙

- 허가받은 **본인 소유/격리 네트워크**에서만 차단 테스트를 한다.
- 원본 PCAP·데이터셋에 포함된 개인/비밀 정보를 로그·깃 저장소에 넣지 않는다.
- 모델 다운로드·패키지 의존성은 출처를 명시하고, **신뢰할 수 없는 pickle 체크포인트를 무조건 로드하지 않는다**. 가능한 한 안전한 가중치 포맷과 신뢰한 구성만 사용한다.
- 외부 데이터셋 원본을 임의로 수정·재배포하지 않고 데이터셋 라이선스/인용 조건을 확인한다.
- 평가 보고서에는 최소한 OS·CPU·RAM·Python/PyTorch 버전·C++ compiler·모델·threshold·데이터셋 구간과 분할·룰 파일 해시를 기록한다.

---

## 11. 확정사항과 미확정 파라미터

### 11.1 사용자 확정사항과 명세서 작성자의 데이터셋 권고안

| 결정 | 확정 내용 | 개발에 미치는 영향 |
|---|---|---|
| **Q1. AI 목표** | **A: 기존 룰이 놓친 공격 추가 탐지** | 지도학습 이진 분류 PyTorch MLP 우선; 미지 공격 탐지 성능 주장 금지 |
| **Q2. 학습 데이터** | **추천 기본안: 원본 CIC-IDS2017 PCAP + 2022 개선 라벨 우선 검증** | 수정 라벨 매칭 실측 필수; `Attempted`는 주요 평가에서 제외; UNSW-NB15은 후속 외부 검증 후보 |
| **Q3. AI 행동** | **C: 경고(shadow) 먼저, 충분한 성능 검증 뒤 자동 차단 선택** | C단계 MVP에서 AI는 verdict를 바꾸지 않음; AI 차단은 격리 테스트/명시적 활성화가 필요한 C5 옵션 |
| 구현 순서 | **A(C++ IDS/IPS) → B(Python+PyTorch) → C(연동)** | 선행 단계 통과 전 후속 구현 금지 |
| 설계 참고 | **Precision AI의 시그니처+딥러닝 결합 원칙을 참고** | 비공개 모델 모방/동일 성능 주장 금지; 필수 구현 범위 증가 없음 |

### 11.2 구현 중 측정하여 정할 파라미터 — 질문 없이 기본안으로 시작

| 항목 | 첫 구현 기본안 | 확정 시점 |
|---|---|---|
| 모델 | 16개 Flow 특징을 쓰는 작은 MLP, 이진 분류 | B1/B3 검증 뒤 변경 가능 |
| 추론 | CPU, 단일 요청/제한된 큐 우선 | C1/C2 실측에 맞춤 |
| 스냅샷 발행 | 2초 또는 신규 패킷 20개 누적 시 + 종료 시 | B1 분포 검증 후 조정 |
| 모델 임계값 | **0.5/0.95 등 임의 상수로 확정하지 않음** | Validation에서 오탐 예산과 함께 선택 |
| 자동 차단 | **기본 비활성화** | C4 평가 후 별도 활성화가 필요할 경우만 C5 |
| 하드웨어/데이터 규모 | 소량 PCAP 및 작은 모델부터 시작 | B0에서 실제 이용 가능한 리소스 확인 |
| AI 후보 선별 | `all_eligible` (shadow에서 공정한 기준 실험) | C4 비교 평가 후 선택적 최적화 |
| 순차 모델 | 비필수·도입하지 않음 | MVP 완료 뒤 근거가 있을 경우 별도 승인 |

**핵심 결과 판정:** 목표는 모델 Accuracy가 아니다. **동일 테스트셋에서 `룰-only FN` 가운데 AI가 추가로 잡은 `TP`가 있고, 늘어난 정상 Flow의 오탐 비용이 수용 가능한지**가 성패 기준이다. 지금 정한 데이터셋이 실서비스의 실제 네트워크 공격 전체를 대표한다고 주장하지 않는다.

---

## 12. C++ 엔진 공식 참고 자료

- Suricata 8 사용자 문서: https://docs.suricata.io/en/suricata-8.0.0/
- Suricata IPS 동작 개념: https://docs.suricata.io/en/suricata-8.0.3/ips/ips-concept.html
- Suricata TCP Stream Engine: https://docs.suricata.io/en/suricata-8.0.2/devguide/internals/engines/stream/inspection_raw_data.html
- Netfilter `libnetfilter_queue`: https://www.netfilter.org/projects/libnetfilter_queue/index.html
- nftables `queue`/`bypass`: https://www.netfilter.org/projects/nftables/manpage.html
- libpcap: https://www.tcpdump.org/

> **주의:** Suricata 공식 설계서의 번역이나 코드 복제본이 아닌 별도의 경량 프로젝트 명세다. 세 단계의 실행 순서는 [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)를 따른다.


---

## 13. AI·데이터 참고 자료

- Palo Alto Networks Advanced Threat Prevention 공식 설명 (참고 아키텍처): https://docs.paloaltonetworks.com/advanced-threat-prevention/getting-started/about-advanced-threat-prevention
- Palo Alto Networks 2026년 시퀀스 기반 탐지 사례 (참고 연구): https://docs.paloaltonetworks.com/advanced-threat-prevention
- PyTorch inference mode: https://docs.pytorch.org/docs/stable/generated/torch.autograd.grad_mode.inference_mode.html
- PyTorch 튜토리얼: https://docs.pytorch.org/tutorials/
- CIC-IDS2017 공식 페이지 (원본 PCAP·라벨 CSV): https://www.unb.ca/cic/datasets/ids-2017.html
- Improved CIC-IDS2017 / CNS 2022 (개선판 개요와 문서): https://intrusion-detection.distrinet-research.be/CNS2022/index.html
- Improved CIC-IDS2017 상세 라벨링 수정 사항: https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html
- Improved CIC-IDS2017 다운로드 및 `Attempted` 라벨 설명: https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html
- 데이터셋 오류 분석 연구 (2022 IEEE CNS): https://doi.org/10.1109/CNS56114.2022.9947235
- UNSW-NB15 공식 프로젝트: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CSE-CIC-IDS2018 원본 등록: https://registry.opendata.aws/cse-cic-ids2018/
- CSE-CIC-IDS2018 분석 및 라벨/추출 문제 참고: https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018/

> **범위 고지:** 이 문서는 C++20의 전체 Suricata 재구현 명세가 아닌 **6기능 경량 엔진 + Flow 기반 PyTorch 보조 탐지 + 프로세스 연동**의 개발 실행 명세다. AI 탐지 목표와 초기 경고 정책은 확정됐으며, **CIC-IDS2017의 개선 라벨 우선**은 검증 전 기본 추천안이다. 사용자가 2번 데이터셋을 승인한 것으로 간주하지 않는다. 실제 사용할 수정 데이터셋/PCAP 매칭 가능성, 학습 임계값, AI 자동 차단 허용 여부는 **실측 검증 전까지 결정된 것으로 간주하지 않는다.**
