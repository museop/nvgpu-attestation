# NVGPU quote verifier (Go)

이 저장소는 **NVIDIA GPU attestation quote(NVGPU quote)** 를 로컬에서 검증하는 작은 Go 예제입니다.

현재 구현은 두 단계로 나뉩니다.

1. **오프라인 quote 검증**
   - quote request nonce 일치
   - quote 서명(ECDSA P-384, raw `r || s`) 검증
   - device certificate chain 검증
   - quote FWID ↔ leaf certificate FWID 일치 검증
2. **네트워크/레퍼런스 검증 (옵션)**
   - NVIDIA **OCSP** endpoint 질의
   - NVIDIA **RIM(Reference Integrity Manifest)** fetch 또는 로컬 RIM 파일 검증
   - RIM schema / cert chain / signature 검증
   - quote runtime measurements ↔ golden measurements 비교

---

## 추가 문서

- [NVGPU verification 개념 정리](docs/nvgpu-verification.md)
- [NVGPU verifier 코드 구조와 검증 동작](docs/nvgpu-code-structure.md)
- [Sample data와 mock data 사용 가이드](docs/sample-and-mock-data.md)

## NVGPU quote 전체 검증 과정

이 예제가 따르는 전체 흐름은 아래와 같습니다.

### 1. Evidence 입력
입력은 두 가지 형식을 지원합니다.

- **split files**
  - `hopperAttestationReport.txt` : quote 본문 (hex text)
  - `hopperCertChain.txt` : quote와 함께 제공된 device certificate chain (PEM)
- **serialized JSON evidence**
  - `attestation-sdk/common-test-data/serialized_test_evidence/*.json`
  - 각 엔트리에 `arch`, `certificate`, `evidence`, `nonce` 포함

### 2. Quote 기본 검증
- quote request nonce가 기대값과 같은지 확인
- quote의 leaf certificate public key로 quote 서명 검증
- NVIDIA device root bundle을 trust anchor로 certificate chain 검증
- quote opaque field의 FWID와 leaf certificate FWID 비교

### 3. Device certificate OCSP 검증 (`--verify-ocsp`)
- NVIDIA 공개 OCSP endpoint `https://ocsp.ndis.nvidia.com` 질의
- 샘플 chain 기준으로 GPU attestation chain의 **intermediate 구간들**을 조회
- 현재 구현은 `openssl ocsp`를 사용해 상태(`good`, `revoked`, `unknown`)를 확인

### 4. Driver/VBIOS RIM 검증 (`--verify-rim`)
- quote에서 아래 값을 읽어 RIM ID를 계산
  - driver version
  - project
  - project SKU
  - chip SKU
  - VBIOS version
- Driver RIM ID 예:
  - `NV_GPU_DRIVER_GH100_550.90.07`
- VBIOS RIM ID 예:
  - `NV_GPU_VBIOS_1010_0200_882_96009F0001`
- RIM은 두 방법 중 하나로 가져옵니다.
  - 로컬 `.swidtag` 파일 (`--driver-rim`, `--vbios-rim`)
  - NVIDIA 공개 RIM service (`https://rim.attestation.nvidia.com/v1/rim/...`)

### 5. RIM 무결성 검증
각 RIM에 대해:
- SWID XML schema validation
- RIM embedded certificate chain validation
- RIM certificate OCSP 질의
- XML Signature(ECDSA-SHA384) 검증

### 6. Measurement appraisal
- driver RIM과 VBIOS RIM의 **active measurement**를 합침
- quote의 runtime measurement block들과 index별 비교
- 불일치 index가 없으면 attestation measurement 검증 통과
- NVDEC0가 disabled인 경우 measurement 35는 skip

---

## 현재 구현 사항

### 지원 입력
- split quote/cert files
- serialized JSON evidence
- multi-GPU JSON 전체 일괄 검증 (`--all-evidence`)
- NVSwitch LS10 split report/cert files
- NVSwitch LS10 serialized JSON evidence와 multi-switch JSON 전체 일괄 검증

### 현재 지원 검증
- quote nonce 검증
- quote signature 검증
- device cert chain 검증
- device cert OCSP 질의
- driver/VBIOS RIM fetch 또는 로컬 파일 로드
- RIM schema 검증 (`xmllint --schema`)
- RIM cert chain 검증
- RIM cert OCSP 질의
- RIM XML signature 검증
- runtime measurements vs golden measurements 비교
- 선택적 policy appraisal (`--policy-driver-version`, `--policy-vbios-version`, `--policy-arch`, `--policy-require-rim`, `--policy-require-ocsp`)
- NVSwitch LS10 attestation report nonce/signature/device chain 검증
- NVSwitch BIOS RIM schema / cert chain / XML signature 검증
- NVSwitch runtime measurements vs BIOS RIM golden measurements 비교

### 현재 미구현 / 제한
- NVSwitch는 현재 LS10 sample path 중심으로 지원하며, GPU policy appraisal과 같은 정책 layer는 아직 별도 구현하지 않음
- NVIDIA attestation-sdk의 switch sample RIM은 public OCSP에서 `unknown`을 반환할 수 있어, 샘플 재현 시에는 `--skip-rim-ocsp`와 고정 `--time`을 사용함. 운영 검증에서는 RIM OCSP skip을 권장하지 않음
- batch mode에서 `serialized_test_evidence`의 Hopper multi-GPU 전체 검증은 가능하지만,
  해당 JSON 샘플의 driver version이 RIM service에 항상 존재한다고 가정하지는 않음
- OCSP는 현재 `openssl ocsp` 출력 파싱 기반
- XML canonicalization / schema validation은 현재 `xmllint`에 의존

---

## 요구 도구

현재 구현은 다음 명령이 로컬에 있어야 합니다.

- `openssl`
- `xmllint`
- `jq` (샘플 다운로드 스크립트용)

macOS에서는 기본/패키지 매니저 환경에서 흔히 사용할 수 있습니다.

---

## 샘플 데이터 받기

```bash
./scripts/fetch-samples.sh
```

받아오는 데이터:

- `hopperAttestationReport.txt`
- `hopperCertChain.txt`
- `hopper_evidence.json`
- `multi_gpu_hopper.json`
- `switchAttestationReport.txt`
- `switchCertChain.txt`
- `switch_evidence_ls10.json`
- `multi_switch_ls10.json`
- `device-root-bundle.pem`
- `verifier_RIM_root.pem`
- `swidSchema2015.xsd`
- `NV_GPU_DRIVER_GH100_550.90.07.swidtag`
- `NV_GPU_VBIOS_1010_0200_882_96009F0001.swidtag`
- `switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml`

---

## 실행 예시

CLI는 `cobra` 기반 subcommand 구조를 사용합니다. root command는 도움말만 출력하며, 검증은 `verify` subcommand로 명시적으로 실행합니다.

### 1) 기본 오프라인 quote 검증
```bash
go run ./cmd/nvgpu-attest verify
```

### 2) split sample + OCSP + RIM 전체 검증
로컬 샘플 RIM 파일 사용:

```bash
go run ./cmd/nvgpu-attest verify \
  --verify-ocsp \
  --verify-rim \
  --driver-rim ./testdata/NV_GPU_DRIVER_GH100_550.90.07.swidtag \
  --vbios-rim ./testdata/NV_GPU_VBIOS_1010_0200_882_96009F0001.swidtag \
  --time 2026-05-25T00:00:00Z
```

동일 검증을 public RIM service fetch로 수행:

```bash
go run ./cmd/nvgpu-attest verify \
  --verify-ocsp \
  --verify-rim \
  --time 2026-05-25T00:00:00Z
```

### 3) serialized JSON evidence 1개 검증
```bash
go run ./cmd/nvgpu-attest verify \
  --evidence-json ./testdata/hopper_evidence.json
```

### 4) multi-GPU JSON에서 특정 엔트리 검증
```bash
go run ./cmd/nvgpu-attest verify \
  --evidence-json ./testdata/multi_gpu_hopper.json \
  --evidence-index 2
```

### 5) multi-GPU JSON 전체 일괄 검증
```bash
go run ./cmd/nvgpu-attest verify \
  --evidence-json ./testdata/multi_gpu_hopper.json \
  --all-evidence
```

### 6) JSON 출력
```bash
go run ./cmd/nvgpu-attest verify --verify-ocsp --verify-rim --json
```

### 7) NVSwitch LS10 split sample 기본 검증
```bash
go run ./cmd/nvswitch-attest verify --json
```

### 8) NVSwitch LS10 serialized JSON evidence 검증
```bash
go run ./cmd/nvswitch-attest verify \
  --evidence-json ./testdata/switch_evidence_ls10.json \
  --json
```

### 9) NVSwitch LS10 BIOS RIM + measurement 검증

NVIDIA attestation-sdk unit-test용 switch RIM은 샘플 재현 목적의 staging 성격 artifact라 public OCSP가 `unknown`을 반환할 수 있습니다. 이 경우 아래처럼 RIM cert validity 시점을 고정하고 RIM OCSP만 명시적으로 skip합니다.

```bash
go run ./cmd/nvswitch-attest verify \
  --verify-rim \
  --switch-bios-rim ./testdata/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml \
  --time 2026-05-20T00:00:00Z \
  --skip-rim-ocsp \
  --json
```

운영 환경에서는 `--skip-rim-ocsp` 없이 최신/운영용 RIM과 OCSP freshness 정책을 사용해야 합니다.

### 10) 테스트 전용 root와 mock quote 생성

`root` subcommand는 실제 NVIDIA 인증 체인을 흉내 내지 않는 **테스트 전용** root key/cert를 생성합니다. `mock` subcommand는 그 root key/cert를 인자로 받아 leaf cert, quote, serialized evidence를 생성하고, 생성 직후 동일한 표준 verifier 경로로 self-check합니다.

```bash
go run ./cmd/nvgpu-attest root --out ./mock-root

go run ./cmd/nvgpu-attest mock \
  --root-key ./mock-root/root-key.pem \
  --root-cert ./mock-root/root.pem \
  --out ./mock-evidence
```

생성된 mock quote도 실제 샘플 quote와 같은 `verify` 경로로 검증합니다. 차이는 trust anchor가 NVIDIA root가 아니라 mock root라는 점뿐입니다.

```bash
go run ./cmd/nvgpu-attest verify \
  --quote ./mock-evidence/quote.hex \
  --cert-chain ./mock-evidence/cert-chain.pem \
  --roots ./mock-evidence/root.pem \
  --nonce $(cat ./mock-evidence/nonce.txt) \
  --policy-driver-version 999.0.mock \
  --policy-vbios-version 96.00.9f.00.01 \
  --json
```

serialized evidence 경로도 동일하게 사용할 수 있습니다.

```bash
go run ./cmd/nvgpu-attest verify \
  --evidence-json ./mock-evidence/evidence.json \
  --roots ./mock-evidence/root.pem \
  --policy-arch MOCK \
  --json
```

주의: `./mock-root/root-key.pem`과 `./mock-evidence/leaf-key.pem`은 로컬 테스트용 private key입니다. 운영 attestation 또는 NVIDIA 신뢰 체인으로 사용하면 안 됩니다.

### 8) Certificate validity 기준 시간 지정

기본값은 현재 시간입니다. 만료된 샘플 RIM처럼 과거 기준으로 certificate chain validity를 재현해야 하면 `--time`에 RFC3339 시간을 지정합니다.

```bash
go run ./cmd/nvgpu-attest verify \
  --verify-ocsp \
  --verify-rim \
  --driver-rim ./testdata/NV_GPU_DRIVER_GH100_550.90.07.swidtag \
  --vbios-rim ./testdata/NV_GPU_VBIOS_1010_0200_882_96009F0001.swidtag \
  --time 2026-05-25T00:00:00Z
```

`--time`은 X.509 certificate chain의 NotBefore/NotAfter 검증 기준 시간입니다. nonce, quote signature, FWID, measurement 비교는 같은 방식으로 수행됩니다.

---

## 테스트

```bash
go test ./...
go vet ./...
```

현재 테스트는 다음을 확인합니다.
- split-file quote 기본 검증
- 잘못된 nonce reject
- serialized JSON single/multi 입력 검증
- multi-GPU batch 검증
- split-file sample에 대한 OCSP + RIM + measurement 통합 검증

---

## 구현 노트

### VBIOS version 형식
quote 내부의 raw VBIOS bytes는 바로 사람이 읽는 문자열이 아니고,
NVIDIA 로컬 verifier와 같은 규칙으로 포맷팅해서 `96.00.9f.00.01` 같은 형태로 바꿉니다.

### Device OCSP 범위
GPU device chain의 경우 NVIDIA의 기존 verifier와 비슷하게 leaf FMC cert 자체가 아니라
그 위의 attestation chain 구간(BROM → Provisioner ICA → Identity CA ...)을 질의합니다.

### RIM signature 검증 방식
Go 표준 라이브러리만으로 XML DSIG canonicalization을 직접 구현하지 않고,
현재는 `xmllint --c14n11` 을 사용해 canonical form을 얻은 뒤 Go에서 ECDSA-SHA384를 검증합니다.

### Public RIM service 접근
NVIDIA 문서에는 GPU RIM fetch 예시가 `Authorization: Bearer ${NVIDIA_API_KEY}` 형태로 설명되어 있지만,
이 저장소에서 2026-05-25 기준 실제 확인한 `https://rim.attestation.nvidia.com/v1/rim/ids` 와
특정 GPU RIM fetch는 공개 접근으로 응답했습니다. 이 동작은 향후 바뀔 수 있습니다.

---

## 공식 출처

- NVIDIA nvtrust sample quote / cert chain / RIM root / schema  
  https://github.com/NVIDIA/nvtrust/tree/0c5d627313037c1e577d05a232e79394a41b2c21/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier
- NVIDIA attestation-sdk serialized evidence  
  https://github.com/NVIDIA/attestation-sdk/tree/bbef6857afccede55d44727b4ce7c0facf31d014/common-test-data/serialized_test_evidence
- NVIDIA NDIS device root certificates  
  https://docs.ndis.nvidia.com/NDIS%20Certificate%20Chains/NDIS%20Device%20Identity.html
- NVIDIA NDIS OCSP API  
  https://docs.ndis.nvidia.com/OCSP/ocsp_api_docs.html
- NVIDIA RIM guide  
  https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/rim_guide.html
- NVIDIA local verifier usage  
  https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/local-verifier/usage.html
- NVIDIA attestation architecture overview  
  https://docs.nvidia.com/attestation/quick-start-guide/latest/architecture.html
