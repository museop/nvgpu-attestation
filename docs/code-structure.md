# NVIDIA attestation verifier 코드 구조와 검증 동작

이 문서는 현재 저장소의 내부 패키지 경계를 설명합니다. 개념 중심 설명은 [`nvgpu-verification.md`](./nvgpu-verification.md), 샘플 데이터 설명은 [`sample-and-mock-data.md`](./sample-and-mock-data.md)를 참고하세요.

## 1. 패키지 구조 요약

리팩터링 후 코드는 공통 attestation service/primitive와 device-specific verifier를 분리합니다. `internal/attest`는 단순 byte 파서만이 아니라 GPU와 NVSwitch가 공유하는 RIM/OCSP/certificate verification service도 포함합니다. 다만 RIM ID 생성, opaque field 해석, device policy는 각 device package에 둡니다.

| 패키지/파일 | 역할 | 주요 함수/타입 |
| --- | --- | --- |
| `internal/attest/quote.go` | SPDM-like request/response quote/report parser와 measurement record 추출 | `ParseQuote`, `Quote`, `Response.GetMeasurements` |
| `internal/attest/evidence.go` | NVIDIA SDK serialized JSON evidence 공통 파서 | `SerializedEvidenceEntry`, `ParseSerializedEvidenceEntries` |
| `internal/attest/cert.go` | PEM/root bundle parsing, X.509 chain 검증, raw P-384 report signature 검증, FWID extension 추출 | `ParsePEMCertificates`, `ParseRootBundle`, `VerifyCertChain`, `VerifyReportSignature`, `ExtractLeafFWID` |
| `internal/attest/ocsp.go` | NVIDIA OCSP 질의와 결과 파싱 | `CheckOCSPChain`, `QueryOCSP` |
| `internal/attest/rim.go` | RIM load/fetch, XML parsing, schema/cert/OCSP/signature 검증 | `LoadAndVerifyRIM`, `ParseRIM`, `RIMDocument` |
| `internal/attest/rim_signature.go` | RIM XML DSIG digest/signature 검증 | internal `verifyRIMSignature`, `canonicalizeXML` |
| `internal/attest/measurement.go` | generic runtime vs golden measurement 비교 | `CompareMeasurements`, `ActiveGoldenMeasurements` |
| `internal/nvgpu/api.go` | GPU verifier public API wrappers | `Verify`, `VerifyFiles`, `VerifySerializedEvidence*` |
| `internal/nvgpu/pipeline.go` | GPU 옵션 포함 검증 파이프라인 | `VerifyFilesWithOptions`, `verifyDetailed`, `verifyQuoteBinding`, `enrichResult` |
| `internal/nvgpu/rim.go` | GPU driver/VBIOS RIM ID 계산과 GPU measurement appraisal orchestration | `verifyRIMsAndMeasurements` |
| `internal/nvgpu/verify.go` | GPU result shape와 GPU opaque field decoding | `Result`, `BatchItem`, `populateOpaqueSummary` |
| `internal/nvgpu/policy.go` | GPU service policy appraisal | `AppraisePolicy`, `PolicyOptions` |
| `internal/nvgpu/mock.go` | 테스트/교육용 mock GPU root/evidence 생성 | `GenerateMockRootBundle`, `GenerateMockQuoteBundleFromRoot` |
| `internal/nvswitch/verify.go` | NVSwitch LS10 attestation report 검증과 BIOS RIM/measurement appraisal | `VerifyFilesWithOptions`, `VerifySerializedEvidenceFileWithOptions`, `VerifySerializedEvidenceAllFileWithOptions` |

큰 흐름은 다음처럼 읽으면 됩니다.

```text
input files / serialized JSON
        │
        ▼
internal/attest
  - quote/report parse
  - nonce and hex helpers
  - certificate chain verify
  - report signature verify
  - OCSP/RIM primitive verification
        │
        ├─ internal/nvgpu
        │    - GPU opaque fields
        │    - GPU FWID binding requirement
        │    - driver/VBIOS RIM ID and measurement appraisal
        │    - optional GPU policy appraisal
        │
        └─ internal/nvswitch
             - LS10 opaque fields
             - optional FWID binding when present
             - BIOS RIM ID and measurement appraisal
```

`cmd/nvgpu-attest` imports `internal/nvgpu`; `cmd/nvswitch-attest` imports `internal/nvswitch`. Both device packages depend on `internal/attest`, while `internal/attest` must not import either device package.

## 2. Public API와 입력 형식

### GPU 기본 오프라인 검증 API

| 함수 | 입력 | 수행하는 검증 |
| --- | --- | --- |
| `nvgpu.VerifyFiles(quotePath, certChainPath, rootsPath, expectedNonceHex)` | split quote/cert/root 파일 | 파일 read 후 `Verify` 호출 |
| `nvgpu.Verify(quoteInput, certChainPEM, rootsPEM, expectedNonceHex)` | quote bytes 또는 hex text, PEM chain, PEM roots | 필수 로컬 검증만 수행 |
| `nvgpu.VerifySerializedEvidenceFile(jsonPath, rootsPath, index, expectedNonceHex)` | NVIDIA SDK 계열 serialized JSON | JSON entry 선택 후 검증 |
| `nvgpu.VerifySerializedEvidence(serializedJSON, rootsPEM, index, expectedNonceHex)` | serialized JSON bytes | 단일 entry 검증 |
| `nvgpu.VerifySerializedEvidenceAll(...)` | serialized JSON array | 모든 entry를 `BatchItem` 배열로 검증 |

기본 API는 네트워크를 사용하지 않습니다. 즉 OCSP, RIM fetch, RIM measurement appraisal, policy check는 수행하지 않습니다.

### GPU 옵션 포함 검증 API

| 함수 | 추가 가능 layer |
| --- | --- |
| `nvgpu.VerifyFilesWithOptions(...)` | `VerifyOptions`에 따라 OCSP/RIM/policy 수행 |
| `nvgpu.VerifySerializedEvidenceFileWithOptions(...)` | serialized JSON 단일 entry + optional layer |
| `nvgpu.VerifySerializedEvidenceAllFileWithOptions(...)` | serialized JSON 전체 entry + optional layer |

### NVSwitch 검증 API

| 함수 | 입력 | 수행하는 검증 |
| --- | --- | --- |
| `nvswitch.VerifyFilesWithOptions(reportPath, certChainPath, rootsPath, expectedNonceHex, opts)` | split switch report/cert/root 파일 | mandatory local checks + optional OCSP/RIM |
| `nvswitch.VerifySerializedEvidenceFileWithOptions(jsonPath, rootsPath, index, expectedNonceHex, opts)` | serialized switch JSON | 단일 entry 검증 |
| `nvswitch.VerifySerializedEvidenceAllFileWithOptions(...)` | serialized switch JSON array | 전체 entry 검증 |

## 3. GPU 필수 로컬 검증 흐름

GPU 필수 검증은 `internal/nvgpu/pipeline.go`의 `verifyDetailed`가 담당합니다.

```text
verifyDetailed
  ├─ attest.DecodeHexOrRaw
  ├─ attest.ParseQuote
  ├─ attest.ParsePEMCertificates
  ├─ attest.ParseRootBundle
  ├─ attest.ParseNonce
  ├─ attest.VerifyCertChain
  ├─ newVerificationResult
  ├─ verifyNonce
  └─ verifyQuoteBinding
       ├─ attest.VerifyReportSignature
       ├─ populateOpaqueSummary
       ├─ attest.ExtractLeafFWID
       └─ report FWID ↔ leaf FWID 비교
```

GPU path에서 FWID opaque field는 필수입니다. Chain 검증과 signature 검증이 성공해도 report FWID와 leaf certificate FWID가 일치하지 않으면 실패합니다.

## 4. NVSwitch 필수 로컬 검증 흐름

NVSwitch 필수 검증은 `internal/nvswitch/verify.go`가 담당합니다.

```text
verifyDetailed
  ├─ attest.DecodeHexOrRaw
  ├─ attest.ParseQuote
  ├─ attest.ParsePEMCertificates
  ├─ attest.ParseRootBundle
  ├─ attest.ParseNonce
  ├─ attest.VerifyCertChain
  ├─ newResult
  └─ verifyReportBinding
       ├─ attest.VerifyReportSignature
       └─ if FWID field present: report FWID ↔ leaf FWID 비교
```

NVIDIA SDK 동작에 맞춰 NVSwitch FWID opaque field는 없을 수 있으며, 없으면 non-fatal로 처리합니다.

## 5. Optional enrichment 흐름

### GPU

```text
enrichResult
  ├─ if VerifyOCSP: attest.CheckOCSPChain(device chain, startIndex=1)
  ├─ if VerifyRIM:  verifyRIMsAndMeasurements
  └─ if Policy.Enabled: AppraisePolicy
```

GPU RIM appraisal은 `internal/nvgpu/rim.go`에서 driver/VBIOS RIM ID를 계산한 뒤 `attest.LoadAndVerifyRIM`과 `attest.CompareMeasurements`를 사용합니다.

### NVSwitch

```text
enrichResult
  ├─ if VerifyOCSP: attest.CheckOCSPChain(device chain, startIndex=1)
  └─ if VerifyRIM:  verifyRIMAndMeasurements
```

NVSwitch LS10 RIM appraisal은 BIOS version으로 `NV_SWITCH_BIOS_5612_0002_890_<version>` RIM ID를 만들고 BIOS RIM active measurements와 runtime measurements를 비교합니다.

## 6. 외부 도구 의존성

현재 구현은 일부 검증에 로컬 CLI를 사용합니다.

| 도구 | 사용 위치 |
| --- | --- |
| `openssl` | OCSP 질의 |
| `xmllint` | RIM schema validation, XML canonicalization |
| `jq` | 샘플 다운로드 스크립트 |

## 7. 리팩터링 경계 규칙

- `internal/attest`는 `internal/nvgpu` 또는 `internal/nvswitch`를 import하지 않습니다.
- `internal/attest`는 NVIDIA attestation에 공통인 quote/report parsing, certificate/OCSP, RIM XML 검증, measurement 비교까지만 소유합니다. Device별 RIM ID 구성이나 opaque field 의미 해석을 추가하지 않습니다.
- GPU opaque field decoding, GPU policy, mock GPU evidence 생성은 `internal/nvgpu`에 남깁니다.
- NVSwitch LS10 opaque field decoding과 BIOS RIM ID 계산은 `internal/nvswitch`에 둡니다.
- GPU와 NVSwitch의 high-level verifier skeleton은 의도적으로 일부 중복을 허용합니다. 현재 단계에서는 공통 skeleton 추출보다 device isolation과 behavior preservation을 우선합니다. 두 device path의 shared primitive 변경은 `internal/attest` 단위 테스트와 양쪽 CLI smoke test로 함께 검증합니다.
- CLI flag/default path는 command package에서 유지합니다.
