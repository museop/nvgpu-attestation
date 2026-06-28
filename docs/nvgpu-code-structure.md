# NVGPU verifier 코드 구조와 검증 동작

이 문서는 `internal/nvgpu` 패키지를 기준으로 코드가 어떻게 나뉘고, 주요 함수들이 어떤 순서로 NVGPU evidence를 검증하는지 설명합니다. 개념 중심 설명은 [`nvgpu-verification.md`](./nvgpu-verification.md), 샘플 데이터 설명은 [`sample-and-mock-data.md`](./sample-and-mock-data.md)를 참고하세요.

## 1. 패키지 구조 요약

`internal/nvgpu`는 “필수 로컬 검증”과 “선택적 appraisal”을 분리합니다.

| 파일 | 역할 | 주요 함수/타입 |
| --- | --- | --- |
| `verify.go` | 기본 타입, public 기본 API, quote 파서, 인증서/서명/opaque field helper | `Verify`, `VerifyFiles`, `VerifySerializedEvidence`, `ParseQuote`, `verifyCertChain`, `verifyQuoteSignature` |
| `pipeline.go` | 옵션 포함 검증 파이프라인. 기본 검증 후 OCSP/RIM/policy layer를 붙임 | `VerifyFilesWithOptions`, `verifyDetailed`, `verifyQuoteBinding`, `enrichResult` |
| `options.go` | 옵션과 optional verification 결과 타입 | `VerifyOptions`, `OCSPCheck`, `RIMVerification`, `MeasurementSummary` |
| `ocsp.go` | NVIDIA OCSP 질의와 결과 파싱 | `checkOCSPChain`, `queryOCSP` |
| `rim.go` | RIM ID 계산, RIM load/fetch, RIM XML parsing, RIM cert chain/OCSP 검증 orchestration | `verifyRIMsAndMeasurements`, `loadAndVerifyRIM`, `fetchRIM`, `parseRIM` |
| `rim_signature.go` | RIM XML DSIG digest/signature 검증 | `verifyRIMSignature`, `canonicalizeXML` |
| `measurement.go` | quote runtime measurement와 RIM golden measurement 비교 | `compareMeasurements`, `activeGoldenMeasurements`, `Response.getMeasurements` |
| `policy.go` | 서비스 정책 appraisal | `AppraisePolicy`, `PolicyOptions` |
| `mock.go` | 테스트/교육용 mock root/evidence 생성 | `GenerateMockRootBundle`, `GenerateMockQuoteBundleFromRoot` |
| `tempfile.go` | `openssl`, `xmllint` 호출을 위한 임시 파일 helper | `writeTempPEM`, `writeTempBytes` |

큰 흐름은 다음처럼 읽으면 됩니다.

```text
input files / serialized JSON
        │
        ▼
verify.go / pipeline.go
  - quote parse
  - nonce check
  - device cert chain verify
  - quote signature verify
  - FWID binding check
        │
        ▼
optional enrichResult
  ├─ ocsp.go: device cert OCSP
  ├─ rim.go + rim_signature.go + measurement.go: RIM + measurement appraisal
  └─ policy.go: relying-party policy appraisal
```

## 2. Public API와 입력 형식

### 기본 오프라인 검증 API

| 함수 | 입력 | 수행하는 검증 |
| --- | --- | --- |
| `VerifyFiles(quotePath, certChainPath, rootsPath, expectedNonceHex)` | split quote/cert/root 파일 | 파일 read 후 `Verify` 호출 |
| `Verify(quoteInput, certChainPEM, rootsPEM, expectedNonceHex)` | quote bytes 또는 hex text, PEM chain, PEM roots | 필수 로컬 검증만 수행 |
| `VerifySerializedEvidenceFile(jsonPath, rootsPath, index, expectedNonceHex)` | NVIDIA SDK 계열 serialized JSON | JSON entry 선택 후 검증 |
| `VerifySerializedEvidence(serializedJSON, rootsPEM, index, expectedNonceHex)` | serialized JSON bytes | 단일 entry 검증 |
| `VerifySerializedEvidenceAll(...)` | serialized JSON array | 모든 entry를 `BatchItem` 배열로 검증 |

기본 API는 네트워크를 사용하지 않습니다. 즉 OCSP, RIM fetch, RIM measurement appraisal, policy check는 수행하지 않습니다.

### 옵션 포함 검증 API

| 함수 | 추가 가능 layer |
| --- | --- |
| `VerifyFilesWithOptions(...)` | `VerifyOptions`에 따라 OCSP/RIM/policy 수행 |
| `VerifySerializedEvidenceFileWithOptions(...)` | serialized JSON 단일 entry + optional layer |
| `VerifySerializedEvidenceAllFileWithOptions(...)` | serialized JSON 전체 entry + optional layer |

`VerifyOptions`의 주요 필드는 다음과 같습니다.

| 필드 | 의미 |
| --- | --- |
| `VerifyOCSP` | device certificate chain에 대해 NVIDIA OCSP 확인 |
| `VerifyRIM` | driver/VBIOS RIM을 검증하고 measurement 비교 |
| `DriverRIMPath`, `VBIOSRIMPath` | 로컬 RIM 파일을 사용할 때 지정 |
| `RIMServiceURL` | 로컬 RIM 경로가 없을 때 fetch할 RIM service base URL |
| `RIMRootPEM`, `SWIDSchemaXSD` | RIM cert chain/schema 검증에 필요한 로컬 trust/schema 파일 |
| `VerificationTime` | X.509 chain validity 기준 시간. zero value면 현재 시간 |
| `Policy` | driver/VBIOS/architecture allowlist, OCSP/RIM required policy |

## 3. 필수 로컬 검증 흐름

필수 검증은 `pipeline.go`의 `verifyDetailed`가 담당합니다. 기본 `Verify`도 이 함수로 들어오고, 옵션 포함 API도 먼저 이 함수를 통과합니다.

```text
verifyDetailed
  ├─ decodeHexOrRaw
  ├─ ParseQuote
  ├─ parsePEMCertificates
  ├─ parseRootBundle
  ├─ parseNonce
  ├─ verifyCertChain
  ├─ newVerificationResult
  ├─ verifyNonce
  └─ verifyQuoteBinding
       ├─ verifyQuoteSignature
       ├─ populateOpaqueSummary
       ├─ extractLeafFWID
       └─ report FWID ↔ leaf FWID 비교
```

### `decodeHexOrRaw`

`testdata/hopperAttestationReport.txt`처럼 hex text로 저장된 quote와 raw bytes quote를 모두 받을 수 있게 입력을 정규화합니다.

- 공백 제거 후 전체가 hex 문자이면 hex decode
- 그렇지 않으면 raw bytes로 간주
- 빈 입력이나 odd-length hex는 오류

### `ParseQuote`

NVGPU quote를 request/response 구조로 나눕니다.

- request section: version/code/param/nonce/slot
- response header: measurement count/record length
- measurement record
- response nonce
- opaque fields
- 마지막 96 bytes signature

`ParseQuote`는 길이 일관성을 먼저 확인합니다. 길이가 맞지 않으면 이후 서명/measurement 검증으로 진행하지 않습니다.

### `verifyCertChain`

leaf certificate가 로컬 root bundle까지 이어지는지 Go `x509.Verify`로 확인합니다.

- `rootsPEM`은 trust anchor pool로 사용
- leaf 뒤의 chain certificate들은 intermediate pool로 사용
- root bundle과 같은 certificate가 chain에 포함되어 있으면 intermediate에서 제외
- `VerificationTime`이 지정되면 해당 시점 기준으로 NotBefore/NotAfter를 평가

### `verifyNonce`

quote request nonce와 verifier가 기대한 nonce를 비교합니다. nonce mismatch가 나면 `Result`는 반환하되 검증은 실패합니다. 이 덕분에 호출자는 실패 원인과 quote에 들어 있던 nonce를 함께 볼 수 있습니다.

### `verifyQuoteBinding`

quote가 해당 leaf certificate와 실제로 연결되는지 확인합니다.

1. `verifyQuoteSignature`
   - quote 마지막 96-byte signature를 제외한 부분을 SHA-384로 digest
   - leaf public key(ECDSA P-384)로 raw `r || s` signature 검증
2. `populateOpaqueSummary`
   - opaque field에서 driver version, VBIOS version, FWID, feature flag 등을 추출
3. `extractLeafFWID`
   - leaf certificate extension에서 FWID 추출
4. report FWID와 leaf FWID 비교

이 단계가 중요한 이유는 “인증서 chain이 유효하다”와 “그 인증서가 이 quote를 서명했고 quote 안 FWID와 certificate FWID가 같은 맥락이다”가 별개의 조건이기 때문입니다.

## 4. Optional enrichment 흐름

필수 로컬 검증이 성공하면 `enrichResult`가 옵션에 따라 추가 layer를 수행합니다.

```text
enrichResult
  ├─ if VerifyOCSP: checkOCSPChain(device chain, startIndex=1)
  ├─ if VerifyRIM:  verifyRIMsAndMeasurements
  └─ if Policy.Enabled: AppraisePolicy
```

기본 endpoint는 `options.go`에 있습니다.

```text
OCSP: https://ocsp.ndis.nvidia.com
RIM:  https://rim.attestation.nvidia.com/v1/rim/
```

## 5. OCSP 검증 코드

`ocsp.go`는 certificate revocation 상태 확인만 담당합니다.

### `checkOCSPChain`

입력 chain에서 인접한 `(cert, issuer)` pair를 만들어 `queryOCSP`를 반복 호출합니다.

- device certificate path에서는 `startIndex=1`을 사용해 FMC leaf 자체는 건너뛰고 BROM 이상 chain을 확인합니다.
- RIM signing certificate path에서는 `startIndex=0`으로 signer certificate부터 확인합니다.
- status가 `good`이면 통과 후보입니다.
- 현재 구현은 `revoked/certificateHold`를 별도 문자열로 보존합니다.
- 그 외 status는 오류로 처리합니다.

### `queryOCSP`

`openssl ocsp` CLI를 호출합니다.

```text
openssl ocsp -issuer issuer.pem -cert target.pem -url <ocspURL> -noverify -timeout 10
```

출력에서 status, `This Update`, `Next Update`를 파싱해 `OCSPCheck`로 반환합니다. 운영 환경에서는 OCSP response signature, responder chain, nonce/freshness 검증을 더 엄격히 다루는 것이 좋습니다.

## 6. RIM 검증 코드

RIM 검증은 `rim.go`, `rim_signature.go`, `measurement.go`에 나뉩니다.

### `verifyRIMsAndMeasurements`

quote/result에서 RIM ID를 만들고 driver RIM과 VBIOS RIM을 각각 검증합니다.

```text
driver ID = NV_GPU_DRIVER_GH100_<driver version>
vbios ID  = NV_GPU_VBIOS_<project>_<project SKU>_<chip SKU>_<VBIOS version without dots>
```

그 다음 `compareMeasurements`로 quote runtime measurement와 RIM golden measurement를 비교합니다.

### `loadAndVerifyRIM`

RIM 하나에 대해 아래 순서로 검증합니다.

1. `loadRIMBytes`
   - local path가 있으면 파일 read
   - 없으면 `fetchRIM`으로 RIM service에서 JSON/base64 payload fetch
2. `parseRIM`
   - SWID XML에서 `Meta.colloquialVersion`, `Payload.Resource`, XML DSIG 값, embedded X.509 cert들을 추출
3. `validateRIMSchema`
   - `xmllint --schema`로 SWID schema validation
4. RIM version match
   - RIM `colloquialVersion`과 quote에서 추출한 driver/VBIOS version 비교
5. embedded RIM cert chain verification
   - `RIMRootPEM`을 trust anchor로 `verifyCertChain`
6. RIM signing cert OCSP
   - `checkOCSPChain(doc.Certs, 0, opts.OCSPURL)`
7. XML signature verification
   - `verifyRIMSignature`
8. measurement count 기록

이 순서가 중요한 이유는 RIM 문서를 measurement 정답지로 사용하기 전에 “문서 형식, 서명자 chain, revocation 상태, XML digest/signature”가 모두 신뢰 가능해야 하기 때문입니다.

### `fetchRIM`

RIM service 응답을 다음 형태로 기대합니다.

```json
{ "rim": "<base64 encoded .swidtag XML>" }
```

HTTP status가 200이 아니면 body 일부를 포함한 오류를 반환합니다. 200이면 `rim` 필드를 base64 decode해 XML bytes를 반환합니다.

### `parseRIM`

streaming XML decoder로 필요한 값만 뽑습니다.

- `Meta`의 `colloquialVersion`
- `Resource`의 `index`, `active`, `size`, `Hash*`
- `DigestValue`
- `SignatureValue`
- `X509Certificate`

RIM 안에 X.509 certificate가 없거나 signature 필드가 없으면 실패합니다.

### `verifyRIMSignature`

RIM XML DSIG 검증은 `rim_signature.go`에 있습니다.

1. `<Signature>` element를 제거한 문서를 `xmllint --c14n11`로 canonicalize
2. SHA-384 digest가 `DigestValue`와 같은지 확인
3. `<SignedInfo>`를 canonicalize
4. `SignatureValue`를 raw ECDSA `r || s`로 해석
5. RIM signer certificate public key로 ECDSA-SHA384 검증

Go 표준 라이브러리에는 XML DSIG canonicalization 전체 구현이 없으므로, 이 저장소는 `xmllint --c14n11`에 의존합니다.

## 7. Measurement 비교 코드

`measurement.go`는 runtime measurement와 RIM golden measurement를 비교합니다.

### `Response.getMeasurements`

quote response의 measurement record를 block 단위로 읽고, 1-based measurement index를 0-based slice 위치에 저장합니다.

```text
measurement_block = index || spec || block_size || block_payload
block_payload     = type_or_spec || value_size || measurement_value
```

### `activeGoldenMeasurements`

- driver RIM에서 `active=true`인 measurement를 수집
- VBIOS RIM에서 `active=true`인 measurement를 추가
- 두 RIM이 같은 active index를 제공하면 conflict로 실패

### `compareMeasurements`

각 golden measurement에 대해 아래 조건을 확인합니다.

```text
runtime[index] == one_of(golden.Hash*)
len(runtime[index]) == golden.size * 2
```

특수 처리:

- NVDEC0가 disabled이면 measurement index 35를 skip합니다.
- runtime index가 없거나 값이 맞지 않으면 `MeasurementMismatch`에 기록합니다.
- mismatch가 하나라도 있으면 `MeasurementSummary.Verified=false`와 오류를 반환합니다.

## 8. Policy appraisal 코드

`policy.go`의 `AppraisePolicy`는 cryptographic verification 이후 relying party가 적용하는 서비스 정책입니다.

지원하는 정책:

- allowed driver versions
- allowed VBIOS versions
- allowed architecture
- measurement verification required
- device OCSP required

정책 실패는 quote나 RIM의 cryptographic failure와 다릅니다. 예를 들어 GPU evidence가 암호학적으로 정상이어도 서비스가 허용하지 않는 driver version이면 policy에서 거부할 수 있습니다.

## 9. Mock evidence 코드

`mock.go`는 실제 NVIDIA trust chain이 아니라 테스트 전용 root/leaf/quote를 생성합니다.

주요 용도:

- parser와 verifier pipeline 회귀 테스트
- serialized evidence shape 테스트
- policy appraisal 테스트

중요한 점은 mock evidence도 별도 mock verifier가 아니라 같은 `VerifyFilesWithOptions` 또는 `VerifySerializedEvidence` 경로를 통과한다는 것입니다. 차이는 trust anchor가 NVIDIA root bundle이 아니라 mock root라는 점뿐입니다.

## 10. 실패 지점별 해석

| 실패 위치 | 대표 오류 | 의미 |
| --- | --- | --- |
| `decodeHexOrRaw` | `empty input`, `hex input has odd length` | quote 입력 형식 문제 |
| `ParseQuote` | `quote too short`, `opaque length exceeds response size` | quote 구조/길이 문제 |
| `parsePEMCertificates` | `no PEM certificates found` | cert/root PEM 입력 문제 |
| `verifyCertChain` | `certificate chain verification failed` | root bundle 누락, chain 오류, validity 시간 문제 |
| `verifyNonce` | `nonce mismatch` | verifier가 요청한 quote가 아니거나 stale/replayed evidence |
| `verifyQuoteSignature` | `quote signature verification failed` | quote 변조 또는 leaf cert 불일치 |
| `verifyQuoteBinding` | `fwid mismatch` | quote opaque FWID와 leaf certificate FWID 불일치 |
| `checkOCSPChain` | `ocsp status ...` 또는 `openssl ocsp failed` | certificate revocation/status 확인 실패 |
| `loadAndVerifyRIM` | `rim version mismatch`, `rim cert chain verification failed` | RIM이 quote version과 다르거나 RIM signer chain이 유효하지 않음 |
| `verifyRIMSignature` | `rim digest mismatch`, `rim ecdsa signature invalid` | RIM XML 무결성/서명 실패 |
| `compareMeasurements` | `runtime measurements do not match golden measurements` | GPU runtime 상태가 RIM golden measurement와 다름 |
| `AppraisePolicy` | `policy verification failed` | cryptographic 검증 후 서비스 정책에서 거부 |

## 11. 리팩터링/확장 시 가이드

- 필수 로컬 검증은 `verifyDetailed` 경로에 유지합니다.
- 네트워크나 reference-data 의존 검증은 `enrichResult` 아래 optional layer로 둡니다.
- 새 RIM source를 추가하더라도 `loadAndVerifyRIM` 이후의 schema/cert/OCSP/signature/measurement 검증은 우회하지 않습니다.
- 새 policy는 `PolicyOptions`와 `AppraisePolicy`에 추가하고, cryptographic failure와 policy failure를 구분합니다.
- 외부 도구 호출(`openssl`, `xmllint`)은 실패를 숨기지 말고 stderr/stdout 일부를 포함한 명시적 오류로 반환합니다.
