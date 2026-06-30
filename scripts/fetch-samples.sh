#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTDATA_DIR="$ROOT_DIR/testdata"
NVTRUST_COMMIT="0c5d627313037c1e577d05a232e79394a41b2c21"
ATTESTATION_SDK_COMMIT="bbef6857afccede55d44727b4ce7c0facf31d014"

mkdir -p "$TESTDATA_DIR"

echo "[1/9] downloading sample Hopper quote"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/nvtrust/${NVTRUST_COMMIT}/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/samples/hopperAttestationReport.txt" \
  -o "$TESTDATA_DIR/hopperAttestationReport.txt"

echo "[2/9] downloading sample Hopper certificate chain"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/nvtrust/${NVTRUST_COMMIT}/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/samples/hopperCertChain.txt" \
  -o "$TESTDATA_DIR/hopperCertChain.txt"

echo "[3/10] downloading attestation-sdk serialized GPU evidence"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/common-test-data/serialized_test_evidence/hopper_evidence.json" \
  -o "$TESTDATA_DIR/hopper_evidence.json"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/common-test-data/serialized_test_evidence/multi_gpu_hopper.json" \
  -o "$TESTDATA_DIR/multi_gpu_hopper.json"

echo "[4/10] downloading attestation-sdk serialized/split NVSwitch LS10 evidence"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/common-test-data/serialized_test_evidence/switch_evidence_ls10.json" \
  -o "$TESTDATA_DIR/switch_evidence_ls10.json"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/common-test-data/serialized_test_evidence/multi_switch_ls10.json" \
  -o "$TESTDATA_DIR/multi_switch_ls10.json"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/nv-attestation-sdk-cpp/unit-tests/testdata/switchAttestationReport.txt" \
  -o "$TESTDATA_DIR/switchAttestationReport.txt"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/nv-attestation-sdk-cpp/unit-tests/testdata/switchCertChain.txt" \
  -o "$TESTDATA_DIR/switchCertChain.txt"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/${ATTESTATION_SDK_COMMIT}/nv-attestation-sdk-cpp/unit-tests/testdata/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml" \
  -o "$TESTDATA_DIR/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml"

echo "[5/10] downloading public NVIDIA device roots from NDIS"
curl -fsSL "https://docs.ndis.nvidia.com/certs/identity-root/Root-CA.cer" -o "$TESTDATA_DIR/Root-CA.cer"
curl -fsSL "https://docs.ndis.nvidia.com/certs/identity-root/Root-CA-L1B.cer" -o "$TESTDATA_DIR/Root-CA-L1B.cer"

echo "[6/10] downloading RIM root/schema and matching sample GPU RIMs"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/nvtrust/${NVTRUST_COMMIT}/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_RIM_root.pem" \
  -o "$TESTDATA_DIR/verifier_RIM_root.pem"
curl -fsSL \
  "https://raw.githubusercontent.com/NVIDIA/nvtrust/${NVTRUST_COMMIT}/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/swidSchema2015.xsd" \
  -o "$TESTDATA_DIR/swidSchema2015.xsd"
curl -fsSL "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GH100_550.90.07" \
  | jq -r '.rim' | base64 -d > "$TESTDATA_DIR/NV_GPU_DRIVER_GH100_550.90.07.swidtag"
curl -fsSL "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_1010_0200_882_96009F0001" \
  | jq -r '.rim' | base64 -d > "$TESTDATA_DIR/NV_GPU_VBIOS_1010_0200_882_96009F0001.swidtag"

echo "[7/10] converting DER roots to PEM"
openssl x509 -inform DER -in "$TESTDATA_DIR/Root-CA.cer" -out "$TESTDATA_DIR/Root-CA.pem"
openssl x509 -inform DER -in "$TESTDATA_DIR/Root-CA-L1B.cer" -out "$TESTDATA_DIR/Root-CA-L1B.pem"

echo "[8/10] building root bundle"
cat "$TESTDATA_DIR/Root-CA.pem" "$TESTDATA_DIR/Root-CA-L1B.pem" > "$TESTDATA_DIR/device-root-bundle.pem"

echo "[9/10] downloaded files:"
ls -1 "$TESTDATA_DIR" | sed 's#^#  - #'

echo "[10/10] sample artifacts ready in $TESTDATA_DIR"
