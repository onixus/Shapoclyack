# Local inference on a Windows GPU workstation

This profile runs the operator's language model on a separate Windows machine
with an NVIDIA GPU that has 12 GB of VRAM. Shapoclyack reaches it over the LAN
as the `local` provider. It is a deployment guide, not an accepted profile: the
primary acceptance profile is the Mac CPU container
([local-operator-mac.md](local-operator-mac.md), [ADR 0005](adr/0005-local-operator-mac-acceptance.md)),
and Linux/NVIDIA acceptance is tracked separately in
[#609](https://github.com/onixus/Shapoclyack/issues/609). No runtime manifest is
written on Windows, so `GET /api/operator/status` reports configuration only and
never `manifest_attested=true` for this host.

## What fits in 12 GB

Use the same model artifact and context as the Mac profile, so prompts, output
limits and quality results stay comparable:

| Input | Value |
|---|---|
| Model repository | `unsloth/Qwen3.5-9B-GGUF` at `3885219b6810b007914f3a7950a8d1b469d598a5` |
| Artifact | `Qwen3.5-9B-Q4_K_M.gguf`, 5680522464 bytes |
| Artifact SHA-256 | `03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8` |
| Runtime | llama.cpp release `b11854` (`8e5a58df87ab59dfceb5b961ae26691e39f30c24`), Windows CUDA build |
| Context / slots | 8192 tokens, one slot |
| Model alias | `Qwen3.5-9B-Q4_K_M` (must equal `OCTO_OPERATOR_MODEL`) |

The Q4_K_M weights take about 5.3 GiB. With every layer offloaded and an
8192-token KV cache, the model fits in 12 GB with headroom for the Windows
desktop and the CUDA context. Check this on the actual card with `nvidia-smi`
under load instead of relying on this estimate. Larger quantizations (Q5_K_M,
Q6_K) or a longer context may also fit, but they are not pinned, change the
quality baseline and must not be substituted silently. Do not raise
`--ctx-size` above 8192: the operator budgets its prompts and the
`OCTO_OPERATOR_MAX_OUTPUT_TOKENS` reservation for that context.

## Install

Requirements: Windows 10/11 x64, a current NVIDIA driver (check with
`nvidia-smi`), and about 7 GB of disk space. The CUDA build of llama.cpp ships
with its CUDA runtime DLLs as a separate archive on the same release page; no
CUDA Toolkit installation is needed.

1. From the [llama.cpp release b11854](https://github.com/ggml-org/llama.cpp/releases/tag/b11854),
   download the Windows x64 CUDA archive and the matching `cudart` archive.
   Compare their SHA-256 values with the release page, then extract both into
   `C:\Shapoclyack\llm\bin`.
2. Download the model from the pinned revision and check it before first use:

   ```powershell
   New-Item -ItemType Directory -Force C:\Shapoclyack\llm\models | Out-Null
   curl.exe -L --fail -o C:\Shapoclyack\llm\models\Qwen3.5-9B-Q4_K_M.gguf `
     https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/3885219b6810b007914f3a7950a8d1b469d598a5/Qwen3.5-9B-Q4_K_M.gguf
   (Get-FileHash -Algorithm SHA256 C:\Shapoclyack\llm\models\Qwen3.5-9B-Q4_K_M.gguf).Hash.ToLower()
   # must print 03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8
   ```

   Then make the file read-only (`attrib +R`). A hash mismatch means the file
   must be deleted, not used.
3. Create the API key file. The key authenticates Shapoclyack to the server; it
   is never committed and is passed by file so it does not appear in the
   process command line:

   ```powershell
   $key = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
   Set-Content -NoNewline -Encoding ascii C:\Shapoclyack\llm\api-key.txt $key
   icacls C:\Shapoclyack\llm\api-key.txt /inheritance:r /grant:r "SYSTEM:R" "Administrators:R"
   ```

   On Windows PowerShell 5.1, which lacks `Convert.ToHexString`, generate the
   key with any 32-byte CSPRNG and store its hex form the same way.

## Run

Bind the server to the workstation's LAN address only, not `0.0.0.0`
(`192.168.1.50` below stands for that address):

```powershell
C:\Shapoclyack\llm\bin\llama-server.exe `
  --model C:\Shapoclyack\llm\models\Qwen3.5-9B-Q4_K_M.gguf `
  --alias Qwen3.5-9B-Q4_K_M `
  --host 192.168.1.50 --port 8080 `
  --api-key-file C:\Shapoclyack\llm\api-key.txt `
  --ctx-size 8192 --parallel 1 `
  --n-gpu-layers 99 `
  --n-predict 1024 --temp 0 --seed 42 `
  --reasoning off `
  --offline --no-webui --no-agent --no-ui-mcp-proxy
```

`--n-gpu-layers 99` offloads every layer. The generation flags match the Mac
profile. `--offline`, `--no-webui`, `--no-agent` and `--no-ui-mcp-proxy` turn off
model downloads, the browser UI and its tool proxy; the server is only an
inference endpoint.

To start it at boot without a logged-in user, register it as a scheduled task
under a dedicated local account with read access to `C:\Shapoclyack\llm` and no
administrator rights. Grant that account read access to `api-key.txt`.

```powershell
$llmArgs = (Get-Content C:\Shapoclyack\llm\args.txt -Raw)  # the flags above, one line
$action = New-ScheduledTaskAction -Execute C:\Shapoclyack\llm\bin\llama-server.exe -Argument $llmArgs
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName ShapoclyackLLM -Action $action -Trigger $trigger -Settings $settings `
  -User "$env:COMPUTERNAME\shapo-llm" -Password (Read-Host "shapo-llm password")
```

Allow inbound connections to the port only from the Shapoclyack API hosts
(`10.0.0.20` stands for those addresses; for k8s, use the node addresses or the
egress gateway the API pods leave through):

```powershell
New-NetFirewallRule -DisplayName "Shapoclyack LLM" -Direction Inbound -Protocol TCP `
  -LocalPort 8080 -RemoteAddress 10.0.0.20 -Profile Private,Domain -Action Allow
```

Check from the API host:

```sh
curl --fail http://192.168.1.50:8080/health
curl --fail -H "Authorization: Bearer $KEY" http://192.168.1.50:8080/v1/models   # lists Qwen3.5-9B-Q4_K_M
```

## Connect Shapoclyack

```sh
OCTO_OPERATOR_ENABLED=true
OCTO_OPERATOR_PROVIDER=local
OCTO_OPERATOR_BASE_URL=http://192.168.1.50:8080/v1
OCTO_OPERATOR_MODEL=Qwen3.5-9B-Q4_K_M
OCTO_OPERATOR_API_KEY=<contents of api-key.txt, from a deployment secret>
```

The `local` provider accepts only private IP literals (RFC 1918, loopback, IPv6
ULA), so use the workstation's address, not its host name; give it a DHCP
reservation so the address does not change. `OCTO_OPERATOR_ALLOW_EXTERNAL`
stays `false`: inference inputs remain on the LAN. In k8s, put the key in the
API Secret and allow API egress to `192.168.1.50:8080` in the API NetworkPolicy.

The LAN connection is plain HTTP. The key and the prompts, which contain finding
data, cross the network unencrypted, so keep the workstation and the API on a
trusted segment. If that is not acceptable, terminate TLS on the workstation (for
example with a reverse proxy) and use `https://192.168.1.50/v1`; the `local`
provider accepts HTTPS to a private IP literal and verifies the certificate,
which must then carry that IP address.

## Failure handling

If the server is down or out of VRAM, operator tasks fail with
`operator_transport_failed` or `operator_upstream_rejected`; there is no hosted
fallback. Look in the task's log or `llama-server` output for `out of memory`
first. Close other GPU workloads or reduce `--n-gpu-layers` (slower, partly on
CPU). Do not reduce the context or switch quantization without recording it.
