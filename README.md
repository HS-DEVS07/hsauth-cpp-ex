# HS DEVS AUTH - C++ Client SDK (`hsauth.hpp`)

Single-header C++ SDK for [HS DEVS AUTH](https://hsauth.mujahid.xyz).

## Highlights
- **Single Header**: Include `hsauth.hpp` and compile directly with MSVC or GCC.
- **Native Windows Network**: Uses native `wininet.lib` on Windows (no curl or external packages required).
- **HWID Protection**: Automatically reads MachineGuid from Windows Registry.
- **Broadcast & Killswitch**: Supports real-time server messages.
