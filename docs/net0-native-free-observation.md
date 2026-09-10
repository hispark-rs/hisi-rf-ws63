# NET0 Native Free Observation

Status: default-off diagnostic prototype, not an allocation-lifetime or DMA
fence contract. Native ownership and return values remain unchanged.

## Pinned ABI

The matching SDK paths are relative to an explicitly supplied oracle checkout;
consumer Cargo builds do not read that checkout:

- `src/protocol/wifi/rom_code/ws63/source/inc/romable/oal_net_pkt_rom.h`
  defines callback 249 as one opaque native-netbuf pointer returning `u32`.
- `src/protocol/wifi/rom_code/ws63/source/device/frw/romable/frw_rom_cb_rom.h`
  defines the ROM callback table and the two-argument, void-returning register.
- `src/protocol/wifi/rom_code/ws63/source/device/frw/romable/oal_pkt_netbuf_rom.h`
  defines the native subpool records. It does not establish a live-origin bound.

The SDK final assembly registers `oal_mem_netbuf_free_from_ram` at callback
249 in `dmac_main_rom_cb_base_init_before_frw_init`. The normalized archive
keeps the free function `STB_LOCAL`; `--wrap` cannot resolve its `__real_*`
alias. Do not globalize it or write its current image address into Rust.

Instead, the experiment wraps the public `frw_rom_cb_register`, captures the
typed original pointer for 249, and publishes its observer in the same short
critical section. The ROM register function only stores a RAM-table entry;
it does not invoke the callback. All other callback IDs forward unchanged.
A null registration clears the saved original and publishes null, not an
observer without a target. Re-registering the observer does not capture itself.

The saved pointer is copied under a short critical section; the native free
call runs outside it and is forwarded exactly once. No native netbuf is read,
copied, retained as an owner, or freed by Rust. Original return values remain
intact, including 0 (RAM free completed), 2 (not RAM, ROM continues pool free),
and errors. A missing original fails closed rather than falsely returning 0/2.

## ROM And Pool Observations

Read-only ROM examination places `oal_mem_netbuf_free` at `0x132364`.
It consults callback 250 before 249. With 250 null, the saved 249 callback is
invoked; a return of 2 continues into the ROM pool-free path at `0x132b70`.
Runtime bootstrap validation therefore requires 249 to point to the observer,
an original function to have been captured, and 250 to be null. The observer
must not claim coverage if a different pbuf-free callback can bypass it.

The fixed paired rigs' pool-header snapshots both report 35 control blocks,
four subpools and a 16-byte control stride. The AP subpool counts are
9 + 0 + 10 + 16. This is a pool-capacity observation, not proof that all live
RX buffers are pool-backed or that 16 descriptors bound outstanding origins.
Snapshots were sequential, not an atomic cross-board ownership census.

Source and read-only capture hashes:

| Input | SHA-256 |
| --- | --- |
| `oal_net_pkt_rom.h` | `d04a5d581db591a6876b015c6250f1f15e24facea066b06951e40146d514c614` |
| `frw_rom_cb_rom.h` | `081d9473acf6c3b941633f993debb80ea17765fbc694947547f1f06d5b080ba1` |
| `oal_pkt_netbuf_rom.h` | `0c907a9252edf0c96dee64e0bf3fe54c3667c107bf2a1ef3f45af08ef48122e1` |
| ROM `[0x132100, 0x132b00)` | `1b1d8d8eac978c4b21f4bcc1eddb21233183f3aa77fe30a4b3a2b9282824da9f` |
| ROM `[0x132a00, 0x132f00)` | `d289c0bf4959a0c0c7847836fd13a7faff1c45dbda67eafc8e7f0304a548282c` |
| AP pool header, 28 bytes | `beda354c03fda99415717eb88f2c2e44572e94d4bb93258d68ceeaf2e3803ea5` |
| AP four subpools, 80 bytes | `31d30a4e2044b5acd67140aabd93833c2fd810800fceaa07b874d68717917369` |
| STA pool header, 28 bytes | `ca3cdeaf1964b826e0170477867f7089d3b9e769a52cd0b31377ab0e9cbbd61f` |

The LLVM decoder does not decode every vendor instruction. These observations
are bounded to the audited calls, standard loads/stores, SDK declarations and
pool snapshots; they are not a complete ROM semantics proof.

## Verification Boundary

The final-ELF gate checks the initializer's local free-function argument, both
resolved registration edges, wrapper forwarding and both ROM thunk hops. It
also checks the existing descriptor hook/ROM patch destinations and physical
384-byte tracker plus 4-byte saved callback. Missing-link-argument consumer
tests must reject a build with the observation edge absent.

The census equation is:

```text
bindings = matched + replaced + retired_on_free_attempt + occupied
matched = closed_origin + current_origin + stale_origin
```

`retired_on_free_attempt` is deliberately recorded before native free. It is
not successful deallocation, DMA completion, or permission to reuse an epoch.
A failed free can make a later delivery unmatched; that is visible failed
coverage, never grounds to substitute the current epoch. Capacity failures,
unmatched delivery, failed bindings and counter exhaustion remain failures.

The marker pair `RFDBG_NET0_RX_ORIGIN` / `RFDBG_NET0_RX_FREE` uses one snapshot
per phase. Collectors must combine both; the old census equation is invalid
for this experiment. Host tests and Miri establish only Rust metadata behavior;
silicon coverage and one-shot traffic are separate results. Neither result
proves AMSDU generation inheritance, a native producer fence, or reconnect.
