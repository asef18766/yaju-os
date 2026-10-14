# Nordic legacy DFU CTF target

這是一個可實際跑通的 Nordic **legacy BLE DFU** 題目骨架。預期解法只有一件事：
legacy bootloader 對 application image 做 CRC/相容性檢查，卻不驗證簽章；參賽者因此能
刷入自己的 Thumb image，讀取題目板子的 GPIO secret，再從正常的 UART 輸出路徑取回它。

它刻意沒有再疊 parser bug、memory corruption 或 Web/API 題。

預設 runner 對齊 Nordic nRF5 SDK 11 的 `PCA10028 / nRF51422_xxAC /
dual_bank_ble_s130` legacy DFU target：256 KiB flash、32 KiB SRAM、S130 2.0.0
（FWID `0x0080`）、application base `0x1b000`、bootloader base `0x3c000`。

```text
player HCI client -- H4/TCP --+                     +-- H4/TCP -- target runner
                              |                     |                 |
                              +---- Rootcanal -------+              Bumble GATT
                                                         actual ATT/GATT |
                                                                    S130 event shim
                                                                        |
                                                  compiled SDK 11 legacy DFU in Qiling
                                                    | pstorage / dual-bank copy |
                                                    +-----------+--------------+
                                                                |
                                                          Qiling Cortex-M app
                                                              |          |
                                                        P0.IN secret   UART0.TXD
                                                              |          |
                                                     host-only secret  BLE console
```

Rootcanal 的 TCP port 是 H4/HCI，不是「DFU over TCP」。因此 target 端使用 Bumble
作為一個 BLE peripheral，參賽者也必須以另一個 H4 connection 接到同一個 Rootcanal
HCI port；兩邊才會真的走 advertising、ATT、CCCD、notification 與 GATT write。

## 題目模型

- Python model profile 的 Legacy DFU UUID family：service `1530`、control point `1531`、
  packet `1532`、status report `1533`，全部使用 Nordic legacy base UUID；direct-ELF
  profile 改用官方 SDK 11 的 control-point notification。
- 支援 application-only flow：

  ```text
  Start DFU -> image sizes -> init begin -> init data -> init complete
            -> firmware data -> validate -> activate/reset
  ```

- 支援完整 legacy init packet（device type/revision、app version、SoftDevice list、
  trailing CRC16）。SDK 11 nRF51 profile 使用真實 template 的限制：init packet 最多
  128 bytes、image 必須 4-byte aligned，且不接受只有 2-byte CRC 的簡化封包。
  通用 model 仍可開啟 CRC-only 相容模式，方便測舊版 target。
- 只接受 application image，避免題目變成改 bootloader/SoftDevice 的題目。
- image 要有可執行的 Cortex-M vector table，寫入 `0x1b000`；bootloader 保留區從
  `0x3c000` 開始，settings page 在 `0x3fc00`。真實 SDK target 是 dual-bank，因此
  0x21000-byte application region 中單次可收的 image 上限是 `0x10800` bytes。
- Qiling 中的 `P0.IN` 是 `0x50000510`。secret 僅在 guest 讀取該 MMIO register 時
  才會以連續 bytes 提供，並不在 flash、SRAM 或 guest filesystem。
- 範例 payload 將 UART0 `TXD`（`0x4000251c`）當成輸出。重開機後，player 可重新連線
  到 console service `6e400001-b5a3-f393-e0a9-e50e24dcca9e`，讀取 notify/read
  characteristic `6e400003-b5a3-f393-e0a9-e50e24dcca9e`。這是預期的 flag 輸出線，
  不是第二個漏洞。

## 實際編譯 Nordic nRF51 reference bootloader

此 repo 會抓取並編譯 Nordic 官方 nRF5 SDK 11 的 source，不是只憑文件猜 layout。選擇的
官方 Makefile target 是 `examples/dfu/bootloader/pca10028/dual_bank_ble_s130/armgcc`
的 `nrf51422_xxac`。

```bash
# Ubuntu/Debian；只需第一次安裝。
sudo apt-get install gcc-arm-none-eabi libnewlib-arm-none-eabi

./scripts/fetch_nrf51_sdk11.sh
./scripts/build_nrf51_sdk11_legacy_dfu.sh
```

產物在 `artifacts/nrf51_sdk11_legacy_dfu/`（刻意不納入 git）：ELF、HEX、map、flash-only
binary、section size 與 SHA-256 manifest 都會留下。SDK Makefile 會先產生一個巨大的 raw
`.bin`，因為它把 flash 與 UICR (`0x10001014`) 間的空洞也 materialize；build script 會在
抽出本題需要的 15,264-byte flash-only binary 後移除那個衍生檔。

SDK 11 的 `dfu_init_template.c` 明確採用 CRC16，並把 signing 留給可選擴充；這正是本題
保留的唯一安全性缺口。

### 執行 reference ELF，而不只讀它的 source

`Nrf51Sdk11BootloaderRuntime` 會將上面的 **ELF 的 PT_LOAD sections** 載入 Qiling，從真正的
`Reset_Handler` 開始跑。它提供最小的 nRF51 FICR/UICR、NVIC priority、MMIO register bank 與
S130 SVC ABI shim；實測會跑過 `sd_ble_enable`、加入 DFU service/三個 characteristics、
`sd_ble_gap_adv_start`，最後停在 `sd_app_evt_wait`。

S130 是專有 radio stack，因此它本身沒有被假裝成已完整 emulation：Qiling memory 中的 `svc`
instruction 會被 NOP 掉，host shim 回傳 ABI 結果，而 Nordic 編譯出的周邊 boot/DFU code 繼續執行。
Rootcanal/Bumble 仍負責實際 HCI/ATT/GATT transport。這個邊界是刻意明示的。

傳入 artifact 後，runner 不再把 DFU transfer 交給 Python model，而是改用
`Nrf51Sdk11BumblePeripheral`：Bumble 收到的 connection、control-point write 與 packet write
會被轉成 S130 2.0.0 的 `ble_evt_t`，注入 Qiling 裡編譯好的 `ble_evt_dispatch`。因此
`ble_dfu_on_ble_evt`、init packet、CRC、`pstorage_raw` queue 以及 dual-bank copy 都是官方 ELF
實際跑出的結果；`sd_ble_gatts_hvx` 會回到 Bumble 的 control-point notification，activate 後才由
Qiling 跑寫入 application region 的 player firmware。

```bash
hitcon-legacy-dfu \
  --secret-file /run/secrets/team-01.flag \
  --hci-transport tcp-client:127.0.0.1:6402 \
  --reference-bootloader-elf artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.elf
```

這個 direct-ELF mode 使用官方 SDK 11 的實際 GATT shape：response notification 在 control point
`1531` 本身，沒有 Python model 為了方便觀察而提供的 `1533` status-report characteristic。標準
legacy DFU client 對兩種形狀都能正常處理；自寫 client 應訂閱 `1531`。

S130 的 radio/RTC/SWI 仍不是完整 emulation。host shim 只做三件必要的事：把 Bumble 的 CCCD 狀態
回覆給 `sd_ble_gatts_value_get`、把 `sd_ble_gatts_hvx` payload 回送給 Bumble、在 `pstorage_raw`
要求 S130 flash operation 後遞送完成事件。DFU timeout/connection-parameter timer API 會同步回覆
success，而非模擬 RTC interrupt。這些界線不會改寫 DFU protocol 或驗證邏輯，且刻意在程式碼與題目
說明中明示。

若不傳 artifact，runner 仍使用較快的 Python challenge model；它可用於開發基本 protocol 或無法
安裝 Qiling 的環境。model mode 的兩個安全性 gate 也可個別交由 ELF 驗證（API level）使用，但這和
上面完整 direct-ELF transport 是不同模式。

## 啟動完整 target

建議在隔離的 per-team container/VM 中跑一組 Rootcanal 與 target，避免不同隊伍的
controller、RF traffic 和 flag 共用。

```bash
python3 -m pip install -e '.[full]'

# terminal 1: only expose hci_port to the player network.
python3 -m rootcanal \
  --hci_port=6402 --test_port=6401 --link_port=6403 --link_ble_port=6404 \
  --enable_log_color=false

# terminal 2: do not place the flag in the uploaded image or guest-visible env.
hitcon-legacy-dfu \
  --secret-file /run/secrets/team-01.flag \
  --hci-transport tcp-client:127.0.0.1:6402
```

`--test_port`、`--link_port`、`--link_ble_port` 應只留給 infrastructure；對外只代理
HCI port，並且限制每個 player instance 的連線數、時間與 CPU/memory。Qiling 的
instruction budget 預設為 5,000，可用 `--instruction-budget` 調整。

## 測試

不裝 optional dependency 時，core protocol tests 仍可跑：

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

安裝 `.[full]` 並先 build reference ELF 後，同一條指令還會跑真實整合測試：

1. 兩個獨立 H4 TCP controller 經 Rootcanal 完整走一次 legacy DFU GATT upload。
2. 同一條 upload 在 activate/reset 後進入 Qiling、讀取 `P0.IN`、寫 UART，接著由
   第二次 BLE 連線從 console characteristic 讀回輸出。
3. 官方 nRF51 ELF 從 `Reset_Handler` 跑到 DFU advertising event loop，且其
   `dfu_init_prevalidate`/`dfu_init_postvalidate` 會接受 unsigned、CRC-correct image。
4. Rootcanal 的真實 ATT/GATT upload 會驅動該 ELF 的 `ble_evt_dispatch`、`pstorage_raw` 與
   dual-bank activation，再由 Qiling app 讀 GPIO 並從 console characteristic 回傳資料。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
