"""Qiling harness for the compiled Nordic SDK 11 nRF51 legacy-DFU ELF.

This deliberately has a narrow scope.  It executes Nordic's unmodified
bootloader code through Reset_Handler, substitutes the proprietary S130 ABI at
its SVC boundary, and exposes the compiled template's init/post-validation
functions plus its legacy-GATT event dispatcher.  Rootcanal/Bumble remains
the RF/GATT transport in this project; this is not a claim that S130's radio
implementation is emulated.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import tempfile
from typing import Any


NRF_SUCCESS = 0
NRF_ERROR_NOT_FOUND = 5
NRF_ERROR_INVALID_PARAM = 7

_FLASH_SIZE = 0x0004_0000
_SRAM_BASE = 0x2000_0000
_SRAM_SIZE = 0x0000_8000
_BOOTLOADER_BASE = 0x0003_C000
_BANK_1_BASE = 0x0002_B800
_MAX_DUAL_BANK_IMAGE_SIZE = 0x0001_0800
_S130_APPLICATION_BASE = 0x0001_B000
_S130_FWID = 0x0080
_S130_INFO_SIZE_ADDRESS = 0x0000_3008
_S130_INFO_FWID_ADDRESS = 0x0000_300C
_FICR_UICR_BASE = 0x1000_0000
_SYSTEM_ROM_BASE = 0xF000_0000
_PERIPHERAL_400_BASE = 0x4000_0000
_PERIPHERAL_500_BASE = 0x5000_0000
_PERIPHERAL_SIZE = 0x0010_0000
_CORTEX_SYSTEM_BASE = 0xE000_E000
_CORTEX_SYSTEM_SIZE = 0x1000
_CALL_SENTINEL = 0x2000_7E00
_CALL_STACK = 0x2000_7D00
_INIT_PACKET_BUFFER = 0x2000_6000
_BLE_EVENT_BUFFER = 0x2000_6400
_FLASH_PAGE_SIZE = 0x400
_MAX_FLASH_COMPLETIONS_PER_EVENT = 1024

# S130 SVC IDs reached by the SDK 11 boot/DFU paths.  The shim only models ABI
# outputs that the compiled bootloader consumes while processing legacy DFU.
_SVC_APP_EVT_WAIT = 0x48
_SVC_EVT_GET = 0x52
_SVC_BLE_ENABLE = 0x60
_SVC_BLE_EVT_GET = 0x61
_SVC_BLE_UUID_VS_ADD = 0x63
_SVC_BLE_GAP_ADDRESS_GET = 0x71
_SVC_BLE_GAP_ADV_START = 0x73
_SVC_BLE_GAP_DISCONNECT = 0x76
_SVC_BLE_GATTS_SERVICE_ADD = 0xA0
_SVC_BLE_GATTS_CHARACTERISTIC_ADD = 0xA2
_SVC_BLE_GATTS_VALUE_GET = 0xA5
_SVC_BLE_GATTS_HVX = 0xA6
_SVC_BLE_GATTS_RW_AUTHORIZE_REPLY = 0xA8
_SVC_FLASH_PAGE_ERASE = 0x28
_SVC_FLASH_WRITE = 0x29

_NRF_EVT_FLASH_OPERATION_SUCCESS = 2

# Event identifiers and field values from S130 2.0.0's ``ble.h`` / ``ble_gatts.h``.
_BLE_GAP_EVT_CONNECTED = 0x10
_BLE_GAP_EVT_DISCONNECTED = 0x11
_BLE_GATTS_EVT_WRITE = 0x50
_BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST = 0x51
_BLE_GATTS_AUTHORIZE_TYPE_WRITE = 2
_BLE_GATTS_OP_WRITE_REQ = 1
_BLE_GATTS_OP_WRITE_CMD = 2

# ``dfu_dual_bank.c`` leaves the state here only after the compiled CRC check
# succeeded and the target is waiting for legacy opcode 0x05.
_DFU_STATE_WAIT_4_ACTIVATE = 7


class Nrf51Sdk11RuntimeError(RuntimeError):
    """The reference ELF could not reach a supported execution boundary."""


class Nrf51Sdk11ArtifactError(Nrf51Sdk11RuntimeError):
    """The requested Nordic SDK build artifact is absent or unsuitable."""


class _ReachedEventWait(Exception):
    """Internal signal used once the real bootloader is advertising."""


class _FunctionReturned(Exception):
    """Internal signal used by the small in-RAM call trampoline."""


class _RegisterBank:
    """Simple little-endian MMIO register storage for a Qiling mapping."""

    def __init__(self, size: int) -> None:
        self._data = bytearray(size)

    def fill(self, offset: int, size: int, value: int) -> None:
        self._data[offset : offset + size] = bytes((value,)) * size

    def read(self, _ql: object, offset: int, size: int) -> int:
        return int.from_bytes(self._data[offset : offset + size], "little")

    def write(self, _ql: object, offset: int, size: int, value: int) -> None:
        self._data[offset : offset + size] = value.to_bytes(size, "little")


@dataclass(frozen=True)
class Nrf51Sdk11BootResult:
    """Observable milestones reached by the real Nordic bootloader ELF."""

    elf_path: Path
    elf_sha256: str
    entry_point: int
    reset_handler: int
    reached_event_wait: bool
    advertising_started: bool
    services_added: int
    characteristics_added: int
    svc_calls: tuple[int, ...]


@dataclass(frozen=True)
class Nrf51Sdk11DfuHandles:
    """ATT value/CCCD handles allocated by the compiled SDK 11 service."""

    packet_value: int
    control_point_value: int
    control_point_cccd: int


@dataclass(frozen=True)
class Nrf51Sdk11DfuEventResult:
    """Observable output from one host-delivered BLE event.

    Notifications are not reconstructed by Python: they were passed by the
    compiled ``ble_dfu_response_send`` code to the S130 ``hvx`` ABI shim.
    ``activated_image`` is set only after the compiled dual-bank copy has
    completed successfully.
    """

    notifications: tuple[bytes, ...]
    disconnect_requested: bool
    activated_image: bytes | None


class Nrf51Sdk11BootloaderRuntime:
    """Run the official SDK 11 nRF51 bootloader through its DFU-ready state.

    The official S130 SoftDevice is intentionally not executed: it is a large
    opaque radio stack.  Instead, each known S130 wrapper's SVC instruction is
    replaced *in emulated memory only* by a NOP and handled by a small ABI
    shim.  The wrappers are found from the ELF function-symbol table rather
    than by byte-scanning ``.text``: ARM literal pools live there too and may
    coincidentally contain the SVC byte pattern.
    Nordic's startup, SDK BLE-service setup,
    init-packet validation, image CRC validation, GATT event dispatch, flash
    staging, and dual-bank activation still execute as compiled ARM Thumb code
    from the supplied ELF.

    :meth:`connect`, :meth:`write_control_point`, and :meth:`write_packet`
    form the narrow boundary used by the Bumble/Rootcanal adapter.  Bumble
    owns HCI/ATT, while this class injects the equivalent S130 ``ble_evt_t``
    into Qiling and mirrors only the SoftDevice calls needed by that code.
    """

    def __init__(self, elf_path: str | Path, *, instruction_budget: int = 50_000) -> None:
        if instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")

        self.elf_path = Path(elf_path).resolve()
        self.instruction_budget = instruction_budget
        self._ql: Any | None = None
        self._bootstrap: tempfile.NamedTemporaryFile[bytes] | None = None
        self._symbols: dict[str, int] = {}
        self._svc_addresses: dict[int, int] = {}
        self._mode = "new"
        self._boot_result: Nrf51Sdk11BootResult | None = None
        self._svc_calls: list[int] = []
        self._advertising_started = False
        self._services_added = 0
        self._characteristics_added = 0
        self._next_attribute_handle = 1
        self._dfu_handles: Nrf51Sdk11DfuHandles | None = None
        self._connection_handle: int | None = None
        self._control_point_notifications_enabled = False
        self._notifications: list[bytes] = []
        self._disconnect_requested = False
        self._activated_image: bytes | None = None
        self._validated_image_size: int | None = None

    @staticmethod
    def repository_reference_elf() -> Path:
        """Return the artifact location generated by the bundled build script."""

        return (
            Path(__file__).resolve().parents[2]
            / "artifacts"
            / "nrf51_sdk11_legacy_dfu"
            / "nrf51422_xxac.elf"
        )

    def __enter__(self) -> "Nrf51Sdk11BootloaderRuntime":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the temporary bootstrap image retained by Qiling."""

        if self._bootstrap is not None:
            self._bootstrap.close()
            self._bootstrap = None
        self._ql = None
        self._dfu_handles = None
        self._connection_handle = None
        self._control_point_notifications_enabled = False
        self._notifications.clear()
        self._disconnect_requested = False
        self._activated_image = None
        self._validated_image_size = None
        if self._mode != "closed":
            self._mode = "closed"

    def boot(self) -> Nrf51Sdk11BootResult:
        """Execute Reset_Handler until the SDK waits for its first BLE event."""

        if self._boot_result is not None:
            return self._boot_result
        if self._mode == "closed":
            raise Nrf51Sdk11RuntimeError("runtime is closed")

        self._prepare_qiling()
        assert self._ql is not None

        reset_handler = self._symbol("Reset_Handler")
        self._mode = "boot"
        self._ql.arch.regs.msp = _SRAM_BASE + _SRAM_SIZE - 0x80
        self._ql.arch.regs.pc = reset_handler | 1
        try:
            self._ql.run(begin=reset_handler | 1, count=self.instruction_budget)
        except _ReachedEventWait:
            pass
        except Exception as exc:
            raise Nrf51Sdk11RuntimeError(
                f"official bootloader faulted before its DFU event loop: {type(exc).__name__}: {exc}"
            ) from exc
        else:
            raise Nrf51Sdk11RuntimeError(
                "official bootloader did not reach sd_app_evt_wait within the instruction budget"
            )

        if not self._advertising_started:
            raise Nrf51Sdk11RuntimeError(
                "official bootloader reached its event loop without starting BLE advertising"
            )

        self._mode = "ready"
        self._boot_result = Nrf51Sdk11BootResult(
            elf_path=self.elf_path,
            elf_sha256=hashlib.sha256(self.elf_path.read_bytes()).hexdigest(),
            entry_point=self._symbols["__entry_point__"],
            reset_handler=reset_handler,
            reached_event_wait=True,
            advertising_started=True,
            services_added=self._services_added,
            characteristics_added=self._characteristics_added,
            svc_calls=tuple(self._svc_calls),
        )
        return self._boot_result

    def prevalidate_init_packet(self, init_packet: bytes) -> int:
        """Call the ELF's real ``dfu_init_prevalidate`` function."""

        if not init_packet:
            raise ValueError("init_packet must not be empty")
        if len(init_packet) > 0x400:
            raise ValueError("init_packet exceeds the harness call buffer")

        self.boot()
        assert self._ql is not None
        self._ql.mem.write(_INIT_PACKET_BUFFER, init_packet)
        return self._call("dfu_init_prevalidate", _INIT_PACKET_BUFFER, len(init_packet))

    def postvalidate_image(self, image: bytes) -> int:
        """Call the ELF's real CRC16 post-validation over the staged image."""

        if not image:
            raise ValueError("image must not be empty")
        if len(image) > _MAX_DUAL_BANK_IMAGE_SIZE:
            raise ValueError("image exceeds the SDK 11 dual-bank staging capacity")

        self.boot()
        assert self._ql is not None
        self._ql.mem.write(_BANK_1_BASE, image)
        return self._call("dfu_init_postvalidate", _BANK_1_BASE, len(image))

    @property
    def dfu_handles(self) -> Nrf51Sdk11DfuHandles:
        """Return the value/CCCD handles created by the real DFU service."""

        self.boot()
        return self._require_dfu_handles()

    @property
    def activated_image(self) -> bytes | None:
        """Return the image copied to the S130 application region, if any."""

        return self._activated_image

    @property
    def connected(self) -> bool:
        """Whether a host-side central is currently attached to this instance."""

        return self._connection_handle is not None

    def connect(self, connection_handle: int = 0) -> Nrf51Sdk11DfuEventResult:
        """Deliver a real ``BLE_GAP_EVT_CONNECTED`` to the compiled ELF.

        ``connection_handle`` is supplied by the transport adapter.  Rootcanal
        normally assigns zero to a target's first connection, which is also
        the handle used by the integration test.
        """

        if not 0 <= connection_handle < 0xFFFF:
            raise ValueError("connection_handle must fit in an active uint16 handle")
        if self._connection_handle is not None:
            raise Nrf51Sdk11RuntimeError("the compiled DFU service already has a connection")

        self.boot()
        self._require_dfu_handles()
        self._connection_handle = connection_handle
        try:
            event = struct.pack(
                "<HHH",
                _BLE_GAP_EVT_CONNECTED,
                6,
                connection_handle,
            ) + b"\x00\x00"
            self._dispatch_ble_event(event)
            return self._event_result()
        except Exception:
            self._connection_handle = None
            raise

    def disconnect(self) -> Nrf51Sdk11DfuEventResult:
        """Deliver ``BLE_GAP_EVT_DISCONNECTED`` and clear host transport state."""

        connection_handle = self._require_connection()
        event = struct.pack(
            "<HHH",
            _BLE_GAP_EVT_DISCONNECTED,
            6,
            connection_handle,
        ) + b"\x00\x00"
        try:
            self._dispatch_ble_event(event)
            return self._event_result()
        finally:
            self._connection_handle = None
            self._control_point_notifications_enabled = False

    def set_control_point_notifications(self, enabled: bool) -> None:
        """Reflect the control-point CCCD held by the HCI/GATT transport.

        Nordic's ``ble_dfu_on_ble_evt`` asks S130 for this descriptor before
        it accepts an authorize-write control command.  The actual ATT CCCD
        operation happens in Bumble; this state is its tiny S130-side mirror.
        """

        self._require_connection()
        self._control_point_notifications_enabled = bool(enabled)

    def write_control_point(self, payload: bytes) -> Nrf51Sdk11DfuEventResult:
        """Inject an authorized control-point GATT write into the ELF."""

        payload = self._validate_att_payload(payload)
        connection_handle = self._require_connection()
        handles = self._require_dfu_handles()
        event = struct.pack(
            "<HHHBxHHBxBBHH",
            _BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST,
            20 + len(payload),
            connection_handle,
            _BLE_GATTS_AUTHORIZE_TYPE_WRITE,
            handles.control_point_value,
            0,
            2,
            _BLE_GATTS_OP_WRITE_REQ,
            1,
            0,
            len(payload),
        ) + payload
        self._dispatch_ble_event(event)
        if payload[:1] == b"\x04":
            self._remember_validated_image()
        elif payload[:1] == b"\x05":
            self._remember_activated_image()
        return self._event_result()

    def write_packet(self, payload: bytes) -> Nrf51Sdk11DfuEventResult:
        """Inject a packet-characteristic write-command into the ELF."""

        payload = self._validate_att_payload(payload)
        connection_handle = self._require_connection()
        handles = self._require_dfu_handles()
        event = struct.pack(
            "<HHHHHBxBBHH",
            _BLE_GATTS_EVT_WRITE,
            18 + len(payload),
            connection_handle,
            handles.packet_value,
            0,
            2,
            _BLE_GATTS_OP_WRITE_CMD,
            0,
            0,
            len(payload),
        ) + payload
        self._dispatch_ble_event(event)
        return self._event_result()

    def _dispatch_ble_event(self, event: bytes) -> None:
        """Run one S130 event through the compiled dispatcher and its flash work."""

        if len(event) > 0x100:
            raise ValueError("BLE event exceeds the Qiling harness event buffer")
        assert self._ql is not None
        self._notifications.clear()
        self._disconnect_requested = False
        self._ql.mem.write(_BLE_EVENT_BUFFER, event)
        self._call("ble_evt_dispatch", _BLE_EVENT_BUFFER)
        self._complete_flash_operations()

    def _complete_flash_operations(self) -> None:
        """Complete asynchronous S130 flash operations through real pstorage.

        ``pstorage_raw`` queues an SVC erase/write then waits for
        ``NRF_EVT_FLASH_OPERATION_SUCCESS``.  A physical SoftDevice delivers
        that later as a system event; the host shim delivers it synchronously
        after the operation's memory-side effect, preserving the compiled
        queue/callback code and its ordering.
        """

        for _ in range(_MAX_FLASH_COMPLETIONS_PER_EVENT):
            if not self._flash_operation_pending():
                return
            self._call("pstorage_sys_event_handler", _NRF_EVT_FLASH_OPERATION_SUCCESS)
        raise Nrf51Sdk11RuntimeError(
            "compiled pstorage queue did not drain after simulated flash completions"
        )

    def _flash_operation_pending(self) -> bool:
        assert self._ql is not None
        # ``pstorage_cmd_queue_t`` starts with rp/count/flash_access.  This is
        # a stable SDK 11 layout and deliberately read from the actual ELF's
        # BSS symbol instead of duplicated transfer state in Python.
        command_queue = self._symbol("m_cmd_queue")
        return bool(self._ql.mem.read(command_queue + 2, 1)[0])

    def _require_dfu_handles(self) -> Nrf51Sdk11DfuHandles:
        if self._dfu_handles is not None:
            return self._dfu_handles
        if self._mode != "ready":
            raise Nrf51Sdk11RuntimeError("compiled DFU service is not ready")
        assert self._ql is not None

        dfu_service = self._symbol("m_dfu")
        # SDK 11 ``ble_dfu_t`` has packet ``ble_gatts_char_handles_t`` at
        # +8 and control-point handles at +16.  The first uint16_t of each is
        # its value handle; the third control-point field is its CCCD handle.
        packet_value = self._read_u16(dfu_service + 8)
        control_point_value = self._read_u16(dfu_service + 16)
        control_point_cccd = self._read_u16(dfu_service + 20)
        handles = Nrf51Sdk11DfuHandles(
            packet_value=packet_value,
            control_point_value=control_point_value,
            control_point_cccd=control_point_cccd,
        )
        if any(handle == 0 for handle in (packet_value, control_point_value, control_point_cccd)):
            raise Nrf51Sdk11RuntimeError(
                "compiled DFU service did not expose packet/control-point handles"
            )
        if len({packet_value, control_point_value, control_point_cccd}) != 3:
            raise Nrf51Sdk11RuntimeError("compiled DFU service allocated overlapping ATT handles")
        self._dfu_handles = handles
        return handles

    def _require_connection(self) -> int:
        if self._connection_handle is None:
            raise Nrf51Sdk11RuntimeError("no central is connected to the compiled DFU service")
        return self._connection_handle

    def _validate_att_payload(self, payload: bytes) -> bytes:
        data = bytes(payload)
        # S130 2.0.0 on nRF51 begins at ATT MTU 23, leaving twenty value bytes.
        # The target does not negotiate a larger MTU, so reject packets a real
        # peer could not have supplied to this legacy service.
        if not data:
            raise ValueError("ATT write payload must not be empty")
        if len(data) > 20:
            raise ValueError("SDK 11 legacy DFU accepts at most 20 ATT value bytes")
        return data

    def _remember_validated_image(self) -> None:
        assert self._ql is not None
        if self._ql.mem.read(self._symbol("m_dfu_state"), 1)[0] != _DFU_STATE_WAIT_4_ACTIVATE:
            return
        image_size = self._read_u32(self._symbol("m_image_size"))
        if not 0 < image_size <= _MAX_DUAL_BANK_IMAGE_SIZE:
            return
        self._validated_image_size = image_size

    def _remember_activated_image(self) -> None:
        """Observe the image only after compiled dual-bank copy completion."""

        assert self._ql is not None
        image_size = self._validated_image_size
        if image_size is None:
            return
        staged = bytes(self._ql.mem.read(_BANK_1_BASE, image_size))
        active = bytes(self._ql.mem.read(_S130_APPLICATION_BASE, image_size))
        if active == staged and active != b"\xff" * image_size:
            self._activated_image = active

    def _event_result(self) -> Nrf51Sdk11DfuEventResult:
        result = Nrf51Sdk11DfuEventResult(
            notifications=tuple(self._notifications),
            disconnect_requested=self._disconnect_requested,
            activated_image=self._activated_image,
        )
        self._notifications.clear()
        return result

    def _read_u16(self, address: int) -> int:
        assert self._ql is not None
        return struct.unpack("<H", bytes(self._ql.mem.read(address, 2)))[0]

    def _read_u32(self, address: int) -> int:
        assert self._ql is not None
        return struct.unpack("<I", bytes(self._ql.mem.read(address, 4)))[0]

    def _prepare_qiling(self) -> None:
        if self._ql is not None:
            return
        if not self.elf_path.is_file():
            raise Nrf51Sdk11ArtifactError(f"reference bootloader ELF does not exist: {self.elf_path}")

        try:
            from elftools.elf.elffile import ELFFile
            from qiling import Qiling
            from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        except ModuleNotFoundError as exc:
            raise Nrf51Sdk11ArtifactError(
                "Qiling and its ELF loader are required; install the 'emulator' extra"
            ) from exc

        with self.elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            self._symbols = self._read_symbols(elf)
            self._symbols["__entry_point__"] = int(elf.header["e_entry"])
            segments = [
                (int(segment["p_paddr"]), segment.data())
                for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]
            ]
            self._svc_addresses = self._find_svc_instructions(elf)

        for symbol in (
            "Reset_Handler",
            "dfu_init_prevalidate",
            "dfu_init_postvalidate",
            "ble_evt_dispatch",
            "pstorage_sys_event_handler",
            "app_timer_start",
            "app_timer_stop",
            "m_dfu",
            "m_dfu_state",
            "m_image_size",
            "m_cmd_queue",
        ):
            self._symbol(symbol)

        self._bootstrap = tempfile.NamedTemporaryFile(suffix=".bin")
        self._bootstrap.write(struct.pack("<II", _SRAM_BASE + _SRAM_SIZE, 1))
        self._bootstrap.flush()
        env = {
            "FLASH": {"base": 0, "size": _FLASH_SIZE, "type": "memory"},
            "SRAM": {"base": _SRAM_BASE, "size": _SRAM_SIZE, "type": "memory"},
        }
        ql = Qiling(
            [self._bootstrap.name, 0],
            archtype=QL_ARCH.CORTEX_M,
            ostype=QL_OS.MCU,
            env=env,
            verbose=QL_VERBOSE.OFF,
        )

        # Model erased flash/UICR first, then load the actual ELF's PT_LOAD
        # contents exactly as Qiling's MCU loader would (using p_paddr).
        ql.mem.write(0, b"\xff" * _FLASH_SIZE)
        ql.mem.map(_FICR_UICR_BASE, 0x2000, info="[nRF51 FICR/UICR]")
        ql.mem.write(_FICR_UICR_BASE, b"\xff" * 0x2000)
        ql.mem.map(_SYSTEM_ROM_BASE, 0x1000, info="[Cortex-M CPUID]")

        peripheral_400 = _RegisterBank(_PERIPHERAL_SIZE)
        peripheral_500 = _RegisterBank(_PERIPHERAL_SIZE)
        cortex_system = _RegisterBank(_CORTEX_SYSTEM_SIZE)
        # nRF51 has two implemented NVIC priority bits.  Give application IRQs
        # priority 1 (encoded as 0x40), which permits the SDK's SWI2 handler.
        cortex_system.fill(0x400, 0x20, 0x40)
        ql.mem.map_mmio(_PERIPHERAL_400_BASE, _PERIPHERAL_SIZE, peripheral_400, "[nRF51 peripherals]")
        ql.mem.map_mmio(_PERIPHERAL_500_BASE, _PERIPHERAL_SIZE, peripheral_500, "[nRF51 peripherals]")
        ql.mem.map_mmio(_CORTEX_SYSTEM_BASE, _CORTEX_SYSTEM_SIZE, cortex_system, "[Cortex-M system]")

        for address, data in segments:
            ql.mem.write(address, data)
        # The reference bootloader reads its real update layout from S130's
        # information structure rather than from a build-time constant.  Seed
        # the S130 2.0.0 fields that a flashed PCA10028 would provide; without
        # these, erased ``0xffffffff`` metadata makes the compiled dual-bank
        # code calculate a nonsensical staging-bank address.
        ql.mem.write(_S130_INFO_SIZE_ADDRESS, struct.pack("<I", _S130_APPLICATION_BASE))
        ql.mem.write(_S130_INFO_FWID_ADDRESS, struct.pack("<I", _S130_FWID))

        # The build emits UICR boot-start address.  Set board identity values
        # the bootloader checks even if a toolchain emitted no UICR section.
        ql.mem.write(0x1000_0010, struct.pack("<I", 0x400))  # FICR.CODEPAGESIZE
        ql.mem.write(0x1000_0014, struct.pack("<I", _FLASH_SIZE // 0x400))  # FICR.CODESIZE
        ql.mem.write(0x1000_1000, struct.pack("<I", _S130_APPLICATION_BASE))  # UICR.CLENR0
        ql.mem.write(0x1000_1010, struct.pack("<I", _S130_FWID))  # UICR.FWID
        ql.mem.write(0x1000_1014, struct.pack("<I", _BOOTLOADER_BASE))

        # The S130 API wrappers are ``svc imm; bx lr``.  Only wrapper function
        # entry points discovered from symbols are patched; literal data is
        # left untouched.
        for address in self._svc_addresses:
            ql.mem.write(address, b"\x00\xbf")
        # The DFU timeout/connection-parameter timers rely on nRF51 RTC/SWI
        # interrupts, which are outside this intentionally narrow harness.
        # Keep their API outcome (NRF_SUCCESS) while letting the compiled DFU,
        # BLE event, CRC, and pstorage paths execute unchanged.  Do this before
        # Qiling executes the ELF so Unicorn cannot retain translated original
        # timer blocks in its cache.
        for symbol in ("app_timer_start", "app_timer_stop"):
            ql.mem.write(self._symbol(symbol), b"\x00\x20\x70\x47")  # movs r0,#0; bx lr
        ql.mem.write(_CALL_SENTINEL, b"\x00\xbf")
        ql.hook_code(self._on_code)

        self._ql = ql

    def _read_symbols(self, elf: Any) -> dict[str, int]:
        symbol_table = elf.get_section_by_name(".symtab")
        if symbol_table is None:
            raise Nrf51Sdk11ArtifactError("reference ELF has no symbol table")
        return {
            symbol.name: int(symbol["st_value"])
            for symbol in symbol_table.iter_symbols()
            if symbol.name
        }

    def _find_svc_instructions(self, elf: Any) -> dict[int, int]:
        """Find SVC wrappers without interpreting literal-pool bytes as code."""

        symbol_table = elf.get_section_by_name(".symtab")
        if symbol_table is None:
            raise Nrf51Sdk11ArtifactError("reference ELF has no symbol table")

        load_segments = [
            (int(segment["p_paddr"]), segment.data())
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]
        ]

        def read_instruction(address: int) -> bytes:
            for base, data in load_segments:
                offset = address - base
                if 0 <= offset <= len(data) - 2:
                    return data[offset : offset + 2]
            return b""

        result: dict[int, int] = {}
        for symbol in symbol_table.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address = int(symbol["st_value"]) & ~1
            instruction = read_instruction(address)
            # ARMv6-M ``svc imm8`` is ``imm8, 0xdf`` in little-endian memory.
            if len(instruction) == 2 and instruction[1] == 0xDF:
                result[address] = instruction[0]
        if not result:
            raise Nrf51Sdk11ArtifactError("reference ELF contains no S130 SVC wrappers")
        return result

    def _on_code(self, ql: Any, address: int, _size: int) -> None:
        svc_number = self._svc_addresses.get(address)
        if svc_number is not None:
            self._svc_calls.append(svc_number)
            self._handle_svc(ql, svc_number)
            if self._mode == "boot" and svc_number == _SVC_APP_EVT_WAIT:
                raise _ReachedEventWait()

        if self._mode == "call" and address == _CALL_SENTINEL:
            raise _FunctionReturned()

    def _handle_svc(self, ql: Any, svc_number: int) -> None:
        # Most startup APIs return NRF_SUCCESS and do not expose data that the
        # bootloader uses.  The following cases have output pointers/state that
        # the compiled SDK code subsequently consumes.
        if svc_number in {_SVC_EVT_GET, _SVC_BLE_EVT_GET}:
            ql.arch.regs.r0 = NRF_ERROR_NOT_FOUND
            return

        if svc_number == _SVC_FLASH_PAGE_ERASE:
            page_number = ql.arch.regs.r0
            address = page_number * _FLASH_PAGE_SIZE
            if address < 0 or address + _FLASH_PAGE_SIZE > _FLASH_SIZE:
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            ql.mem.write(address, b"\xff" * _FLASH_PAGE_SIZE)
            ql.arch.regs.r0 = NRF_SUCCESS
            return

        if svc_number == _SVC_FLASH_WRITE:
            destination = ql.arch.regs.r0
            source = ql.arch.regs.r1
            words = ql.arch.regs.r2
            byte_count = words * 4
            if (
                destination < 0
                or byte_count < 0
                or destination + byte_count > _FLASH_SIZE
                or destination % 4
            ):
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            ql.mem.write(destination, bytes(ql.mem.read(source, byte_count)))
            ql.arch.regs.r0 = NRF_SUCCESS
            return

        if svc_number == _SVC_BLE_GATTS_VALUE_GET:
            value = b"\x00\x00"
            handles = self._dfu_handles
            if (
                handles is not None
                and ql.arch.regs.r1 == handles.control_point_cccd
                and self._control_point_notifications_enabled
            ):
                value = b"\x01\x00"
            value_pointer = ql.arch.regs.r2
            if not value_pointer:
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            data_pointer = self._read_u32(value_pointer + 4)
            if not data_pointer:
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            ql.mem.write(value_pointer, struct.pack("<H", len(value)))
            ql.mem.write(data_pointer, value)
            ql.arch.regs.r0 = NRF_SUCCESS
            return

        if svc_number == _SVC_BLE_GATTS_HVX:
            parameters_pointer = ql.arch.regs.r1
            if not parameters_pointer:
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            handle = self._read_u16(parameters_pointer)
            length_pointer = self._read_u32(parameters_pointer + 8)
            data_pointer = self._read_u32(parameters_pointer + 12)
            if not length_pointer or not data_pointer:
                ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM
                return
            length = self._read_u16(length_pointer)
            handles = self._dfu_handles
            if (
                handles is not None
                and handle == handles.control_point_value
                and self._control_point_notifications_enabled
            ):
                self._notifications.append(bytes(ql.mem.read(data_pointer, length)))
            ql.arch.regs.r0 = NRF_SUCCESS
            return

        if svc_number == _SVC_BLE_GAP_DISCONNECT:
            self._disconnect_requested = True
            ql.arch.regs.r0 = NRF_SUCCESS
            return

        if svc_number == _SVC_BLE_ENABLE:
            app_ram_base_pointer = ql.arch.regs.r1
            if app_ram_base_pointer:
                ql.mem.write(app_ram_base_pointer, struct.pack("<I", 0x2000_2C00))
        elif svc_number == _SVC_BLE_UUID_VS_ADD:
            uuid_type_pointer = ql.arch.regs.r1
            if uuid_type_pointer:
                ql.mem.write(uuid_type_pointer, b"\x02")
        elif svc_number == _SVC_BLE_GAP_ADDRESS_GET:
            address_pointer = ql.arch.regs.r0
            if address_pointer:
                # ble_gap_addr_t: type byte followed by six little-endian BLE
                # address bytes.  The exact address is immaterial to DFU.
                ql.mem.write(address_pointer, b"\x01\xfb\xfa\xf9\xf8\xf7\xf6")
        elif svc_number == _SVC_BLE_GATTS_SERVICE_ADD:
            handle_pointer = ql.arch.regs.r2
            ql.mem.write(handle_pointer, struct.pack("<H", self._allocate_handle()))
            self._services_added += 1
        elif svc_number == _SVC_BLE_GATTS_CHARACTERISTIC_ADD:
            handles_pointer = ql.arch.regs.r3
            handles = [self._allocate_handle() for _ in range(4)]
            ql.mem.write(handles_pointer, struct.pack("<4H", *handles))
            self._characteristics_added += 1
        elif svc_number == _SVC_BLE_GAP_ADV_START:
            self._advertising_started = True

        ql.arch.regs.r0 = NRF_SUCCESS

    def _allocate_handle(self) -> int:
        handle = self._next_attribute_handle
        self._next_attribute_handle += 1
        return handle

    def _symbol(self, name: str) -> int:
        try:
            return self._symbols[name] & ~1
        except KeyError as exc:
            raise Nrf51Sdk11ArtifactError(f"reference ELF is missing symbol: {name}") from exc

    def _call(self, symbol: str, *arguments: int) -> int:
        if self._mode != "ready":
            raise Nrf51Sdk11RuntimeError("reference bootloader is not ready for direct calls")
        if len(arguments) > 4:
            raise ValueError("ARM register-call helper supports at most four arguments")
        assert self._ql is not None

        self._mode = "call"
        try:
            for index in range(4):
                self._ql.arch.regs.write(f"r{index}", arguments[index] if index < len(arguments) else 0)
            self._ql.arch.regs.msp = _CALL_STACK
            self._ql.arch.regs.lr = _CALL_SENTINEL | 1
            address = self._symbol(symbol)
            self._ql.arch.regs.pc = address | 1
            try:
                self._ql.run(begin=address | 1, count=self.instruction_budget)
            except _FunctionReturned:
                return self._ql.arch.regs.r0
            except Exception as exc:
                raise Nrf51Sdk11RuntimeError(
                    f"reference ELF faulted in {symbol}: {type(exc).__name__}: {exc}"
                ) from exc
            raise Nrf51Sdk11RuntimeError(f"reference ELF did not return from {symbol}")
        finally:
            if self._mode != "closed":
                self._mode = "ready"
