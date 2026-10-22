"""Qiling Cortex-M runner with secret GPIO and a narrow S130 GATT shim."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
import tempfile
from typing import Any
from uuid import UUID

from .hardware import GPIO_P0_BASE, GPIO_P0_IN_OFFSET
from .maintenance_runtime import FirmwareGattCharacteristic, FirmwareGattService


NRF_SUCCESS = 0
NRF_ERROR_INVALID_PARAM = 7
NRF_ERROR_INVALID_STATE = 8

_SVC_BLE_UUID_VS_ADD = 0x63
_SVC_BLE_GATTS_SERVICE_ADD = 0xA0
_SVC_BLE_GATTS_CHARACTERISTIC_ADD = 0xA2
_SUPPORTED_SVCS = {
    _SVC_BLE_UUID_VS_ADD,
    _SVC_BLE_GATTS_SERVICE_ADD,
    _SVC_BLE_GATTS_CHARACTERISTIC_ADD,
}
_BLE_UUID_TYPE_BLE = 1
_BLE_UUID_TYPE_VENDOR_BEGIN = 2
_BLE_GATTS_SRVC_TYPE_PRIMARY = 1
_BLE_GATTS_SRVC_TYPE_SECONDARY = 2
_BLE_GATT_HANDLE_INVALID = 0
_MAX_ATTRIBUTE_LENGTH = 512


class QilingUnavailable(RuntimeError):
    """The optional emulator dependency has not been installed."""


@dataclass(frozen=True)
class ExecutionResult:
    """Observable effects produced while the uploaded application booted."""

    gatt_services: tuple[FirmwareGattService, ...]
    svc_calls: tuple[int, ...]
    gpio_reads: int
    initial_sp: int
    reset_handler: int
    fault: str | None = None


class _SecretGpioP0:
    """P0 model whose IN register streams secret bytes to guest firmware."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self._offset = 0
        self.reads = 0

    def read(self, _ql: object, offset: int, size: int) -> int:
        if offset != GPIO_P0_IN_OFFSET:
            return 0
        self.reads += 1
        data = self._secret[self._offset : self._offset + size]
        self._offset += size
        return int.from_bytes(data.ljust(size, b"\x00"), "little")

    def write(self, _ql: object, _offset: int, _size: int, _value: int) -> None:
        return None


@dataclass
class _GattServiceBuilder:
    uuid: str
    firmware_handle: int
    primary: bool
    characteristics: list[FirmwareGattCharacteristic] = field(default_factory=list)


class _ApplicationSoftDevice:
    """Record the GATT table an uploaded raw image creates through S130 SVCs."""

    def __init__(self, ql: Any, svc_addresses: dict[int, int]) -> None:
        self.ql = ql
        self.svc_addresses = svc_addresses
        self.svc_calls: list[int] = []
        self.vendor_uuids: dict[int, bytes] = {}
        self.service_builders: list[_GattServiceBuilder] = []
        self.services_by_handle: dict[int, _GattServiceBuilder] = {}
        self.next_attribute_handle = 1

    @property
    def gatt_services(self) -> tuple[FirmwareGattService, ...]:
        return tuple(
            FirmwareGattService(
                uuid=service.uuid,
                firmware_handle=service.firmware_handle,
                primary=service.primary,
                characteristics=tuple(service.characteristics),
            )
            for service in self.service_builders
        )

    def on_code(self, ql: Any, address: int, _size: int) -> None:
        svc_number = self.svc_addresses.get(address)
        if svc_number is None:
            return
        self.svc_calls.append(svc_number)
        if svc_number == _SVC_BLE_UUID_VS_ADD:
            ql.arch.regs.r0 = self._uuid_vs_add(ql.arch.regs.r0, ql.arch.regs.r1)
        elif svc_number == _SVC_BLE_GATTS_SERVICE_ADD:
            ql.arch.regs.r0 = self._service_add(
                ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2
            )
        elif svc_number == _SVC_BLE_GATTS_CHARACTERISTIC_ADD:
            ql.arch.regs.r0 = self._characteristic_add(
                ql.arch.regs.r0,
                ql.arch.regs.r1,
                ql.arch.regs.r2,
                ql.arch.regs.r3,
            )

    def _uuid_vs_add(self, base_pointer: int, type_pointer: int) -> int:
        if not base_pointer or not type_pointer:
            return NRF_ERROR_INVALID_PARAM
        base = bytearray(self.ql.mem.read(base_pointer, 16))
        base[12:14] = b"\x00\x00"
        normalized = bytes(base)
        for uuid_type, registered in self.vendor_uuids.items():
            if registered == normalized:
                self.ql.mem.write(type_pointer, bytes((uuid_type,)))
                return NRF_SUCCESS
        uuid_type = _BLE_UUID_TYPE_VENDOR_BEGIN + len(self.vendor_uuids)
        if uuid_type > 0xFF:
            return NRF_ERROR_INVALID_STATE
        self.vendor_uuids[uuid_type] = normalized
        self.ql.mem.write(type_pointer, bytes((uuid_type,)))
        return NRF_SUCCESS

    def _service_add(
        self, service_type: int, uuid_pointer: int, handle_pointer: int
    ) -> int:
        if (
            service_type
            not in {_BLE_GATTS_SRVC_TYPE_PRIMARY, _BLE_GATTS_SRVC_TYPE_SECONDARY}
            or not uuid_pointer
            or not handle_pointer
        ):
            return NRF_ERROR_INVALID_PARAM
        uuid, _uuid16, _uuid_type = self._read_ble_uuid(uuid_pointer)
        handle = self._allocate_handle()
        builder = _GattServiceBuilder(
            uuid=uuid,
            firmware_handle=handle,
            primary=service_type == _BLE_GATTS_SRVC_TYPE_PRIMARY,
        )
        self.service_builders.append(builder)
        self.services_by_handle[handle] = builder
        self.ql.mem.write(handle_pointer, struct.pack("<H", handle))
        return NRF_SUCCESS

    def _characteristic_add(
        self,
        service_handle: int,
        metadata_pointer: int,
        attribute_pointer: int,
        handles_pointer: int,
    ) -> int:
        service = self.services_by_handle.get(service_handle)
        if (
            service is None
            or not metadata_pointer
            or not attribute_pointer
            or not handles_pointer
        ):
            return NRF_ERROR_INVALID_PARAM

        properties = self._read_u8(metadata_pointer)
        uuid_pointer = self._read_u32(attribute_pointer)
        attr_metadata_pointer = self._read_u32(attribute_pointer + 4)
        if not uuid_pointer or not attr_metadata_pointer:
            return NRF_ERROR_INVALID_PARAM
        uuid, uuid16, uuid_type = self._read_ble_uuid(uuid_pointer)
        init_length = self._read_u16(attribute_pointer + 8)
        init_offset = self._read_u16(attribute_pointer + 10)
        max_length = self._read_u16(attribute_pointer + 12)
        value_pointer = self._read_u32(attribute_pointer + 16)
        if (
            max_length > _MAX_ATTRIBUTE_LENGTH
            or init_offset + init_length > max_length
            or (init_length and not value_pointer)
        ):
            return NRF_ERROR_INVALID_PARAM
        initial_value = b"\x00" * init_offset
        if init_length:
            initial_value += bytes(self.ql.mem.read(value_pointer, init_length))

        read_permission = self._read_u8(attr_metadata_pointer)
        write_permission = self._read_u8(attr_metadata_pointer + 1)
        attr_flags = self._read_u8(attr_metadata_pointer + 2)
        readable = bool(properties & 0x02) and read_permission != 0
        writable = bool(properties & 0x0C) and write_permission != 0
        read_authorized = bool(attr_flags & 0x08)

        self._allocate_handle()  # characteristic declaration
        value_handle = self._allocate_handle()
        cccd_handle = _BLE_GATT_HANDLE_INVALID
        if properties & 0x30:
            cccd_handle = self._allocate_handle()
        self.ql.mem.write(
            handles_pointer,
            struct.pack(
                "<4H",
                value_handle,
                _BLE_GATT_HANDLE_INVALID,
                cccd_handle,
                _BLE_GATT_HANDLE_INVALID,
            ),
        )
        service.characteristics.append(
            FirmwareGattCharacteristic(
                uuid=uuid,
                uuid16=uuid16,
                uuid_type=uuid_type,
                firmware_value_handle=value_handle,
                properties=properties,
                max_length=max_length,
                initial_value=initial_value,
                readable=readable,
                writable=writable,
                read_authorized=read_authorized,
            )
        )
        return NRF_SUCCESS

    def _read_ble_uuid(self, pointer: int) -> tuple[str, int, int]:
        uuid16 = self._read_u16(pointer)
        uuid_type = self._read_u8(pointer + 2)
        if uuid_type == _BLE_UUID_TYPE_BLE:
            return f"{uuid16:04x}", uuid16, uuid_type
        try:
            base = bytearray(self.vendor_uuids[uuid_type])
        except KeyError as exc:
            raise ValueError(
                f"firmware used unregistered vendor UUID type {uuid_type}"
            ) from exc
        base[12] = uuid16 & 0xFF
        base[13] = uuid16 >> 8
        return str(UUID(bytes=bytes(reversed(base)))), uuid16, uuid_type

    def _allocate_handle(self) -> int:
        handle = self.next_attribute_handle
        if handle >= 0xFFFF:
            raise ValueError("firmware exhausted GATT handles")
        self.next_attribute_handle += 1
        return handle

    def _read_u8(self, address: int) -> int:
        return self.ql.mem.read(address, 1)[0]

    def _read_u16(self, address: int) -> int:
        return struct.unpack("<H", bytes(self.ql.mem.read(address, 2)))[0]

    def _read_u32(self, address: int) -> int:
        return struct.unpack("<I", bytes(self.ql.mem.read(address, 4)))[0]


class QilingRuntime:
    """Execute an uploaded Cortex-M application with GPIO and S130 GATT only.

    The flag is never mapped in flash or SRAM by the host. It is streamed from
    ``P0.IN`` when guest instructions read that MMIO register. To expose data,
    the guest must register its own readable characteristic through S130; no
    UART capture or host-provided console service exists.
    """

    def __init__(
        self,
        gpio_secret: bytes,
        *,
        flash_size: int = 0x0008_0000,
        sram_base: int = 0x2000_0000,
        sram_size: int = 0x0001_0000,
        instruction_budget: int = 5_000,
    ) -> None:
        if not gpio_secret:
            raise ValueError("gpio_secret must not be empty")
        if instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")
        self.gpio_secret = gpio_secret
        self.flash_size = flash_size
        self.sram_base = sram_base
        self.sram_size = sram_size
        self.instruction_budget = instruction_budget
        self.last_result: ExecutionResult | None = None

    def run_application(self, image: bytes, application_base: int) -> ExecutionResult:
        try:
            from qiling import Qiling
            from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        except ModuleNotFoundError as exc:
            raise QilingUnavailable(
                "Qiling is optional; install the project with the 'emulator' extra"
            ) from exc

        if len(image) < 8:
            raise ValueError("application image has no vector table")
        initial_sp, reset_handler = struct.unpack_from("<II", image)
        gpio = _SecretGpioP0(self.gpio_secret)
        fault: str | None = None

        with tempfile.NamedTemporaryFile(suffix=".bin") as bootstrap:
            bootstrap.write(struct.pack("<II", self.sram_base + self.sram_size, 1))
            bootstrap.flush()
            env = {
                "FLASH": {"base": 0x0000_0000, "size": self.flash_size, "type": "memory"},
                "SRAM": {"base": self.sram_base, "size": self.sram_size, "type": "memory"},
            }
            ql = Qiling(
                [bootstrap.name, 0],
                archtype=QL_ARCH.CORTEX_M,
                ostype=QL_OS.MCU,
                env=env,
                verbose=QL_VERBOSE.OFF,
            )
            ql.mem.map_mmio(GPIO_P0_BASE, 0x1000, gpio, "[GPIO P0]")
            ql.mem.write(application_base, image)

            # Raw binaries have no symbols. Replace only the three supported
            # S130 Thumb SVC opcodes with NOPs, then emulate their ABI from the
            # code hook. This also avoids Qiling dispatching SVC into an NVIC.
            svc_addresses = self._find_svc_instructions(image, application_base)
            for address in svc_addresses:
                ql.mem.write(address, b"\x00\xbf")
            softdevice = _ApplicationSoftDevice(ql, svc_addresses)
            ql.hook_code(softdevice.on_code)

            ql.arch.regs.msp = initial_sp
            ql.arch.regs.pc = reset_handler
            try:
                ql.run(begin=reset_handler, count=self.instruction_budget)
            except Exception as exc:  # Bad firmware must not kill the service process.
                fault = f"{type(exc).__name__}: {exc}"

        self.last_result = ExecutionResult(
            gatt_services=softdevice.gatt_services,
            svc_calls=tuple(softdevice.svc_calls),
            gpio_reads=gpio.reads,
            initial_sp=initial_sp,
            reset_handler=reset_handler,
            fault=fault,
        )
        return self.last_result

    @staticmethod
    def _find_svc_instructions(image: bytes, application_base: int) -> dict[int, int]:
        return {
            application_base + offset: image[offset]
            for offset in range(0, len(image) - 1, 2)
            if image[offset + 1] == 0xDF and image[offset] in _SUPPORTED_SVCS
        }
