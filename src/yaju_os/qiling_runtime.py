"""Qiling Cortex-M runner with secret GPIO and a narrow S130 GATT shim."""

from __future__ import annotations

from dataclasses import dataclass
import struct
import tempfile
from typing import Any

from .hardware import GPIO_P0_BASE, GPIO_P0_IN_OFFSET
from .s130_abi import (
    SVC_BLE_GATTS_CHARACTERISTIC_ADD as _SVC_BLE_GATTS_CHARACTERISTIC_ADD,
    SVC_BLE_GATTS_SERVICE_ADD as _SVC_BLE_GATTS_SERVICE_ADD,
    SVC_BLE_UUID_VS_ADD as _SVC_BLE_UUID_VS_ADD,
    FirmwareGattService,
    S130GattsRegistry,
)


_SUPPORTED_SVCS = {
    _SVC_BLE_UUID_VS_ADD,
    _SVC_BLE_GATTS_SERVICE_ADD,
    _SVC_BLE_GATTS_CHARACTERISTIC_ADD,
}


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


class _ApplicationSoftDevice:
    """Record the GATT table an uploaded raw image creates through S130 SVCs."""

    def __init__(self, ql: Any, svc_addresses: dict[int, int]) -> None:
        self.ql = ql
        self.svc_addresses = svc_addresses
        self.svc_calls: list[int] = []
        self.registry = S130GattsRegistry()
        self.registry.attach(ql.mem)

    @property
    def gatt_services(self) -> tuple[FirmwareGattService, ...]:
        return self.registry.services

    def on_code(self, ql: Any, address: int, _size: int) -> None:
        svc_number = self.svc_addresses.get(address)
        if svc_number is None:
            return
        self.svc_calls.append(svc_number)
        if svc_number == _SVC_BLE_UUID_VS_ADD:
            ql.arch.regs.r0 = self.registry.uuid_vs_add(
                ql.arch.regs.r0, ql.arch.regs.r1
            )
        elif svc_number == _SVC_BLE_GATTS_SERVICE_ADD:
            ql.arch.regs.r0 = self.registry.service_add(
                ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2
            )
        elif svc_number == _SVC_BLE_GATTS_CHARACTERISTIC_ADD:
            ql.arch.regs.r0 = self.registry.characteristic_add(
                ql.arch.regs.r0,
                ql.arch.regs.r1,
                ql.arch.regs.r2,
                ql.arch.regs.r3,
            )


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
