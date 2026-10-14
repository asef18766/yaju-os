"""Qiling Cortex-M runner and secret GPIO peripheral for the challenge board."""

from __future__ import annotations

from dataclasses import dataclass
import struct
import tempfile

from .hardware import GPIO_P0_BASE, GPIO_P0_IN_OFFSET, UART0_BASE, UART0_TXD_OFFSET


class QilingUnavailable(RuntimeError):
    """The optional emulator dependency has not been installed."""


@dataclass(frozen=True)
class ExecutionResult:
    uart_output: bytes
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


class _Uart0Capture:
    """Minimal UART0 register model used solely to observe guest output."""

    def __init__(self) -> None:
        self.output = bytearray()

    def read(self, _ql: object, _offset: int, _size: int) -> int:
        return 0

    def write(self, _ql: object, offset: int, size: int, value: int) -> None:
        if offset == UART0_TXD_OFFSET:
            self.output.extend(value.to_bytes(size, "little"))


class QilingRuntime:
    """Execute an uploaded Cortex-M application with only the required peripherals.

    The flag is never mapped in flash or SRAM. It is held by the P0.IN MMIO
    model, which exposes consecutive bytes only when the guest reads that
    specific register.
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
        uart = _Uart0Capture()
        fault: str | None = None

        # Qiling's MCU loader initializes from vector table zero. A tiny harmless
        # bootstrap table lets us map the MCU, then we manually perform the
        # bootloader's application hand-off using the uploaded vector table.
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
            ql.mem.map_mmio(UART0_BASE, 0x1000, uart, "[UART0]")
            ql.mem.write(application_base, image)
            ql.arch.regs.msp = initial_sp
            ql.arch.regs.pc = reset_handler
            try:
                ql.run(begin=reset_handler, count=self.instruction_budget)
            except Exception as exc:  # Bad uploaded firmware must not kill the service process.
                fault = f"{type(exc).__name__}: {exc}"

        self.last_result = ExecutionResult(
            uart_output=bytes(uart.output),
            gpio_reads=gpio.reads,
            initial_sp=initial_sp,
            reset_handler=reset_handler,
            fault=fault,
        )
        return self.last_result
