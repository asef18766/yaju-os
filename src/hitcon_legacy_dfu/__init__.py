"""Nordic legacy DFU challenge primitives."""

from .bootloader import BootloaderConfig, LegacyDfuBootloader
from .bridge import LegacyDfuGattBridge
from .client import LegacyDfuClient
from .nrf51_sdk11_runtime import (
    Nrf51Sdk11BootloaderRuntime,
    Nrf51Sdk11DfuEventResult,
    Nrf51Sdk11DfuHandles,
)
from .maintenance_runtime import MaintenanceFirmwareRuntime
from .qiling_rootcanal import LayeredNrf51BumblePeripheral, Nrf51Sdk11BumblePeripheral
from .session_host import LegacyDfuSessionHost, SessionHostConfig
from .protocol import (
    CONSOLE_OUTPUT_UUID,
    CONSOLE_SERVICE_UUID,
    CONTROL_POINT_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_INFO_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    SERVICE_UUID,
    STATUS_REPORT_UUID,
    DfuImageType,
    DfuOpcode,
    DfuResponse,
    DfuState,
)

__all__ = [
    "BootloaderConfig",
    "CONSOLE_OUTPUT_UUID",
    "CONSOLE_SERVICE_UUID",
    "CONTROL_POINT_UUID",
    "DfuImageType",
    "DfuOpcode",
    "DfuResponse",
    "DfuState",
    "LegacyDfuBootloader",
    "LegacyDfuClient",
    "LegacyDfuGattBridge",
    "LegacyDfuSessionHost",
    "LayeredNrf51BumblePeripheral",
    "MaintenanceFirmwareRuntime",
    "MAINTENANCE_CONTROL_UUID",
    "MAINTENANCE_INFO_UUID",
    "MAINTENANCE_SERVICE_UUID",
    "Nrf51Sdk11BootloaderRuntime",
    "Nrf51Sdk11BumblePeripheral",
    "Nrf51Sdk11DfuEventResult",
    "Nrf51Sdk11DfuHandles",
    "PACKET_UUID",
    "SERVICE_UUID",
    "SessionHostConfig",
    "STATUS_REPORT_UUID",
]
