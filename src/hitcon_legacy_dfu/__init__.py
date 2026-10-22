"""Nordic legacy DFU challenge primitives."""

from .board_runtime import BoardRuntimeArtifact, BoardRuntimePhase
from .bootloader import BootloaderConfig, LegacyDfuBootloader
from .bridge import LegacyDfuGattBridge
from .client import LegacyDfuClient
from .nrf51_sdk11_runtime import (
    Nrf51Sdk11BootloaderRuntime,
    Nrf51Sdk11DfuEventResult,
    Nrf51Sdk11DfuHandles,
)
from .maintenance_runtime import (
    FirmwareGattCharacteristic,
    FirmwareGattReadReply,
    FirmwareGattService,
    MaintenanceFirmwareRuntime,
)
from .qiling_rootcanal import LayeredNrf51BumblePeripheral, Nrf51Sdk11BumblePeripheral
from .session_host import LegacyDfuSessionHost, SessionHostConfig
from .protocol import (
    CONTROL_POINT_UUID,
    INMU_KING_FRAME_UUID,
    INMU_KING_SERVICE_UUID,
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
    "BoardRuntimeArtifact",
    "BoardRuntimePhase",
    "BootloaderConfig",
    "CONTROL_POINT_UUID",
    "DfuImageType",
    "DfuOpcode",
    "DfuResponse",
    "DfuState",
    "FirmwareGattCharacteristic",
    "FirmwareGattReadReply",
    "FirmwareGattService",
    "INMU_KING_FRAME_UUID",
    "INMU_KING_SERVICE_UUID",
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
