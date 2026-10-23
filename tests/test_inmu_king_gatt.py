from __future__ import annotations

import asyncio
import importlib.util
import unittest

from yaju_os.inmu_king_art import INMU_KING_DANCE_FRAMES
from yaju_os.maintenance_runtime import MaintenanceFirmwareRuntime
from yaju_os.gatt_ids import (
    INMU_KING_FRAME_UUID,
    INMU_KING_SERVICE_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_INFO_UUID,
    MAINTENANCE_SERVICE_UUID,
)

MAINTENANCE_REFERENCE_ELF = MaintenanceFirmwareRuntime.repository_board_runtime()


@unittest.skipUnless(
    importlib.util.find_spec("bumble") is not None
    and importlib.util.find_spec("qiling") is not None
    and MAINTENANCE_REFERENCE_ELF.exists(),
    "Bumble, Qiling, or the built maintenance application ELF is unavailable",
)
class InmuKingGattTests(unittest.IsolatedAsyncioTestCase):
    """Real ATT client/server exchanges over Bumble's in-process HCI link."""

    async def asyncSetUp(self) -> None:
        from bumble.controller import Controller
        from bumble.device import Device
        from bumble.gatt import Characteristic, CharacteristicValue, Service
        from bumble.hci import Address
        from bumble.link import LocalLink
        from yaju_os.s130_gatt import S130GattServer

        asyncio.get_running_loop().slow_callback_duration = 1.0
        link = LocalLink()
        self.devices = []
        for index in range(2):
            address = Address(f"F0:F1:F2:F3:F4:{index:02X}")
            controller = Controller(f"controller-{index}", link=link)
            self.devices.append(
                Device.with_hci(f"device-{index}", address, controller, controller)
            )
        self.target, self.client = self.devices
        self.runtime = MaintenanceFirmwareRuntime(MAINTENANCE_REFERENCE_ELF)
        self.runtime.boot()
        self.writes = []
        self.control = Characteristic(
            MAINTENANCE_CONTROL_UUID,
            Characteristic.Properties.WRITE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=lambda _connection, value: self.writes.append(value)),
        )
        self.info = Characteristic(
            MAINTENANCE_INFO_UUID,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            b"FN2\x01",
        )
        self.target.add_service(
            Service(MAINTENANCE_SERVICE_UUID, [self.control, self.info])
        )
        original_handles = (self.control.handle, self.info.handle)
        self.server = S130GattServer.install(self.target, self.runtime)
        self.assertEqual(original_handles, (self.control.handle, self.info.handle))
        self.handle = self.server.characteristic_by_uuid(INMU_KING_FRAME_UUID).handle
        for device in self.devices:
            await device.power_on()
        self.peer = await self._connect(self.client)

    async def asyncTearDown(self) -> None:
        for connection in list(self.client.connections.values()):
            await self._disconnect(connection)
        for device in reversed(self.devices):
            await device.power_off()
        self.runtime.close()

    async def _connect(self, client):
        from bumble.device import Peer

        await self.target.start_advertising()
        connection = await client.connect(self.target.random_address, timeout=2)
        target_connection = next(
            candidate
            for candidate in self.target.connections.values()
            if candidate.peer_address == connection.self_address
        )
        self.server.connect_connection(target_connection, int(target_connection.handle))
        return Peer(connection)

    async def _disconnect(self, connection) -> None:
        # HCI disconnection completion reaches the central before the target.
        # Wait for both sides before inspecting server cleanup or powering off.
        target_connection = next(
            candidate
            for candidate in self.target.connections.values()
            if candidate.peer_address == connection.self_address
        )
        disconnected = asyncio.Event()
        target_connection.once(
            target_connection.EVENT_DISCONNECTION, lambda *_args: disconnected.set()
        )
        await connection.disconnect()
        await asyncio.wait_for(disconnected.wait(), timeout=2)

    async def test_default_mtu_long_reads_play_full_loop_and_wrap(self) -> None:
        from bumble.core import UUID
        from bumble.gatt import Characteristic

        self.assertEqual(self.peer.connection.att_mtu, 23)
        services = await self.peer.discover_service(UUID(INMU_KING_SERVICE_UUID))
        self.assertEqual(len(services), 1)
        characteristics = await self.peer.discover_characteristics(service=services[0])
        self.assertEqual(len(characteristics), 1)
        frame = characteristics[0]
        self.assertEqual(frame.uuid, UUID(INMU_KING_FRAME_UUID))
        self.assertEqual(frame.properties, Characteristic.Properties.READ)
        self.assertEqual(await self.peer.discover_descriptors(characteristic=frame), [])

        # Read By Type is a preview, not a playback tick; at MTU 23 it truncates.
        for _ in range(4):
            self.assertEqual(
                await self.peer.read_characteristics_by_uuid(UUID(INMU_KING_FRAME_UUID)),
                [INMU_KING_DANCE_FRAMES[0][:19]],
            )
        for expected in INMU_KING_DANCE_FRAMES + INMU_KING_DANCE_FRAMES[:8]:
            self.assertEqual(await self.peer.read_value(frame), expected)

    async def test_negotiated_mtus_and_exact_chunk_boundaries(self) -> None:
        # 26 requires a final empty blob (125 / 25); 126 provokes the client's
        # extra blob probe; 185 fits the entire frame in a single Read Response.
        for mtu in (26, 126, 185):
            with self.subTest(mtu=mtu):
                await self._disconnect(self.peer.connection)
                self.peer = await self._connect(self.client)
                self.assertEqual(await self.peer.request_mtu(mtu), mtu)
                for expected in INMU_KING_DANCE_FRAMES[:8]:
                    self.assertEqual(await self.peer.read_value(self.handle), expected)

    async def test_blob_retries_offsets_and_other_reads_keep_the_snapshot(self) -> None:
        from bumble import att

        async def blob(offset):
            return await self.peer.gatt_client.send_request(
                att.ATT_Read_Blob_Request(
                    attribute_handle=self.handle, value_offset=offset
                )
            )

        # A blob before the first Read Request previews frame zero, not a tick.
        self.assertEqual(
            (await blob(22)).part_attribute_value, INMU_KING_DANCE_FRAMES[0][22:44]
        )
        for expected in INMU_KING_DANCE_FRAMES[:3]:
            self.assertEqual(await self.peer.read_value(self.handle), expected)
        expected = INMU_KING_DANCE_FRAMES[3]
        initial = await self.peer.gatt_client.send_request(
            att.ATT_Read_Request(attribute_handle=self.handle)
        )
        self.assertEqual(initial.attribute_value, expected[:22])
        for offset in (0, 22, 22, 110, 125):
            self.assertEqual(
                (await blob(offset)).part_attribute_value, expected[offset : offset + 22]
            )
        invalid = await blob(126)
        self.assertEqual(invalid.error_code, att.ATT_INVALID_OFFSET_ERROR)
        self.assertEqual(invalid.attribute_handle_in_error, self.handle)
        self.assertEqual(await self.peer.read_value(self.info.handle), b"FN2\x01")
        self.assertEqual((await blob(22)).part_attribute_value, expected[22:44])
        self.assertEqual(await self.peer.read_value(self.handle), INMU_KING_DANCE_FRAMES[4])

    async def test_writes_are_rejected_without_mutating_or_advancing(self) -> None:
        from bumble import att

        for request in (
            att.ATT_Write_Request(attribute_handle=self.handle, attribute_value=b"bad"),
            att.ATT_Prepare_Write_Request(
                attribute_handle=self.handle, value_offset=0, part_attribute_value=b"bad"
            ),
        ):
            response = await self.peer.gatt_client.send_request(request)
            self.assertEqual(response.error_code, att.ATT_WRITE_NOT_PERMITTED_ERROR)
        self.assertFalse(self.server.prepared_writes)
        await self.peer.write_value(self.handle, b"bad", with_response=False)
        for expected in INMU_KING_DANCE_FRAMES[:8]:
            self.assertEqual(await self.peer.read_value(self.handle), expected)
        # The existing maintenance write still reaches its original handler.
        await self.peer.write_value(self.control.handle, b"opaque", with_response=True)
        self.assertEqual(self.writes, [b"opaque"])

    async def test_reconnect_rewinds_firmware_cursor(self) -> None:
        for expected in INMU_KING_DANCE_FRAMES[:8]:
            self.assertEqual(await self.peer.read_value(self.handle), expected)
        await self._disconnect(self.peer.connection)
        self.assertEqual(self.server._snapshots, {})
        self.peer = await self._connect(self.client)
        self.assertEqual(await self.peer.read_value(self.handle), INMU_KING_DANCE_FRAMES[0])


if __name__ == "__main__":
    unittest.main()
