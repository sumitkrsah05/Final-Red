"""Asset inventory with deduplication and merge.

Multiple tools observe the same host/service/endpoint from different angles
(nmap sees ports, httpx sees HTTP tech, whatweb fingerprints, gobuster finds
paths). The inventory merges records on ``(type, address, port, protocol)`` and
consolidates their technology fingerprints so the downstream pipeline sees one
normalised surface, not four overlapping views.
"""

from __future__ import annotations

from typing import Iterable

from safeguard.tools.schema import Asset


class AssetInventory:
    def __init__(self) -> None:
        self._assets: dict[tuple, Asset] = {}

    def add(self, asset: Asset) -> Asset:
        key = asset.merge_key()
        existing = self._assets.get(key)
        if existing is None:
            self._assets[key] = asset
            return asset
        self._merge_into(existing, asset)
        return existing

    def add_all(self, assets: Iterable[Asset]) -> None:
        for a in assets:
            self.add(a)

    @staticmethod
    def _merge_into(target: Asset, other: Asset) -> None:
        # Prefer the more specific service/protocol when one side is missing.
        target.service = target.service or other.service
        target.protocol = target.protocol or other.protocol
        target.in_scope = target.in_scope and other.in_scope
        _deep_merge(target.tech, other.tech)

    def assets(self) -> list[Asset]:
        return list(self._assets.values())

    def by_type(self, asset_type) -> list[Asset]:
        t = getattr(asset_type, "value", asset_type)
        return [a for a in self._assets.values() if a.asset_type.value == t]

    def hosts(self) -> list[str]:
        return sorted({a.address for a in self._assets.values()})

    def __len__(self) -> int:
        return len(self._assets)


def _deep_merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if k not in dst or dst[k] in (None, "", [], {}):
            dst[k] = v
        elif isinstance(dst[k], dict) and isinstance(v, dict):
            _deep_merge(dst[k], v)
        elif isinstance(dst[k], list) and isinstance(v, list):
            for item in v:
                if item not in dst[k]:
                    dst[k].append(item)
