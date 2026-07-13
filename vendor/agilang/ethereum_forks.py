"""Ethereum execution fork ordering and opcode activation rules."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

FORKS = ("frontier", "homestead", "byzantium", "constantinople", "istanbul", "berlin", "london", "paris", "shanghai", "cancun", "prague")

@dataclass(frozen=True)
class ForkSchedule:
    activations: Mapping[str, int]
    by_timestamp: bool = False

    def at(self, *, block_number: int = 0, timestamp: int = 0) -> str:
        point = int(timestamp if self.by_timestamp else block_number)
        active = "frontier"
        for fork in FORKS:
            if int(self.activations.get(fork, 2**63 - 1)) <= point:
                active = fork
        return active

def fork_at_least(current: str, required: str) -> bool:
    return FORKS.index(str(current).lower()) >= FORKS.index(str(required).lower())

OPCODE_FORK = {
    0x3D: "byzantium", 0x3E: "byzantium", 0xFA: "byzantium", 0xFD: "byzantium",
    0x1B: "constantinople", 0x1C: "constantinople", 0x1D: "constantinople", 0x3F: "constantinople", 0xF5: "constantinople",
    0x46: "istanbul", 0x47: "istanbul", 0x48: "london", 0x5F: "shanghai",
    0x49: "cancun", 0x4A: "cancun",
}
