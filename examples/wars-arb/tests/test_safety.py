"""Halt on one-sided arbs, failed bridge transfers, and untrusted status responses."""

from concurrent.futures import Future
from types import SimpleNamespace

import pytest

from wars_arb import inventory, lifi, ripio_bridge
from wars_arb.chain import Sent
from wars_arb.inventory import InFlight, State
from wars_arb.main import Bot


def done(value=None, exc=None):
    f = Future()
    f.set_exception(exc) if exc else f.set_result(value)
    return f


def bot(tmp_path):
    b = Bot.__new__(Bot)  # no device or RPC
    b.state = State(tmp_path / "state.json")
    return b


def test_both_legs_confirmed_no_halt(tmp_path):
    b = bot(tmp_path)
    b.check_legs([done(Sent("base", "buy", "0x1", True)), done(Sent("celo", "sell", "0x2", True))])
    assert b.state.halt is None


@pytest.mark.parametrize("second", [done(Sent("celo", "sell", "0x2", False)),
                                    done(exc=RuntimeError("receipt timeout"))], ids=["reverted", "raised"])
def test_one_sided_arb_halts_and_persists(tmp_path, second):
    b = bot(tmp_path)
    b.check_legs([done(Sent("base", "buy", "0x1", True)), second])
    assert b.state.halt and b.state.halt["reason"] == "arb leg did not confirm"
    assert State(tmp_path / "state.json").halt == b.state.halt  # survives a restart
    b.state.clear_halt()
    assert State(tmp_path / "state.json").halt is None


def test_halted_bot_does_nothing(tmp_path):
    b = bot(tmp_path)
    b.state.set_halt("test")
    b.cfg = SimpleNamespace(strategy=None)
    b.inventory = lambda: pytest.fail("a halted bot must not even read balances")
    b.step()


def flight(tx="0xaa"):
    return InFlight("ripio", "wARS", "base", "celo", 10**21, tx, 8453, 0.0)


def test_failed_transfer_is_kept_and_halts(tmp_path, monkeypatch):
    st = State(tmp_path / "state.json")
    st.add(flight())
    monkeypatch.setattr(inventory.ripio_bridge, "status", lambda tx, cid: {"status": "FAILED"})
    st.refresh()
    assert st.inflight == [] and [f.tx for f in st.failed] == ["0xaa"]
    st2 = State(tmp_path / "state.json")
    assert st2.halt and [f.tx for f in st2.failed] == ["0xaa"]


def test_completed_transfer_dropped(tmp_path, monkeypatch):
    st = State(tmp_path / "state.json")
    st.add(flight())
    monkeypatch.setattr(inventory.ripio_bridge, "status", lambda tx, cid: {"status": "COMPLETED"})
    st.refresh()
    assert st.inflight == [] and st.failed == [] and st.halt is None


def test_ripio_status_must_name_the_requested_transfer():
    ok = {"source_tx_hash": "0xAA", "source_chain_id": 8453, "status": "COMPLETED"}
    ripio_bridge.check_operation(ok, "0xaa", 8453)
    with pytest.raises(RuntimeError, match="another tx"):
        ripio_bridge.check_operation({**ok, "source_tx_hash": "0xbb"}, "0xaa", 8453)
    with pytest.raises(RuntimeError, match="chain"):
        ripio_bridge.check_operation({**ok, "source_chain_id": 42220}, "0xaa", 8453)
    with pytest.raises(RuntimeError):
        ripio_bridge.check_operation({"status": "COMPLETED"}, "0xaa", 8453)


def test_mismatched_status_keeps_transfer_in_flight(tmp_path, monkeypatch):
    st = State(tmp_path / "state.json")
    st.add(flight())

    def lying(tx, cid):
        ripio_bridge.check_operation({"source_tx_hash": "0xbb", "source_chain_id": cid, "status": "COMPLETED"}, tx, cid)
    monkeypatch.setattr(inventory.ripio_bridge, "status", lying)
    st.refresh()
    assert [f.tx for f in st.inflight] == ["0xaa"]


class FakeCelo:
    """Records sends; the LI.FI bridge tx reverts."""
    live = True
    address = "0x1111111111111111111111111111111111111111"

    def __init__(self):
        self.allowance, self.sent = 0, []

    def erc20_allowance(self, token, spender):
        return self.allowance

    def send(self, to, data, label, **kw):
        self.sent.append(label)
        if "approve" in label:
            self.allowance = int(data[-64:], 16)
            return Sent("celo", label, "0x1", True)
        return Sent("celo", label, "0x2", False)  # bridge reverted: transferFrom rolled back


def test_lifi_revert_revokes_allowance(monkeypatch):
    monkeypatch.setattr(lifi, "quote_celo_to_base", lambda a, addr: {"transactionRequest": {"data": "0x"}})
    monkeypatch.setattr(lifi, "check_quote", lambda q, addr, a: (a, 10.0))
    celo = FakeCelo()
    with pytest.raises(RuntimeError, match="reverted"):
        lifi.transfer_celo_to_base(celo, 500_000_000, 100)
    assert celo.allowance == 0 and len(celo.sent) == 3
