import ipaddress
import os
import random
import struct
import sys
import unittest
from unittest.mock import patch
import unittest.mock

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "scripts")))

from tonearm_lib import sood


def tlv(key, value):
    kb, vb = key.encode(), value.encode()
    return bytes([len(kb)]) + kb + struct.pack(">H", len(vb)) + vb


class TestSoodFraming(unittest.TestCase):
    def test_query_is_a_well_formed_sood_frame(self):
        q = sood.build_query()
        self.assertTrue(q.startswith(b"SOOD"))
        self.assertEqual(q[4], 2)          # version
        self.assertEqual(q[5:6], b"Q")     # query
        self.assertIn(sood.SERVICE_ID.encode(), q)

    def test_parse_round_trips_a_response(self):
        body = tlv("name", "yavin") + tlv("http_port", "9330")
        buf = b"SOOD" + b"\x02" + b"R" + body
        self.assertEqual(sood.parse(buf), {"name": "yavin", "http_port": "9330"})

    def test_parse_rejects_a_foreign_frame(self):
        self.assertIsNone(sood.parse(b"NOPE\x02R"))
        self.assertIsNone(sood.parse(b""))

    def test_parse_survives_a_truncated_frame(self):
        # A short read must not raise: Service-side, any throw is indistinguish-
        # able from "no core found" and would discard a real response.
        buf = b"SOOD" + b"\x02" + b"R" + b"\x04name\x00"
        self.assertIsNotNone(sood.parse(buf))

    def test_parse_ignores_trailing_garbage_after_a_valid_pair(self):
        buf = b"SOOD" + b"\x02" + b"R" + tlv("name", "yavin") + b"\xff"
        self.assertEqual(sood.parse(buf).get("name"), "yavin")


class TestOversizedFieldsAreRefused(unittest.TestCase):
    """A SOOD response is unauthenticated UDP that anyone on the LAN can send,
    and its values are both displayed (the Core name reaches the bar and MPRIS)
    and persisted (config.json, via core.RoonSession._apply). The wire format
    allows 64KB per value; nothing a real Core sends comes close.
    """

    def test_an_oversized_value_is_dropped_and_the_rest_of_the_frame_survives(self):
        body = (tlv("name", "y" * (sood.MAX_SOOD_FIELD + 1))
                + tlv("http_port", "9330"))
        parsed = sood.parse(b"SOOD" + b"\x02" + b"R" + body)
        self.assertNotIn("name", parsed)
        # Refusing the whole response would let one absurd field hide an
        # otherwise healthy Core.
        self.assertEqual(parsed["http_port"], "9330")

    def test_a_field_at_the_limit_is_kept(self):
        body = tlv("name", "y" * sood.MAX_SOOD_FIELD)
        parsed = sood.parse(b"SOOD" + b"\x02" + b"R" + body)
        self.assertEqual(len(parsed["name"]), sood.MAX_SOOD_FIELD)

    def test_a_core_with_no_usable_name_falls_back_to_its_address(self):
        # to_core's fallback, reached once parse drops the name -- and the
        # address is never a match for a stored Core name, so an adoption
        # decision made on it fails safe (core._relocated_core).
        core = sood.to_core("192.168.50.9", {"http_port": "9330"}, via="multicast")
        self.assertEqual(core["name"], "192.168.50.9")


class TestScanIsOptional(unittest.TestCase):
    """`discover(scan=False)` is the multicast half only.

    The sweep is 254 TCP connects on a /24 (measured). Fair once, on first run,
    with a human waiting; far too high for the relocation check, which reruns
    on every restart for as long as a Core stays switched off.
    """

    def test_scan_false_never_touches_the_lan(self):
        with unittest.mock.patch.object(sood, "_local_networks") as nets, \
             unittest.mock.patch.object(sood, "_port_open") as port_open, \
             unittest.mock.patch.object(sood, "_probe_unicast") as probe:
            self.assertEqual(sood.discover(timeout=0, scan=False), [])
        nets.assert_not_called()
        port_open.assert_not_called()
        probe.assert_not_called()

    def test_the_default_still_scans(self):
        with unittest.mock.patch.object(sood, "_local_networks",
                                        return_value=[]) as nets:
            sood.discover(timeout=0)
        nets.assert_called()


class TestParseNeverRaises(unittest.TestCase):
    """`parse()` must never raise (see its docstring): Service-side, an
    exception is indistinguishable from "no Core found" and would discard a
    real response. These tests pin that property down so a future off-by-one
    in a bounds check fails this suite instead of shipping silently.
    """

    def test_parse_survives_every_truncation_of_a_valid_frame(self):
        body = (
            tlv("name", "yavin")
            + tlv("http_port", "9330")
            + tlv("unique_id", "96e11146-4bec-466e-afe9-e82a1d8f7b4d")
        )
        full = b"SOOD" + b"\x02" + b"R" + body
        for cut in range(len(full) + 1):
            try:
                sood.parse(full[:cut])
            except Exception as exc:
                self.fail(
                    f"parse() raised {exc!r} truncating a valid frame at "
                    f"offset {cut}/{len(full)}"
                )

    def test_parse_survives_seeded_random_fuzz(self):
        seed = 20260827
        rng = random.Random(seed)
        iterations = 4000

        def random_bytes(n):
            return bytes(rng.randrange(256) for _ in range(n))

        for i in range(iterations):
            if rng.random() < 0.5:
                # Pure garbage, with and without the "SOOD" magic prefix.
                prefix = b"SOOD" if rng.random() < 0.5 else b""
                buf = prefix + random_bytes(rng.randint(0, 80))
            else:
                # A SOOD-prefixed frame with adversarial TLV length fields:
                # key/value lengths that may wildly exceed, or exactly
                # match, the bytes that actually follow them.
                parts = [b"SOOD", bytes([2]), b"R"]
                for _ in range(rng.randint(0, 4)):
                    klen = rng.randint(0, 255)
                    key = random_bytes(rng.randint(0, 12))
                    vlen = rng.randint(0, 65535)
                    val = random_bytes(rng.randint(0, 12))
                    parts += [bytes([klen]), key, struct.pack(">H", vlen), val]
                buf = b"".join(parts)
                if buf and rng.random() < 0.5:
                    buf = buf[: rng.randint(0, len(buf))]
                if rng.random() < 0.5:
                    buf += random_bytes(rng.randint(0, 12))

            try:
                sood.parse(buf)
            except Exception as exc:
                self.fail(
                    f"parse() raised {exc!r} at seed={seed} iteration={i} "
                    f"on buf={buf!r}"
                )


class TestCoreRecord(unittest.TestCase):
    def test_to_core_extracts_the_fields_we_use(self):
        # Deliberately NOT 9150/9330 (DEFAULT_TCP_PORT/DEFAULT_HTTP_PORT):
        # using the defaults here means a stub that always returns the
        # default -- skipping both string->int coercion and the actual
        # dict lookup -- would leave this green. Port selection is the
        # trickiest thing in this project (see CONTRIBUTING.md); this fixture
        # must actually exercise it.
        raw = {
            "name": "yavin", "tcp_port": "9151", "http_port": "9331",
            "unique_id": "96e11146", "display_version": "2.71 (build 1683)",
        }
        core = sood.to_core("192.168.50.118", raw, via="multicast")
        self.assertEqual(core["host"], "192.168.50.118")
        self.assertEqual(core["name"], "yavin")
        self.assertEqual(core["tcp_port"], 9151)
        self.assertEqual(core["http_port"], 9331)
        self.assertEqual(core["via"], "multicast")

    def test_to_core_defaults_ports_when_absent(self):
        core = sood.to_core("10.0.0.5", {"name": "x"}, via="scan")
        self.assertEqual(core["tcp_port"], 9150)
        self.assertEqual(core["http_port"], 9330)


class TestLocalNetworksStayPrivate(unittest.TestCase):
    """`_local_networks()` and the `_local_ipv4()` fallback must never hand
    `discover()` a /24 outside private address space -- see Important 3 of
    the final review. A network handing out globally-routable addresses
    (hotel, campus, bridged VM, VPS) must not get 254 unsolicited TCP
    connections from this daemon.
    """

    def test_local_networks_excludes_a_public_interface_address(self):
        # eth0 is a normal private LAN address; eth1 is a real, globally
        # routable address (Google's public DNS range) as an interface
        # could plausibly carry on a network that hands those out directly.
        # Only eth0's /24 must survive.
        addrs = {"eth0": "192.168.1.50", "eth1": "8.8.8.8"}
        with unittest.mock.patch.object(
            sood.socket, "if_nameindex", return_value=[(1, "eth0"), (2, "eth1")]
        ), unittest.mock.patch.object(
            sood, "_iface_ipv4", side_effect=lambda name: addrs[name]
        ):
            nets = sood._local_networks()
        self.assertEqual([str(n) for n in nets], ["192.168.1.0/24"])

    def test_local_networks_excludes_the_tailscale_cgnat_range(self):
        # Measured on the dev machine (see the module docstring): an exit
        # node's policy routes can make an interface-level trick land on a
        # 100.64.0.0/10 address. is_private structurally excludes that
        # whole range, independent of the interface-name ignore list.
        with unittest.mock.patch.object(
            sood.socket, "if_nameindex", return_value=[(1, "eth0")]
        ), unittest.mock.patch.object(
            sood, "_iface_ipv4", return_value="100.94.206.126"
        ):
            nets = sood._local_networks()
        self.assertEqual(nets, [])

    def test_local_ipv4_fallback_rejects_a_public_address(self):
        with unittest.mock.patch.object(
            sood, "_local_networks", return_value=[]
        ), unittest.mock.patch.object(
            sood, "_local_ipv4", return_value="8.8.8.8"
        ):
            # discover() with a zero listen timeout still goes through the
            # multicast phase (no replies expected here) and then the /24
            # fallback path this test targets; assert only that no scan
            # target reached _port_open by checking discover() returns []
            # rather than hanging on 254 real connect attempts.
            found = sood.discover(timeout=0)
        self.assertEqual(found, [])

    def test_local_ipv4_fallback_accepts_a_private_address(self):
        with unittest.mock.patch.object(
            sood, "_local_networks", return_value=[]
        ), unittest.mock.patch.object(
            sood, "_local_ipv4", return_value="192.168.50.5"
        ), unittest.mock.patch.object(
            sood, "_port_open", return_value=False
        ) as port_open:
            sood.discover(timeout=0)
        # _port_open is only reached at all if the fallback network passed
        # the private-space check and produced scan targets.
        self.assertTrue(port_open.called)


# --- hardening: marketplace security review 2026-09-01 -------------------
#
# "Discovery does not actually enforce the documented total-host cap across
# interfaces. ... enforce a strict deduplicated discovery budget."


class TestScanBudget(unittest.TestCase):
    """The /24 fallback must have a ceiling on how many hosts it touches.

    `hosts = [str(h) for net in nets for h in net.hosts()]` had no cap and no
    dedup: two aliased interfaces on one /24 produced 508 connect attempts
    against 254 machines, and N interfaces produced 254*N with no ceiling at
    all. What the docs described as a bounded scan was bounded only in which
    /24s qualified, never in how many hosts that came to.
    """

    def _nets(self, *cidrs):
        return [ipaddress.ip_network(c) for c in cidrs]

    def test_two_interfaces_on_one_subnet_scan_it_once(self):
        nets = self._nets("192.168.1.0/24", "192.168.1.0/24")
        targets = sood._scan_targets(nets)
        self.assertEqual(len(targets), 254)
        self.assertEqual(len(set(targets)), len(targets))

    def test_overlapping_networks_never_yield_a_host_twice(self):
        nets = self._nets("10.0.0.0/24", "10.0.0.128/25")
        targets = sood._scan_targets(nets)
        self.assertEqual(len(set(targets)), len(targets))

    def test_the_budget_caps_the_total_across_interfaces(self):
        # Four distinct /24s is 1016 hosts. The budget is a total, not a
        # per-interface allowance.
        nets = self._nets("10.1.0.0/24", "10.2.0.0/24",
                          "10.3.0.0/24", "10.4.0.0/24")
        targets = sood._scan_targets(nets, budget=512)
        self.assertEqual(len(targets), 512)

    def test_the_default_budget_is_enforced(self):
        nets = self._nets(*["10.%d.0.0/24" % n for n in range(1, 21)])
        self.assertLessEqual(len(sood._scan_targets(nets)),
                             sood.MAX_SCAN_HOSTS)

    def test_discover_probes_no_more_hosts_than_the_budget(self):
        # End to end: the ceiling has to hold on the path discover() takes,
        # not only in the helper.
        nets = [ipaddress.ip_network("10.%d.0.0/24" % n) for n in range(1, 21)]
        with unittest.mock.patch.object(
            sood, "_local_networks", return_value=nets
        ), unittest.mock.patch.object(
            sood, "_port_open", return_value=False
        ) as port_open:
            sood.discover(timeout=0)
        self.assertLessEqual(port_open.call_count, sood.MAX_SCAN_HOSTS)

    def test_local_networks_reports_an_aliased_subnet_once(self):
        addrs = {"eth0": "192.168.1.50", "eth0:1": "192.168.1.51"}
        with unittest.mock.patch.object(
            sood.socket, "if_nameindex",
            return_value=[(1, "eth0"), (2, "eth0:1")]
        ), unittest.mock.patch.object(
            sood, "_iface_ipv4", side_effect=lambda name: addrs[name]
        ):
            nets = sood._local_networks()
        self.assertEqual([str(n) for n in nets], ["192.168.1.0/24"])


if __name__ == "__main__":
    unittest.main()


def _tlv(key, value):
    k = key.encode(); v = value.encode()
    return bytes([len(k)]) + k + struct.pack(">H", len(v)) + v


def _reply(**fields):
    body = b"".join(_tlv(k, v) for k, v in fields.items())
    return b"SOOD" + b"\x02" + b"R" + body


class TestOnlyRepliesToOurQueryAreAccepted(unittest.TestCase):
    """#34: `parse` checked the magic and ignored everything else.

    A frame's type byte says whether it is a query or a reply, and the
    service_id says whose protocol it is. Neither was looked at, so our own
    broadcast query -- which every host on the segment receives -- parsed as
    a Core, as did any unrelated SOOD-shaped traffic.

    NOT gated on a transaction id, although the report suggested it. Measured
    against a live Core: a query carrying `_tid: abc123deadbeef` came back
    with `_tid: bf97ab4b-acbd-1a7d-92e0-ca03cced1dbd`. The Core sends its own
    id and does not echo ours, so requiring a match would reject every reply
    in existence and disable discovery altogether.
    """

    def test_a_reply_still_parses(self):
        self.assertEqual(
            sood.parse(_reply(service_id=sood.SERVICE_ID, name="yavin"))["name"],
            "yavin")

    def test_our_own_query_is_not_a_core(self):
        # The query goes to 239.255.90.90 and to the broadcast address, so
        # this machine receives its own frame.
        self.assertIsNone(sood.parse(sood.build_query()))

    def test_another_protocols_sood_frame_is_not_a_core(self):
        # Decoded as a frame, refused as a Core -- the split that keeps the
        # framing tests above about framing.
        self.assertFalse(sood.is_roon_reply(
            sood.parse(_reply(service_id="not-roons", name="x"))))

    def test_a_reply_with_no_service_id_is_not_a_core(self):
        self.assertFalse(sood.is_roon_reply(sood.parse(_reply(name="yavin"))))

    def test_a_roon_reply_is_accepted(self):
        self.assertTrue(sood.is_roon_reply(
            sood.parse(_reply(service_id=sood.SERVICE_ID, name="yavin"))))


class TestDiscoveryKeepsABoundedNumberOfCores(unittest.TestCase):
    """The receive loop kept one entry per distinct source address, uncapped.

    Source addresses are trivially spoofed on a LAN, so a flood of forged
    replies grew the dict for the whole receive window -- and `_describe_cores`
    then joined every one of them into a single log line. The sweep path has
    had `MAX_SCAN_HOSTS` all along; the multicast path had no counterpart.
    """

    def test_the_cap_is_enforced_and_announced(self):
        class Flood:
            def __init__(self): self.n = 0
            def settimeout(self, _t): pass
            def setsockopt(self, *_a): pass
            def bind(self, _a): pass
            def sendto(self, *_a): pass
            def close(self): pass
            def recvfrom(self, _n):
                self.n += 1
                return (_reply(service_id=sood.SERVICE_ID, name="c%d" % self.n),
                        ("10.0.0.%d" % (self.n % 250), 9003))

        with patch.object(sood.socket, "socket", lambda *a, **k: Flood()), \
             self.assertLogs(sood.LOG, level="WARNING") as logged:
            found = sood.discover(timeout=0.3, scan=False)
        self.assertLessEqual(len(found), sood.MAX_DISCOVERED_CORES)
        self.assertTrue(any("cores" in line.lower() for line in logged.output),
                        logged.output)
