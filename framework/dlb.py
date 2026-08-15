"""Orchestration and chip-assertion helpers for standalone DLB (Dynamic Load Balancing) ECMP.

**Why ASIC_DB injection instead of the product CLI**: SONiC exposes no DLB
configuration entry point -- orchagent never creates DYNAMIC_*/DLB_* type
NEXT_HOP_GROUPs, and CONFIG_DB has no model for them. A DLB group can only be
produced at the SAI layer via `create_next_hop_group(type=DLB_*)`. The only way
to drive this code path on real hardware is to push the object to syncd per the
sairedis ConsumerTable protocol (an entry point exactly equivalent to what the
upstream orch emits). This module uses injection **only** to create/remove the
DLB objects under test; all device configuration (PFC, interfaces, IP, routes,
neighbours) still goes through the product CLI / kernel path.

Injection discipline (do not remove):
 1) Only reference OIDs that **already exist**: syncd's translateVidToRid throws
    on an unknown VID -> the process exits -> orchagent exits with it;
 2) Only send remove for objects that were **created successfully** (have a RID
    in VIDTORID), for the same reason;
 3) An empty OID string makes sai_deserialize_object_id throw "invalid oid",
    which likewise kills syncd;
 4) Test-created VIDs use the reserved index range 0xc0xx to stay clear of
    orchagent's VID allocation;
 5) **Injection produces no sairedis.rec response record** -- the only valid
    criteria are "did a RID appear" + "did the chip table change"; you cannot
    read the last status from sairedis.rec;
 6) **The response produced by an injection must be reaped**: syncd pushes a
    response onto `GETRESPONSE_KEY_VALUE_OP_QUEUE` after processing every
    operation. In async mode orchagent normally does not read it, but during
    bulk route/neighbour operations it waits for a response -- and picks up the
    one **I injected** at the head of the queue (0 statuses), yielding
    `waitForBulkResponse: wrong number of statuses, got 0, expected 1` -> throws
    -> orchagent crashes -> swss restarts. So after every injection the extra
    response must be pulled off. Wait for the ASIC queue to go quiet before
    injecting, then reap exactly by the LLEN delta -- never blind-delete (a blind
    delete would eat the response orchagent itself is waiting on).

Chip tables (LTSW, `bsh -c "lt ..."`):
  ECMP_OVERLAY   L1 group: MAX_PATHS=1, its only member is an L2 group (ECMP_UNDERLAY_ID[0])
  ECMP_UNDERLAY  L2 group: the group that actually carries the DLB attributes
  DLB_ECMP       DLB engine instance: NUM_PATHS / FLOW_SET_SIZE / INACTIVITY_TIME / PFC filter mode
  DLB_ECMP_PORT_CONTROL  per-member-port forced state (OVERRIDE=1 means FORCE_DOWN, the root cause of ingress drops)
  DLB_QUALITY_MAP        (loading, tm_queue_size) -> quality quantization table
  TM_PFC_AWARE_DLB       the 4 unicast queues the DLB engine watches
"""
import json
import re
import shlex
import time

from . import log

_log = log.get("dlb")

ASIC_Q = "ASIC_STATE_KEY_VALUE_OP_QUEUE"     # syncd's inbound operation queue
RESP_Q = "GETRESPONSE_KEY_VALUE_OP_QUEUE"    # syncd's response queue (see header note #6)

# VID encoding for SAI_OBJECT_TYPE_*: type is in bits 40-47, low bits are the object index.
_VID_NHG = 0x0500000000C000        # SAI_OBJECT_TYPE_NEXT_HOP_GROUP(5)
_VID_MBR = 0x1F00000000C100        # SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER(31)

# Each Dlb instance (= each test case) gets its own non-overlapping VID range, so that
# an object a previous case failed to clean up cannot turn the next case's create into
# a "set on an existing object" that silently hides the problem.
_VID_SEQ = [0]

# SAI_NEXT_HOP_GROUP_ATTR_TYPE values (extension range base 0x20000000)
TYPE_ECMP = 1
TYPE_RESILIENT = 536870912
TYPE_DLB_ELIGIBLE = 536870913
TYPE_DLB_FIXED = 536870914
TYPE_DLB_SPRAY = 536870915

DLB_TYPES = (("eligible", TYPE_DLB_ELIGIBLE),
             ("fixed", TYPE_DLB_FIXED),
             ("spray", TYPE_DLB_SPRAY))

_FIELD_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\[[^\]]*\])?=(.*)$")
_HEXDEC_RE = re.compile(r"^0x[0-9a-fA-F]+\((-?\d+)\)$")


def _val(raw):
    raw = raw.strip()
    m = _HEXDEC_RE.match(raw)
    if m:
        return int(m.group(1))
    if raw.lstrip("-").isdigit():
        return int(raw)
    if raw.startswith("0x"):
        try:
            return int(raw, 16)
        except ValueError:
            return raw
    return raw


def parse_entries(out):
    """Parse `lt` output into [{field: value}, ...].

    Handle all three output shapes:
      - one field per line: `    QUALITY=0`
      - several comma-separated fields on one line: `    PFC_UC_Q[0]=0,PFC_UC_Q[1]=1,...`
      - **range**-compressed indices: `    OVERLAY_NHOP_ID[0-511]=0` (a run of equal
        consecutive values in an array is printed as a single merged span)
    Indexed fields are flattened to NAME_i / NAME_i-j, while the list NAME[] is also kept
    for whole-array assertions; to read the value at a given index use field_at(), which
    also accounts for the range shape.
    Entry boundary: a field name reappearing within the current entry = start of a new
    entry (immune to blank-line differences in the output).
    """
    entries, cur = [], {}
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("Table ") or "traversed" in s or s.startswith("lt "):
            continue
        for tok in s.split(","):
            tok = tok.strip()
            m = _FIELD_RE.match(tok)
            if not m:
                continue
            raw_name = tok.split("=", 1)[0]
            base = m.group(1)
            idx = raw_name[len(base):].strip("[]") if raw_name != base else None
            key = f"{base}_{idx}" if idx not in (None, "") else base
            if key in cur:
                entries.append(cur)
                cur = {}
            cur[key] = _val(m.group(2))
            if idx not in (None, ""):
                cur.setdefault(base + "[]", []).append(_val(m.group(2)))
    if cur:
        entries.append(cur)
    return entries


def field_at(entry, name, index=0):
    """Read an array field's value at a given index, handling both the `NAME[i]=` and the range-compressed `NAME[a-b]=` output shapes."""
    if entry is None:
        return None
    key = "%s_%d" % (name, index)
    if key in entry:
        return entry[key]
    if name in entry:
        return entry[name]
    for k, v in entry.items():
        if not k.startswith(name + "_"):
            continue
        span = k[len(name) + 1:]
        if "-" in span:
            lo, _, hi = span.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= index <= int(hi):
                return v
    return None


class Dlb:
    """DLB object orchestration + chip assertions. Must call cleanup() when done (the fixture does this)."""

    def __init__(self, cli, chip):
        self.cli = cli
        self.chip = chip
        self._created = []          # [(vid, sai_type_name)], reaped in reverse order
        _VID_SEQ[0] += 1
        self._slot = _VID_SEQ[0] * 0x100     # this instance's VID range (256 each, plenty for repeated create/remove)

    # ---- ASIC_DB injection ----
    def _llen(self, key):
        out = self.cli.sh.run("redis-cli -n 1 LLEN %s" % key, check=False).out.strip()
        try:
            return int(out)
        except ValueError:
            return -1

    def quiesce(self, timeout=40.0, stable=3):
        """Wait until both the inbound queue **and** the response queue read empty `stable` times in a row before allowing an injection.

        Both conditions are required:
          - inbound queue empty = orchagent has no operation in flight, so my op will
            not get mixed into someone else's batch;
          - response queue empty = my response is guaranteed to be the **oldest** entry
            in the queue, so it is safe to reap it from the tail below.
        """
        seen = 0
        end = time.time() + timeout
        while time.time() < end:
            if self._llen(ASIC_Q) == 0 and self._llen(RESP_Q) == 0:
                seen += 1
                if seen >= stable:
                    return True
            else:
                seen = 0
            time.sleep(0.4)
        return False

    def _push(self, key, fields, op, settle):
        """Inject one operation, and **immediately** reap the response it leaves in the response queue.

        The response queue is structured as "one record per 3 elements, consumer takes
        from the tail FIFO", so:
          - it can only be reaped whole (3 elements); reaping half a record makes the
            consumer's Lua script get a nil and throw, crashing orchagent outright;
          - it must be RPOP'd from the **tail**: the queue was empty before injection, so
            mine is the oldest entry; if syncd meanwhile pushes one for orchagent, that
            one is at the head, and reaping from the tail will not touch it (LPOP from the
            head would reap the wrong record);
          - reap fast: reap the response the moment it appears. Every instant it sits in
            the queue, orchagent's next bulk wait could pick it up
            ("wrong number of statuses, got 0, expected 1" -> crash all the same).
        """
        if not self.quiesce():
            raise RuntimeError("ASIC_DB queues never went quiet (op=%d resp=%d): refusing to "
                               "inject into a busy queue"
                               % (self._llen(ASIC_Q), self._llen(RESP_Q)))
        val = json.dumps(fields) if fields else "{}"
        cmd = ("redis-cli -n 1 LPUSH %s %s %s %s >/dev/null && "
               "redis-cli -n 1 PUBLISH ASIC_STATE_CHANNEL@1 G >/dev/null"
               % (ASIC_Q, shlex.quote(key), shlex.quote(val), shlex.quote(op)))
        self.cli.sh.run(cmd, check=False)
        self._reap_response()
        time.sleep(settle)

    def _reap_response(self, timeout=20.0):
        """Wait for this injection's response to appear and reap the whole record from the tail. Returns whether one was reaped."""
        end = time.time() + timeout
        while time.time() < end:
            if self._llen(RESP_Q) >= 3:
                self.cli.sh.run(
                    "redis-cli -n 1 RPOP %s >/dev/null; redis-cli -n 1 RPOP %s >/dev/null; "
                    "redis-cli -n 1 RPOP %s >/dev/null" % (RESP_Q, RESP_Q, RESP_Q), check=False)
                left = self._llen(RESP_Q)
                if left % 3:
                    _log.error("response queue left misaligned (len=%d) after reaping: the "
                               "consumer will fault on it", left)
                return True
            time.sleep(0.1)
        _log.warning("no response appeared for an injected op within %.0fs", timeout)
        return False

    def rid(self, vid):
        out = self.cli.sh.run("redis-cli -n 1 hget VIDTORID %s" % shlex.quote("oid:%s" % vid),
                              check=False).out.strip()
        return out or None

    def has(self, vid):
        return self.rid(vid) is not None

    def wait_rid(self, vid, timeout=12.0):
        end = time.time() + timeout
        while time.time() < end:
            if self.has(vid):
                return True
            time.sleep(0.5)
        return False

    # ---- objects under test ----
    def group_vid(self, n=1):
        return "0x%x" % (_VID_NHG + self._slot + n)

    def member_vid(self, n=1):
        return "0x%x" % (_VID_MBR + self._slot + n)

    def create_group(self, gtype, n=1, settle=5.0):
        """Create a NEXT_HOP_GROUP. Returns the vid; returns None if it never materialized (no RID)."""
        vid = self.group_vid(n)
        self._push("SAI_OBJECT_TYPE_NEXT_HOP_GROUP:oid:%s" % vid,
                   ["SAI_NEXT_HOP_GROUP_ATTR_TYPE", str(gtype)], "Screate", settle)
        if not self.wait_rid(vid):
            return None
        self._created.append((vid, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP"))
        return vid

    def nh_alive(self, nh_oid):
        """Whether this NEXT_HOP object still exists right now (present in ASIC_DB + has a RID in VIDTORID)."""
        if not nh_oid or not nh_oid.startswith("oid:"):
            return False
        if not self.cli.db_keys("ASIC_DB",
                                "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:%s" % nh_oid):
            return False
        return self.rid(nh_oid.split("oid:")[-1]) is not None

    def add_member(self, group_vid, nh_oid, n=1, settle=5.0):
        """Add a member to the group. nh_oid must be a NEXT_HOP oid string that **still exists right now**.

        Existence is enforced here, not just the format: a next hop can disappear mid-case
        because its port was reset, its neighbour aged out, etc., turning a cached oid into
        an unknown VID; the moment syncd's translateVidToRid hits it, it throws and exits,
        and orchagent receives a shutdown request and exits with it. Blocking this before
        the injection means the worst outcome is a single failed case rather than the whole
        device's forwarding plane going down.
        """
        if not self.nh_alive(nh_oid):
            raise RuntimeError("refusing to inject next hop %r: it no longer exists in ASIC_DB. "
                               "Injecting an unknown VID kills syncd and takes orchagent with "
                               "it — the cached oid went stale, re-resolve it" % (nh_oid,))
        vid = self.member_vid(n)
        self._push("SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER:oid:%s" % vid,
                   ["SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID", "oid:%s" % group_vid,
                    "SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID", nh_oid], "Screate", settle)
        if not self.wait_rid(vid):
            return None
        self._created.append((vid, "SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER"))
        return vid

    def remove(self, vid, sai_type, settle=5.0):
        """Remove an object. **Only send this for objects that have a RID** (an unknown VID kills syncd)."""
        if not self.has(vid):
            return False
        self._push("%s:oid:%s" % (sai_type, vid), None, "Dremove", settle)
        gone = not self.has(vid)
        self._created = [(v, t) for (v, t) in self._created if v != vid]
        return gone

    def cleanup(self):
        """Reap in reverse order (members before groups). Runs to completion even on exceptions, so no half-torn-down object is left for the next case."""
        for vid, sai_type in reversed(list(self._created)):
            try:
                self.remove(vid, sai_type, settle=3.0)
            except Exception as e:  # noqa: BLE001
                _log.warning("cleanup of %s %s failed: %s", sai_type, vid, e)
        self._created = []

    # ---- next hop discovery ----
    def nh_by_ip(self, ip, timeout=20.0):
        """Find the NEXT_HOP oid ("oid:0x...") in ASIC_DB by neighbour IP; returns None if not found."""
        end = time.time() + timeout
        while True:
            for k in self.cli.db_keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:*"):
                h = self.cli.db_hgetall("ASIC_DB", k) or {}
                if h.get("SAI_NEXT_HOP_ATTR_IP") == ip:
                    return k.split("SAI_OBJECT_TYPE_NEXT_HOP:")[-1]
            if time.time() >= end:
                return None
            time.sleep(1.0)

    # ---- chip table reads ----
    def _traverse(self, table):
        out = self.chip.cmd("lt %s traverse -l" % table)
        if "ERROR" in out or "Failed to execute" in out:
            return []
        return parse_entries(out)

    def _lookup(self, table, **keys):
        kv = " ".join("%s=%s" % (k, v) for k, v in keys.items())
        out = self.chip.cmd("lt %s lookup %s" % (table, kv))
        if "ERROR" in out or "Failed to execute" in out:
            return None
        ents = parse_entries(out)
        return ents[0] if ents else None

    def counts(self):
        """Entry counts of the three group tables (assert on the delta, independent of the device baseline)."""
        return {t: len(self._traverse(t))
                for t in ("ECMP_OVERLAY", "ECMP_UNDERLAY", "DLB_ECMP")}

    def overlay(self):
        return self._traverse("ECMP_OVERLAY")

    def underlay(self):
        return self._traverse("ECMP_UNDERLAY")

    def dlb_ecmp(self):
        return self._traverse("DLB_ECMP")

    def port_override(self, port_id):
        """The DLB forced state of a member port. 1 = FORCE_DOWN (the member is kicked out of the group -> 100% ingress drops)."""
        e = self._lookup("DLB_ECMP_PORT_CONTROL", PORT_ID=port_id)
        return None if e is None else e.get("OVERRIDE")

    def watched_queues(self):
        """The 4 unicast queues the DLB engine watches (TM_PFC_AWARE_DLB)."""
        ents = self._traverse("TM_PFC_AWARE_DLB")
        if not ents:
            return []
        e = ents[0]
        if "PFC_UC_Q[]" in e:
            return list(e["PFC_UC_Q[]"])
        return [e[k] for k in sorted(e) if k.startswith("PFC_UC_Q_")]

    def quality_map(self):
        """[(loading, tm_queue_size, quality), ...]。"""
        out = []
        for e in self._traverse("DLB_QUALITY_MAP"):
            if "QUANTIZED_AVG_PORT_LOADING" in e and "QUALITY" in e:
                out.append((e["QUANTIZED_AVG_PORT_LOADING"],
                            e.get("QUANTIZED_AVG_TM_QUEUE_SIZE"), e["QUALITY"]))
        return out


# ---- deriving the expected PFC -> DLB watched queues (mirrors the SAI-side algorithm one-to-one) ----
_DLB_PFC_NUM_COS = 4        # number of queues the engine can watch
_DLB_PFC_MAX_UC_Q = 8       # queues outside this range are not accepted by the engine


def pfc_config(cli):
    """Read back device-wide PFC config: {port: (set(priorities), bound PFC map name or "")}."""
    out = {}
    for key in cli.db_keys("CONFIG_DB", "PORT_QOS_MAP|*"):
        h = cli.db_hgetall("CONFIG_DB", key) or {}
        raw = (h.get("pfc_enable") or "").strip()
        if not raw:
            continue
        prios = {int(x) for x in raw.split(",") if x.strip().isdigit()}
        if not prios:
            continue
        out[key.split("|", 1)[1]] = (
            prios, (h.get("pfc_to_queue_map") or "").strip("[]").split("|")[-1])
    return out


def lossless_queues(cli, off=(), on=(), remap=None):
    """Derive the "device-wide lossless queue set" from the product config.

    Mirrors the SAI-side `_sai_port_dlb_pfc_queues_sync()`: for each front-panel port,
    take the PFC-enabled priorities (combined mode looks only at tx, i.e. CONFIG_DB's
    pfc_enable), convert them to queues through that port's bound PFC_PRIORITY_TO_QUEUE
    map (identity default map if unbound), and take the **union across the whole device**
    (watched queues are switch-level, PFC is port-level).

    off/on/remap are used to **preview** what a config change would turn the union into,
    so a case can pick a change that actually moves the watched window rather than
    hard-coding a queue number (existing PFC config differs from device to device):
      off   -- {(port, prio), ...} treated as turned off
      on    -- {(port, prio), ...} treated as turned on
      remap -- {(port, prio): queue}, treated as the port's map re-pointing prio to queue
    """
    remap = remap or {}
    cfg = pfc_config(cli)
    for port, prio in on:
        prios, mapname = cfg.get(port, (set(), ""))
        cfg[port] = (set(prios) | {prio}, mapname)
    qs = set()
    for port, (prios, mapname) in cfg.items():
        pmap = {}
        if mapname:
            pmap = cli.db_hgetall("CONFIG_DB",
                                  "PFC_PRIORITY_TO_QUEUE_MAP|%s" % mapname) or {}
        for p in prios:
            if (port, p) in off:
                continue
            if (port, p) in remap:
                q = remap[(port, p)]
            else:
                q = int(pmap[str(p)]) if str(p) in pmap else p     # default map is identity
            if 0 <= q < _DLB_PFC_MAX_UC_Q:
                qs.add(q)
    return qs


def expected_watched(cli, off=(), on=(), remap=None):
    """Lossless queue set -> the 4 queues the engine should be programmed with (lossless first in ascending order, padded with non-lossless).

    Same as the SAI side: take the first 4 lossless queues in ascending order; if fewer
    than 4, pad with the smallest non-lossless queues (padding queues never pause, pure
    placeholders); if there are none at all, leave the engine untouched (return None
    meaning "make no assertion").
    See lossless_queues() for off/remap, used to preview the expected value after a change.
    """
    lossless = lossless_queues(cli, off=off, on=on, remap=remap)
    if not lossless:
        return None
    cosq = [q for q in range(_DLB_PFC_MAX_UC_Q) if q in lossless][:_DLB_PFC_NUM_COS]
    for q in range(_DLB_PFC_MAX_UC_Q):
        if len(cosq) >= _DLB_PFC_NUM_COS:
            break
        if q not in lossless:
            cosq.append(q)
    return cosq if len(cosq) == _DLB_PFC_NUM_COS else None
