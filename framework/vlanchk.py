"""Cross-image verification helper for VLAN membership programming evidence.

Background: SONiC's orchagent programs VLAN members **directly into the chip** but
**does not create SAI_VLAN_MEMBER objects** (present in CONFIG_DB, present in the
`vlan show` chip bitmap, but ASIC_DB stays at 0 -- even the default VLAN's members have
no object). Community images present them normally as SAI_VLAN_MEMBER objects.

So the "member truly programmed" assertion adapts per image:
- SAI object model (any VLAN_MEMBER object exists in ASIC_DB) -> use the original ASIC assertion;
- Chip pass-through model (object count stays 0) -> use the chip `vlan show` bitmap as
  evidence (including the tagged/untagged distinction).
"""
import re

from .loopback import BcmShell

_VM_PAT = "ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*"


def sai_member_model(asicdb):
    """Whether this image presents VLAN members as SAI_VLAN_MEMBER objects. The production
    default VLAN always has members, so on a community image this count stays >0; a count
    stuck at 0 means the chip pass-through model (SONiC)."""
    return asicdb.count(_VM_PAT) > 0


def _expand(seg):
    """Expand a bcm port list segment ('cd1,cd8-cd127' / 'none' / 'cd,d3c') into a set.
    A bare class name (e.g. 'cd') means the whole class, returned as the special marker
    '*<classname>'."""
    out = set()
    for tok in (seg or "").split(","):
        tok = tok.strip()
        if not tok or tok == "none":
            continue
        m = re.match(r"^([a-z]+)(\d+)-\1?(\d+)$", tok)
        if m:
            pre, a, b = m.group(1), int(m.group(2)), int(m.group(3))
            out.update(f"{pre}{i}" for i in range(a, b + 1))
        elif re.match(r"^[a-z]+\d+$", tok):
            out.add(tok)
        elif re.match(r"^[a-z]+$", tok) and tok != "none":
            out.add("*" + tok)   # whole class (e.g. 'cd' = all cd ports)
    return out


def _has(ports, bcm):
    if bcm in ports:
        return True
    cls = re.match(r"^([a-z]+)", bcm)
    return bool(cls) and ("*" + cls.group(1)) in ports


def chip_member(cli, dut, vid, port, untagged=None, bsh=None):
    """Chip `vlan show` bitmap evidence: whether port is in vlan <vid>'s member bitmap;
    when untagged=True/False, further check the untagged bitmap (True=must be present,
    False=must be absent=tagged)."""
    bsh = bsh or BcmShell(cli.sh, dut)
    out = bsh.cmd(f"vlan show {vid}") or ""
    line = ""
    for ln in out.splitlines():
        if re.match(rf"^\s*vlan\s+{vid}\b", ln):
            line = ln
            break
    if not line:
        out = bsh.cmd("vlan show") or ""
        for ln in out.splitlines():
            if re.match(rf"^\s*vlan\s+{vid}\b", ln):
                line = ln
                break
    if not line:
        return False
    m_p = re.search(r"ports\s+(.*?)\s*\(0x", line)
    m_u = re.search(r"untagged\s+(.*?)\s*\(0x", line)
    ports = _expand(m_p.group(1) if m_p else "")
    utg = _expand(m_u.group(1) if m_u else "")
    if isinstance(port, str):
        from .ports import Port
        port = Port(name=port)
    bcm = dut.bcm_of(port)
    if not _has(ports, bcm):
        return False
    if untagged is True:
        return _has(utg, bcm)
    if untagged is False:
        return not _has(utg, bcm)
    return True
