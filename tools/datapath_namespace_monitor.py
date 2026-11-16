"""Read-only PPP namespace verification, including named-netns teardown races."""
import os
from pathlib import Path
import subprocess


def process_snapshot(pid):
    try:
        root = Path('/proc', str(pid))
        # comm may contain spaces or parentheses; starttime is stat field 22.
        start = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        return dict(start=start, net=os.readlink(root / 'ns/net'),
                    exe=str((root / 'exe').resolve(strict=True)))
    except (FileNotFoundError, ProcessLookupError):
        return None


def namespace_names():
    names = {}
    for path in Path('/run/netns').glob('*'):
        try:
            names[path.name] = 'net:[%d]' % path.stat().st_ino
        except FileNotFoundError:
            pass
    return names


def identify(pid):
    result = subprocess.run(['ip', 'netns', 'identify', str(pid)],
                            text=True, capture_output=True, check=False)
    return dict(stdout=result.stdout.strip(), stderr=result.stderr.strip(),
                returncode=result.returncode)


def verify_child(pid, before, binary, forbidden, verified,
                 snapshot=process_snapshot, names=namespace_names, query=identify):
    """Return a decision and enough evidence to audit every unverifiable child.

    A live unnamed namespace is accepted only after this exact process identity
    and inode were verified, and its named mount has disappeared during cleanup.
    A live process in an unknown or forbidden namespace always stops the run.
    """
    output = query(pid)
    mounts = names()
    after = snapshot(pid)
    record = dict(pid=int(pid), before=before, after=after, names=mounts,
                  identify=output)
    if after is None or after['exe'] != binary or \
            (before is not None and after['start'] != before['start']):
        record['decision'] = 'process-exited'
        return record
    if before is None:
        before = after
    net = after['net']
    identity = (str(pid), after['start'], net)
    reported = output['stdout'].splitlines()
    valid_name = any(name.startswith(('pppmat-c-', 'pppmat-s-')) and
                     mounts.get(name) == net for name in reported)
    if net not in forbidden and output['returncode'] == 0 and valid_name:
        verified.add(identity)
        record['decision'] = 'verified'
    elif net not in forbidden and identity in verified and net == before['net'] and \
            not reported and net not in mounts.values():
        record['decision'] = 'namespace-gone'
    else:
        record['decision'] = 'STOP-unexpected-namespace'
    return record
