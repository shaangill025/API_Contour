"""Closed v21 adapter for the existing role-separated credential bundle.

No issuer inputs are read until an explicitly called operation executes.
"""
from pathlib import Path
from deploy.local import origin21_profile, origin21_state, origin21_configs
from deploy.pilot import origin_credentials


class Credentials(origin_credentials.Credentials):
    def __init__(self, profile, ca_cert, ca_key):
        if profile is not origin21_profile.PROFILE: raise ValueError('unsupported origin21 profile')
        self.profile, self.ca_cert, self.ca_key = profile, Path(ca_cert), Path(ca_key)
        self.allow_observer_policy = False
        self.allow_renewal_artifacts = frozenset()
        self.allow_runtime_configs = False
        self.allow_operator_evidence = False

    def inspect(self):
        root=self.profile.state
        try:
            origin_credentials._dir(root)
            entries=origin_credentials._walk(root,bool(self.allow_renewal_artifacts)) - {'setup.lock','setup.json'}
            entries-=self.allow_renewal_artifacts
            if self.allow_observer_policy: entries.discard('capture/private/observer-policy.json')
            if self.allow_operator_evidence: entries.discard('operator-evidence.json')
            if self.allow_runtime_configs:
                if origin21_configs.Configs(self.profile).inspect()!=origin21_state.EXACT: return origin21_state.DRIFT
                entries-=set(origin21_configs.expected())
            if not entries: return origin21_state.ABSENT
            if entries!=origin_credentials._expected(): return origin21_state.DRIFT
            self._verify()
            return origin21_state.EXACT
        except (OSError,ValueError,RuntimeError,origin_credentials.subprocess.SubprocessError): return origin21_state.DRIFT
