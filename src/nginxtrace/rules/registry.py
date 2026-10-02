from nginxtrace.rules.alias_traversal import AliasTraversalRule
from nginxtrace.rules.base import Rule
from nginxtrace.rules.crlf_injection import CrlfInjectionRule
from nginxtrace.rules.dangerous_root import DangerousRootRule
from nginxtrace.rules.header_multiline import MultilineHeaderRule
from nginxtrace.rules.header_redefinition import HeaderRedefinitionRule
from nginxtrace.rules.host_spoofing import HostSpoofingRule
from nginxtrace.rules.map_default import MapMissingDefaultRule
from nginxtrace.rules.merge_slashes import MergeSlashesOffRule
from nginxtrace.rules.raw_backend_response import RawBackendResponseRule
from nginxtrace.rules.secret_exposure import SecretExposureRule
from nginxtrace.rules.ssrf import SsrfRule
from nginxtrace.rules.valid_referers import ValidReferersNoneRule

def default_rules() -> tuple[Rule, ...]:
    return (
        SecretExposureRule(),
        DangerousRootRule(),
        MergeSlashesOffRule(),
        HostSpoofingRule(),
        ValidReferersNoneRule(),
        CrlfInjectionRule(),
        MultilineHeaderRule(),
        AliasTraversalRule(),
        MapMissingDefaultRule(),
        SsrfRule(),
        HeaderRedefinitionRule(),
        RawBackendResponseRule(),
    )

def find_rule(rule_id: str) -> Rule | None:
    for rule in default_rules():
        if rule.rule_id == rule_id:
            return rule

    return None
