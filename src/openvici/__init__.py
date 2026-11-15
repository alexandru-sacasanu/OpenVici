"""OpenVici: a personal AI agent that is isolated by default.

Security model in one paragraph: the only boundary against a hostile model is
the operating system (``openvici.sandbox``). Everything else in this package
(the approval gate, redaction, credential scoping) is accident prevention
layered on top of that boundary, and is documented as such.
"""

__version__ = "0.0.1"
