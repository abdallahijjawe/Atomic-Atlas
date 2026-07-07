"""ATLAS-Atomic: Atomic Red Team-style testing framework for MITRE ATLAS (AI security).

A framework that *emulates* AI attacker techniques against LLM applications for
defensive validation. It does not perform real attacks or cause harm -- it drives
prompts through a provider abstraction and evaluates whether the target's safety
controls behaved as expected.
"""

__version__ = "0.1.0"
__author__ = "Abdalla Hijjawe"

__all__ = ["__version__", "__author__"]
