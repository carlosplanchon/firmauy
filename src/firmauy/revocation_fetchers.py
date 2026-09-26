# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""pyhanko-certvalidator's requests fetchers, routed through :mod:`firmauy.outbound`.

certvalidator makes every HTTP request of its requests backend in two methods of a mixin,
``_get`` and ``_post``, with requests' defaults: thirty redirects followed, bodies read whole,
``~/.netrc`` consulted. The fetchers below override those two methods and nothing else, so each
CRL, OCSP and AIA request goes through the outbound policy with the limits that fit it, and what
the policy refuses reaches certvalidator as the ``requests.RequestException`` it already turns
into a failed fetch.

The two methods are private to certvalidator. They are byte-identical in 0.31.4 and 0.32.1, the
range firmauy supports, and the revocation tests go through them, so a change there fails the
suite instead of quietly bypassing the policy.
"""

from __future__ import annotations

import threading
from asyncio import to_thread

import requests
from pyhanko_certvalidator.fetchers.api import FetcherBackend, Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers.cert_fetch_client import (
    RequestsCertificateFetcher,
)
from pyhanko_certvalidator.fetchers.requests_fetchers.crl_client import RequestsCRLFetcher
from pyhanko_certvalidator.fetchers.requests_fetchers.ocsp_client import RequestsOCSPFetcher

from firmauy import outbound


class _PolicyFetchMixin:
    """Replaces the stock mixin's two request methods. ``_policy`` names the limits per kind."""

    _policy = None

    def __init__(self, *args, backend: "PolicyFetcherBackend", **kwargs):
        super().__init__(*args, **kwargs)
        self._backend = backend

    def _get(self, url, *, acceptable_content_types):
        headers = {"Accept": ",".join(acceptable_content_types), "User-Agent": self.user_agent}
        return to_thread(self._backend.fetch, "GET", url, type(self)._policy, headers, None)

    def _post(self, url, data, *, content_type, acceptable_content_types):
        headers = {"Accept": ",".join(acceptable_content_types), "User-Agent": self.user_agent,
                   "Content-Type": content_type}
        return to_thread(self._backend.fetch, "POST", url, type(self)._policy, headers, data)


class _PolicyCRLFetcher(_PolicyFetchMixin, RequestsCRLFetcher):
    _policy = staticmethod(outbound.crl_policy)


class _PolicyOCSPFetcher(_PolicyFetchMixin, RequestsOCSPFetcher):
    _policy = staticmethod(outbound.ocsp_policy)


class _PolicyCertificateFetcher(_PolicyFetchMixin, RequestsCertificateFetcher):
    _policy = staticmethod(outbound.cert_policy)


class PolicyFetcherBackend(FetcherBackend):
    """The fetchers for one verification, sharing its budget and its record of refusals.

    certvalidator reduces a failed fetch to "Failure to fetch CRL from URL ...", which does not
    say that firmauy refused it, nor why, nor that --allow-private-network exists. The refusals
    are kept here so the verifier can add them to the chain row.
    """

    def __init__(self, allow_private_network: bool = False):
        self.allow_private_network = allow_private_network
        self.budget = outbound.FetchBudget()
        self._lock = threading.Lock()
        self._refusals: list = []

    def get_fetchers(self) -> Fetchers:
        return Fetchers(
            ocsp_fetcher=_PolicyOCSPFetcher(backend=self),
            crl_fetcher=_PolicyCRLFetcher(backend=self),
            cert_fetcher=_PolicyCertificateFetcher(backend=self),
        )

    async def close(self):
        # Nothing held open: each fetch makes and closes its own session.
        return

    @property
    def refusals(self) -> list:
        with self._lock:
            return list(self._refusals)

    def fetch(self, method, url, policy_for, headers, data):
        """One request under the policy for its kind, run in certvalidator's worker thread."""
        try:
            result = outbound.fetch(method, url, policy=policy_for(self.allow_private_network),
                                    headers=headers, data=data, budget=self.budget)
        except (outbound.DestinationRefused, outbound.BudgetExceeded) as exc:
            with self._lock:
                self._refusals.append(exc)
            raise
        if result.status_code != 200:
            # What the stock mixin does, so certvalidator sees the same failure it always did.
            raise requests.RequestException(f"status code {result.status_code}")
        return result
