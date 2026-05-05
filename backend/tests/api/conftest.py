"""Test fixtures for API route tests.

WHY: full route tests need a FastAPI TestClient and a stand-in for the
Mongo database. We use FastAPI's `dependency_overrides` to inject a
small in-memory fake — no live Mongo required, no testcontainers
overhead. Phase 9 (real integration tests) replaces the fake with a
testcontainers-backed Mongo.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api import deps
from api.routes import findings as findings_routes
from api.routes import health as health_routes
from api.routes import integrations as integration_routes
from api.routes import reports as report_routes
from api.routes import repositories as repository_routes
from api.routes import scans as scan_routes
from api.routes import settings as settings_routes
from api.routes import stats as stats_routes

# --------------------------------------------------------------------- #
# Tiny in-memory Mongo replacement.
#
# Only implements the operations exercised by the extracted routes:
# find / find_one / delete_one / delete_many / count_documents / sort /
# limit / to_list. This is intentionally minimal — when we move to
# testcontainers in Phase 9 this fake goes away.
# --------------------------------------------------------------------- #


class FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]):
        self._docs = docs
        self._sort_key: str | None = None
        self._reverse: bool = False
        self._limit: int | None = None

    def sort(self, key: str, direction: int = 1) -> FakeCursor:
        self._sort_key = key
        self._reverse = direction == -1
        return self

    def limit(self, n: int) -> FakeCursor:
        self._limit = n
        return self

    async def to_list(self, length: int | None = None) -> list[dict[str, Any]]:
        out = list(self._docs)
        if self._sort_key is not None:
            out.sort(key=lambda d: d.get(self._sort_key, ""), reverse=self._reverse)
        if self._limit is not None:
            out = out[: self._limit]
        if length is not None:
            out = out[:length]
        return out


class FakeCollection:
    def __init__(self, name: str):
        self.name = name
        self._docs: list[dict[str, Any]] = []

    def insert(self, *docs: dict[str, Any]) -> None:
        self._docs.extend(docs)

    def find(self, query: dict[str, Any] | None = None, projection=None) -> FakeCursor:
        return FakeCursor(self._match(query or {}))

    async def find_one(
        self,
        query: dict[str, Any],
        projection=None,
        sort: list[tuple] | None = None,
    ) -> dict[str, Any] | None:
        matched = self._match(query)
        if sort:
            key, direction = sort[0]
            matched.sort(key=lambda d: d.get(key, ""), reverse=direction == -1)
        return matched[0] if matched else None

    async def delete_one(self, query: dict[str, Any]):
        for i, doc in enumerate(self._docs):
            if self._matches(doc, query):
                del self._docs[i]
                return type("Result", (), {"deleted_count": 1})
        return type("Result", (), {"deleted_count": 0})

    async def delete_many(self, query: dict[str, Any]):
        before = len(self._docs)
        self._docs = [d for d in self._docs if not self._matches(d, query)]
        return type("Result", (), {"deleted_count": before - len(self._docs)})

    async def count_documents(self, query: dict[str, Any]) -> int:
        return len(self._match(query))

    def _match(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [d for d in self._docs if self._matches(d, query)]

    @staticmethod
    def _matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
        for key, expected in query.items():
            actual = doc.get(key)
            if isinstance(expected, dict) and "$in" in expected:
                if actual not in expected["$in"]:
                    return False
            elif actual != expected:
                return False
        return True


class FakeDB:
    def __init__(self) -> None:
        self.repositories = FakeCollection("repositories")
        self.scans = FakeCollection("scans")
        self.vulnerabilities = FakeCollection("vulnerabilities")
        self.quality_issues = FakeCollection("quality_issues")
        self.compliance_issues = FakeCollection("compliance_issues")


class FakeMongoClient:
    def __init__(self) -> None:
        self.admin = self

    async def command(self, _name: str) -> dict[str, Any]:
        return {"ok": 1}


class FakeGitIntegration:
    """Stand-in for the real GitIntegrationService.

    Tests can swap behaviour by setting attributes directly on the
    fixture instance — see `tests/api/test_integrations.py`.
    """

    def __init__(self) -> None:
        self.integrations: list[Any] = []
        self.connect_result: dict[str, Any] = {"success": True, "name": "test"}
        self.disconnect_result: dict[str, Any] = {"success": True}
        self.list_remote_result: dict[str, Any] = {"success": True, "repositories": []}

    async def remove_repository(self, _repo_id: str) -> dict[str, Any]:
        return {"success": False}

    async def get_integrations(self):
        return self.integrations

    async def connect_integration(self, **_kwargs):
        return self.connect_result

    async def disconnect_integration(self, _provider, _name):
        return self.disconnect_result

    async def list_remote_repositories(self, _provider, page: int = 1, per_page: int = 30):
        return self.list_remote_result


class FakeSettingsManager:
    """Stand-in for the real SettingsManager.

    The route tests inject canned responses by mutating attributes on
    the fixture instance.
    """

    def __init__(self) -> None:
        from settings.models import AIScannerSettings, ScannerSettings, SettingsResponse

        self._all_settings = SettingsResponse(
            llm_api_keys={"openai": False, "anthropic": False, "gemini": False},
        )
        self._scanner_settings = ScannerSettings()
        self._ai_scanner_settings = AIScannerSettings(
            enable_zero_day_detector=True,
            enable_business_logic_scanner=True,
            enable_llm_security_scanner=True,
            enable_auth_scanner=False,
        )
        self._api_keys: dict[str, str] = {}
        self.update_calls: list[Any] = []

    async def get_scanner_settings(self):
        return self._scanner_settings

    async def update_scanner_settings(self, request):
        self.update_calls.append(("scanners", request))
        return self._scanner_settings

    async def get_ai_scanner_settings(self) -> dict[str, Any]:
        return self._ai_scanner_settings.model_dump()

    async def update_ai_scanner_settings(self, settings) -> bool:
        self.update_calls.append(("ai_scanners", settings))
        return True

    async def get_all_settings(self):
        return self._all_settings

    async def update_api_keys(self, api_keys) -> None:
        self.update_calls.append(("api_keys", api_keys))
        # Use the class — accessing model_fields on instances is
        # deprecated in Pydantic 2.11+.
        for field in type(api_keys).model_fields:
            value = getattr(api_keys, field, None)
            if value:
                self._api_keys[field] = value

    async def get_api_keys(self) -> dict[str, str]:
        return dict(self._api_keys)

    def clear_cache(self) -> None:
        self.update_calls.append(("clear_cache", None))


# --------------------------------------------------------------------- #
# FastAPI app under test — a fresh app per test session so dependency
# overrides do not leak between suites.
# --------------------------------------------------------------------- #


@pytest.fixture
def fake_db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def fake_client_factory():
    def _make(db: FakeDB) -> TestClient:
        from fastapi import APIRouter, FastAPI

        app = FastAPI()
        api_router = APIRouter(prefix="/api")
        api_router.include_router(health_routes.router)
        api_router.include_router(repository_routes.router)
        api_router.include_router(stats_routes.router)
        api_router.include_router(scan_routes.router)
        api_router.include_router(findings_routes.router)
        api_router.include_router(settings_routes.router)
        api_router.include_router(integration_routes.router)
        api_router.include_router(report_routes.router)
        app.include_router(api_router)

        mongo_client = FakeMongoClient()
        git_integration = FakeGitIntegration()
        settings_manager = FakeSettingsManager()

        app.dependency_overrides[deps.get_db] = lambda: db
        app.dependency_overrides[deps.get_client] = lambda: mongo_client
        app.dependency_overrides[deps.get_git_integration] = lambda: git_integration
        app.dependency_overrides[deps.get_settings_manager] = lambda: settings_manager

        return TestClient(app)

    return _make


@pytest.fixture
def client(fake_db, fake_client_factory) -> TestClient:
    return fake_client_factory(fake_db)
