"""
Git Integration Service for FortKnoxx
Handles GitHub and GitLab API interactions
"""

import os
import re
import httpx
import hashlib
import hmac
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from .models import GitProvider, GitIntegration, GitRepository, GitIntegrationStatus

logger = logging.getLogger(__name__)


class GitIntegrationService:
    """Service for managing Git provider integrations"""

    # API endpoints
    GITHUB_API_URL = "https://api.github.com"
    GITLAB_API_URL = "https://gitlab.com/api/v4"

    def __init__(self, db=None, encryption_service=None):
        self.db = db
        self.encryption = encryption_service
        self._integrations_collection = "git_integrations"
        self._repositories_collection = "git_repositories"

    def set_db(self, db):
        """Set the database connection"""
        self.db = db

    def set_encryption(self, encryption_service):
        """Set the encryption service"""
        self.encryption = encryption_service

    # ============================================
    # Integration Management
    # ============================================

    async def connect_integration(
        self,
        provider: GitProvider,
        name: str,
        access_token: str,
        base_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Connect a new Git provider integration"""
        try:
            # Validate the token by making a test API call
            user_info = await self._validate_token(provider, access_token, base_url)

            if not user_info:
                return {"success": False, "error": "Invalid access token"}

            # Encrypt the token
            encrypted_token = None
            if self.encryption:
                encrypted_token = self.encryption.encrypt(access_token)
            else:
                encrypted_token = access_token  # Fallback (not recommended)

            # Generate webhook secret
            webhook_secret = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
            encrypted_webhook_secret = None
            if self.encryption:
                encrypted_webhook_secret = self.encryption.encrypt(webhook_secret)
            else:
                encrypted_webhook_secret = webhook_secret

            # Create integration document
            integration = {
                "provider": provider.value,
                "name": name,
                "access_token": encrypted_token,
                "base_url": base_url,
                "is_connected": True,
                "username": user_info.get("username"),
                "user_id": user_info.get("id"),
                "avatar_url": user_info.get("avatar_url"),
                "webhook_secret": encrypted_webhook_secret,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }

            # Upsert integration (one per provider, or use name as key)
            if self.db is not None:
                await self.db[self._integrations_collection].update_one(
                    {"provider": provider.value, "name": name},
                    {"$set": integration},
                    upsert=True
                )

            return {
                "success": True,
                "provider": provider.value,
                "username": user_info.get("username"),
                "message": f"Successfully connected to {provider.value}"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def disconnect_integration(self, provider: GitProvider, name: str) -> Dict[str, Any]:
        """Disconnect a Git provider integration"""
        try:
            if self.db is not None:
                result = await self.db[self._integrations_collection].delete_one(
                    {"provider": provider.value, "name": name}
                )
                # Also remove associated repositories
                await self.db[self._repositories_collection].delete_many(
                    {"provider": provider.value}
                )

                if result.deleted_count > 0:
                    return {"success": True, "message": f"Disconnected {provider.value}"}

            return {"success": False, "error": "Integration not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_integrations(self) -> List[GitIntegrationStatus]:
        """Get all connected integrations (without sensitive data)"""
        integrations = []

        if self.db is not None:
            cursor = self.db[self._integrations_collection].find({})
            async for doc in cursor:
                integrations.append(GitIntegrationStatus(
                    provider=GitProvider(doc["provider"]),
                    name=doc.get("name", doc["provider"]),
                    is_connected=doc.get("is_connected", False),
                    username=doc.get("username"),
                    base_url=doc.get("base_url"),
                    has_webhook=bool(doc.get("webhook_secret")),
                    updated_at=doc.get("updated_at")
                ))

        return integrations

    async def get_integration(self, provider: GitProvider, name: str = None) -> Optional[Dict[str, Any]]:
        """Get a specific integration with decrypted token"""
        if self.db is None:
            return None

        query = {"provider": provider.value}
        if name:
            query["name"] = name

        doc = await self.db[self._integrations_collection].find_one(query)

        if doc:
            # Decrypt token
            access_token = doc.get("access_token")
            if access_token and self.encryption:
                try:
                    access_token = self.encryption.decrypt(access_token)
                except:
                    pass  # Token might not be encrypted

            return {
                "provider": doc["provider"],
                "name": doc.get("name"),
                "access_token": access_token,
                "base_url": doc.get("base_url"),
                "username": doc.get("username"),
                "is_connected": doc.get("is_connected", False)
            }

        return None

    # ============================================
    # Repository Management
    # ============================================

    async def list_remote_repositories(
        self,
        provider: GitProvider,
        integration_name: str = None,
        page: int = 1,
        per_page: int = 30
    ) -> Dict[str, Any]:
        """List repositories from the connected Git provider"""
        integration = await self.get_integration(provider, integration_name)

        if not integration or not integration.get("access_token"):
            return {"success": False, "error": "Integration not connected"}

        token = integration["access_token"]
        base_url = integration.get("base_url")

        try:
            if provider == GitProvider.GITHUB:
                repos = await self._github_list_repos(token, page, per_page)
            elif provider == GitProvider.GITLAB:
                repos = await self._gitlab_list_repos(token, base_url, page, per_page)
            else:
                return {"success": False, "error": "Unsupported provider"}

            return {"success": True, "repositories": repos}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def add_repository(
        self,
        provider: GitProvider,
        repo_url: str,
        auto_scan: bool = False,
        branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a repository for scanning"""
        # Parse repository URL
        repo_info = self._parse_repo_url(repo_url)

        if not repo_info:
            return {"success": False, "error": "Invalid repository URL"}

        # Get integration
        integration = await self.get_integration(provider)

        if not integration:
            return {"success": False, "error": f"{provider.value} not connected"}

        token = integration["access_token"]
        base_url = integration.get("base_url")

        try:
            # Fetch repository details from API
            if provider == GitProvider.GITHUB:
                repo_details = await self._github_get_repo(
                    token, repo_info["owner"], repo_info["name"]
                )
            elif provider == GitProvider.GITLAB:
                repo_details = await self._gitlab_get_repo(
                    token, base_url, f"{repo_info['owner']}/{repo_info['name']}"
                )
            else:
                return {"success": False, "error": "Unsupported provider"}

            if not repo_details:
                return {"success": False, "error": "Repository not found or not accessible"}

            # Create repository document
            repo_doc = {
                "repo_id": f"{provider.value}_{repo_details['id']}",
                "provider": provider.value,
                "full_name": repo_details["full_name"],
                "name": repo_details["name"],
                "owner": repo_details["owner"],
                "clone_url": repo_details["clone_url"],
                "default_branch": branch or repo_details.get("default_branch", "main"),
                "private": repo_details.get("private", False),
                "auto_scan": auto_scan,
                "added_at": datetime.now(timezone.utc)
            }

            # Save to database
            if self.db is not None:
                await self.db[self._repositories_collection].update_one(
                    {"repo_id": repo_doc["repo_id"]},
                    {"$set": repo_doc},
                    upsert=True
                )

            return {
                "success": True,
                "repository": repo_doc,
                "message": f"Added {repo_details['full_name']}"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def add_public_repository(
        self,
        provider: GitProvider,
        repo_url: str,
        auto_scan: bool = False,
        branch: Optional[str] = None,
        access_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a public repository without requiring Git Integration (or use provided token for private repos)"""
        # Parse repository URL
        repo_info = self._parse_repo_url(repo_url)

        if not repo_info:
            return {"success": False, "error": "Invalid repository URL"}

        try:
            # Use provided token if available, otherwise try public access
            token = access_token

            # Fetch repository details from API (works for public repos without token)
            if provider == GitProvider.GITHUB:
                repo_details = await self._github_get_repo(
                    token, repo_info["owner"], repo_info["name"]
                )
            elif provider == GitProvider.GITLAB:
                # For GitLab, use the default API URL
                base_url = self.GITLAB_API_URL  # https://gitlab.com/api/v4
                repo_details = await self._gitlab_get_repo(
                    token, base_url, f"{repo_info['owner']}/{repo_info['name']}"
                )
            else:
                return {"success": False, "error": "Unsupported provider"}

            if not repo_details:
                return {"success": False, "error": "Repository not found or not accessible"}

            # Create repository document
            repo_doc = {
                "repo_id": f"{provider.value}_{repo_details['id']}",
                "provider": provider.value,
                "full_name": repo_details["full_name"],
                "name": repo_details["name"],
                "owner": repo_details["owner"],
                "clone_url": repo_details["clone_url"],
                "default_branch": branch or repo_details.get("default_branch", "main"),
                "private": repo_details.get("private", False),
                "auto_scan": auto_scan,
                "added_at": datetime.now(timezone.utc),
                "added_via": "direct_url",  # Mark as directly added (not via Git Integration)
                "has_token": access_token is not None  # Track if we have a token stored
            }

            # Save to database
            if self.db is not None:
                await self.db[self._repositories_collection].update_one(
                    {"repo_id": repo_doc["repo_id"]},
                    {"$set": repo_doc},
                    upsert=True
                )

            return {
                "success": True,
                "repository": repo_doc,
                "message": f"Added {repo_details['full_name']}"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_repositories(self, provider: Optional[GitProvider] = None) -> List[Dict[str, Any]]:
        """Get all added repositories"""
        repos = []

        if self.db is not None:
            query = {}
            if provider:
                query["provider"] = provider.value

            cursor = self.db[self._repositories_collection].find(query)
            async for doc in cursor:
                doc.pop("_id", None)
                repos.append(doc)

        return repos

    async def remove_repository(self, repo_id: str) -> Dict[str, Any]:
        """Remove a repository"""
        if self.db is not None:
            result = await self.db[self._repositories_collection].delete_one(
                {"repo_id": repo_id}
            )
            if result.deleted_count > 0:
                return {"success": True, "message": "Repository removed"}

        return {"success": False, "error": "Repository not found"}

    # ============================================
    # Clone Repository for Scanning
    # ============================================

    async def clone_repository(
        self,
        repo_id: str,
        target_dir: str,
        branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """Clone a repository for scanning"""
        import subprocess
        import tempfile

        # Get repository info
        if self.db is not None:
            repo = await self.db[self._repositories_collection].find_one({"repo_id": repo_id})
        else:
            return {"success": False, "error": "Database not connected"}

        if not repo:
            return {"success": False, "error": "Repository not found"}

        # Get integration for auth
        provider = GitProvider(repo["provider"])
        integration = await self.get_integration(provider)

        if not integration:
            return {"success": False, "error": "Git integration not connected"}

        token = integration["access_token"]
        clone_url = repo["clone_url"]
        branch = branch or repo.get("default_branch", "main")

        # Add token to clone URL for authentication
        if provider == GitProvider.GITHUB:
            # https://github.com/owner/repo.git -> https://token@github.com/owner/repo.git
            auth_url = clone_url.replace("https://", f"https://{token}@")
        elif provider == GitProvider.GITLAB:
            # https://gitlab.com/owner/repo.git -> https://oauth2:token@gitlab.com/owner/repo.git
            auth_url = clone_url.replace("https://", f"https://oauth2:{token}@")
        else:
            auth_url = clone_url

        try:
            # Clone the repository
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", branch, auth_url, target_dir],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            # Update last scanned time
            if self.db is not None:
                await self.db[self._repositories_collection].update_one(
                    {"repo_id": repo_id},
                    {"$set": {"last_scanned": datetime.now(timezone.utc)}}
                )

            return {
                "success": True,
                "path": target_dir,
                "branch": branch,
                "message": f"Cloned {repo['full_name']}"
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Clone operation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ============================================
    # Webhook Handling
    # ============================================

    def verify_webhook_signature(
        self,
        provider: GitProvider,
        payload: bytes,
        signature: str,
        secret: str
    ) -> bool:
        """Verify webhook signature"""
        if provider == GitProvider.GITHUB:
            # GitHub uses HMAC-SHA256
            expected = "sha256=" + hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)

        elif provider == GitProvider.GITLAB:
            # GitLab sends token in X-Gitlab-Token header
            return signature == secret

        return False

    # ============================================
    # Private Helper Methods
    # ============================================

    async def _validate_token(
        self,
        provider: GitProvider,
        token: str,
        base_url: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Validate token and get user info"""
        async with httpx.AsyncClient() as client:
            try:
                if provider == GitProvider.GITHUB:
                    url = f"{self.GITHUB_API_URL}/user"
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json"
                    }
                    response = await client.get(url, headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        return {
                            "id": data["id"],
                            "username": data["login"],
                            "avatar_url": data.get("avatar_url")
                        }

                elif provider == GitProvider.GITLAB:
                    url = f"{base_url or self.GITLAB_API_URL}/user"
                    headers = {"PRIVATE-TOKEN": token}
                    response = await client.get(url, headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        return {
                            "id": data["id"],
                            "username": data["username"],
                            "avatar_url": data.get("avatar_url")
                        }

            except Exception as e:
                print(f"Token validation error: {e}")

        return None

    async def _github_list_repos(
        self,
        token: str,
        page: int = 1,
        per_page: int = 100,
        fetch_all: bool = True
    ) -> List[Dict[str, Any]]:
        """List GitHub repositories - fetches all pages by default"""
        repos = []
        current_page = page
        max_pages = 50  # Safety limit to prevent infinite loops

        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json"
            }

            while current_page <= max_pages:
                url = f"{self.GITHUB_API_URL}/user/repos"
                params = {
                    "page": current_page,
                    "per_page": per_page,
                    "sort": "updated",
                    "affiliation": "owner,collaborator,organization_member"
                }

                response = await client.get(url, headers=headers, params=params)

                if response.status_code != 200:
                    break

                page_repos = response.json()

                if not page_repos:
                    break

                for repo in page_repos:
                    repos.append({
                        "id": repo["id"],
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "owner": repo["owner"]["login"],
                        "clone_url": repo["clone_url"],
                        "default_branch": repo.get("default_branch", "main"),
                        "private": repo["private"],
                        "description": repo.get("description"),
                        "language": repo.get("language"),
                        "updated_at": repo["updated_at"]
                    })

                # Check if we should fetch more pages
                if not fetch_all or len(page_repos) < per_page:
                    break

                current_page += 1

        return repos

    async def _gitlab_list_repos(
        self,
        token: str,
        base_url: Optional[str],
        page: int = 1,
        per_page: int = 100,
        fetch_all: bool = True
    ) -> List[Dict[str, Any]]:
        """List GitLab projects - fetches all pages by default"""
        repos = []
        current_page = page
        max_pages = 50  # Safety limit to prevent infinite loops

        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"PRIVATE-TOKEN": token}

            while current_page <= max_pages:
                url = f"{base_url or self.GITLAB_API_URL}/projects"
                params = {
                    "page": current_page,
                    "per_page": per_page,
                    "membership": True,
                    "order_by": "updated_at"
                }

                response = await client.get(url, headers=headers, params=params)

                if response.status_code != 200:
                    break

                page_repos = response.json()

                if not page_repos:
                    break

                for project in page_repos:
                    repos.append({
                        "id": project["id"],
                        "name": project["name"],
                        "full_name": project["path_with_namespace"],
                        "owner": project["namespace"]["path"],
                        "clone_url": project["http_url_to_repo"],
                        "default_branch": project.get("default_branch", "main"),
                        "private": project["visibility"] != "public",
                        "description": project.get("description"),
                        "language": None,  # GitLab doesn't return this in list
                        "updated_at": project["last_activity_at"]
                    })

                # Check if we should fetch more pages
                if not fetch_all or len(page_repos) < per_page:
                    break

                current_page += 1

        return repos

    async def _github_get_repo(
        self,
        token: Optional[str],
        owner: str,
        name: str
    ) -> Optional[Dict[str, Any]]:
        """Get GitHub repository details (supports public repos without token)"""
        async with httpx.AsyncClient() as client:
            url = f"{self.GITHUB_API_URL}/repos/{owner}/{name}"
            headers = {
                "Accept": "application/vnd.github+json"
            }

            # Only add Authorization header if token is provided
            if token:
                headers["Authorization"] = f"Bearer {token}"

            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                repo = response.json()
                return {
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "owner": repo["owner"]["login"],
                    "clone_url": repo["clone_url"],
                    "default_branch": repo.get("default_branch", "main"),
                    "private": repo["private"]
                }

        return None

    async def _gitlab_get_repo(
        self,
        token: Optional[str],
        base_url: Optional[str],
        project_path: str
    ) -> Optional[Dict[str, Any]]:
        """Get GitLab project details (supports public projects without token)"""
        import urllib.parse
        encoded_path = urllib.parse.quote(project_path, safe="")

        async with httpx.AsyncClient() as client:
            url = f"{base_url or self.GITLAB_API_URL}/projects/{encoded_path}"
            headers = {}

            # Only add PRIVATE-TOKEN header if token is provided
            if token:
                headers["PRIVATE-TOKEN"] = token

            logger.debug(f"GitLab API request: {url} (token provided: {bool(token)})")
            response = await client.get(url, headers=headers)
            logger.debug(f"GitLab API response status: {response.status_code}")

            if response.status_code == 200:
                project = response.json()
                return {
                    "id": project["id"],
                    "name": project["name"],
                    "full_name": project["path_with_namespace"],
                    "owner": project["namespace"]["path"],
                    "clone_url": project["http_url_to_repo"],
                    "default_branch": project.get("default_branch", "main"),
                    "private": project["visibility"] != "public"
                }
            else:
                logger.warning(f"GitLab API error: {response.status_code} - {response.text[:200]}")

        return None

    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse repository URL to extract owner and name"""
        # Match patterns like:
        # https://github.com/owner/repo
        # https://github.com/owner/repo.git
        # git@github.com:owner/repo.git
        # https://gitlab.com/owner/repo
        # https://gitlab.com/group/subgroup/repo (GitLab nested groups)

        # GitLab patterns (supports nested groups like group/subgroup/repo)
        gitlab_patterns = [
            r"https?://(?:www\.)?gitlab\.com/(.+)/([^/\.]+)(?:\.git)?/?$",
            r"git@gitlab\.com:(.+)/([^/\.]+)(?:\.git)?$",
        ]

        # GitHub patterns
        github_patterns = [
            r"https?://(?:www\.)?github\.com/([^/]+)/([^/\.]+)(?:\.git)?/?$",
            r"git@github\.com:([^/]+)/([^/\.]+)(?:\.git)?$",
        ]

        # Self-hosted patterns
        other_patterns = [
            r"https?://[^/]+/(.+)/([^/\.]+)(?:\.git)?/?$",  # Self-hosted (supports nested paths)
            r"git@[^:]+:(.+)/([^/\.]+)(?:\.git)?$",  # SSH
        ]

        # Try GitLab patterns first (supports nested groups)
        for pattern in gitlab_patterns:
            match = re.match(pattern, url)
            if match:
                return {
                    "owner": match.group(1),
                    "name": match.group(2)
                }

        # Then GitHub patterns
        for pattern in github_patterns:
            match = re.match(pattern, url)
            if match:
                return {
                    "owner": match.group(1),
                    "name": match.group(2)
                }

        # Finally other patterns
        for pattern in other_patterns:
            match = re.match(pattern, url)
            if match:
                return {
                    "owner": match.group(1),
                    "name": match.group(2)
                }

        return None


# Global instance
git_integration_service = GitIntegrationService()
