# homelab-ci

Shared CI components for homelab projects.

## Usage

Reference actions from workflows:

```yaml
- uses: gillouche/homelab-ci/actions/security-gate@main

- uses: gillouche/homelab-ci/actions/setup-nix-env@main

- uses: gillouche/homelab-ci/actions/trivy-scan@main
  with:
    image: ${{ env.IMAGE_TAG }}
    trivyignore: ./path/to/.trivyignore
    discord-webhook: ${{ secrets.SECURITY_NOTIFICATIONS_DISCORD }}

- uses: gillouche/homelab-ci/actions/discord-notify@main
  with:
    webhook: ${{ secrets.DISCORD_WEBHOOK }}
    status: success
    title: "Build Complete"
    message: "Deployed to production"
```

## Components

### Actions

| Action                   | Description                                                                   |
|--------------------------|-------------------------------------------------------------------------------|
| `actions/security-gate`  | Block fork PRs and validate repository ownership                             |
| `actions/setup-nix-env`  | Configure seaweedfs credentials for Nix cache (Nix pre-installed in runner)  |
| `actions/trivy-scan`     | Run Trivy security scan with stale-ignore detection and Discord notifications|
| `actions/discord-notify` | Send Discord notifications                                                    |
| `actions/renovate-notify`| Notify Discord when Renovate opens a PR                                       |

### Scripts

| Script | Description |
|--------|-------------|
| `scripts/check_scan_results.py` | Analyze Trivy JSON output, detect stale ignores |
| `scripts/notify_discord.py` | Generic Discord notification helper |

## Runner Image

All actions assume the runner uses `arc-runner-homelab-nix` which includes:
- Nix with flakes enabled
- SeaweedFS cache pre-configured
- Common build tools (git, curl)

## Development

### Running Tests Locally

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
PYTHONPATH=scripts pytest -v

# Run with coverage
PYTHONPATH=scripts pytest -v --cov=scripts --cov-report=term-missing
```

### Adding New Features

1. Add or modify scripts in `scripts/`
2. Write tests in `tests/test_<script_name>.py`
3. Run tests locally before pushing
4. CI will run tests on push to main or PRs
