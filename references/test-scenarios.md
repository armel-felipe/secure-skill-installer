# Test Scenarios

The automated suite uses temporary directories and inert text. It never invokes fixture files or installs external skills.

Coverage includes:

1. Valid skills.sh URL.
2. Valid `npx skills add` command.
3. Global installation command.
4. Local installation command.
5. Missing local project folder.
6. Existing skill conflict.
7. Python `requests` usage.
8. `os.environ` access.
9. `curl` usage.
10. Recursive deletion.
11. `opencode.json` modification.
12. Cron or LaunchAgent persistence.
13. Markdown prompt injection.
14. External symbolic link.
15. Local removal.
16. Global removal.
17. Keep decision.
18. More-details decision.
19. Installation cancellation.
20. Installation failure.

Additional tests cover sensitive-file non-disclosure, binary detection, and SHA-256 inventory.
