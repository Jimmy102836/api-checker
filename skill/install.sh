#!/bin/bash
# API Checker Skill Installer for Claude Code
# Usage: bash install.sh

set -e

SKILL_DIR="$HOME/.claude/skills/apicheck"
echo "Installing API Checker skill to $SKILL_DIR..."

mkdir -p "$SKILL_DIR"
cp -r "$(dirname "$0")/apicheck/SKILL.md" "$SKILL_DIR/"

echo "✅ Installed! Restart Claude Code and use /apicheck"
echo ""
echo "Usage:"
echo "  /apicheck https://api.relay.com/v1"
echo "  /apicheck https://api.relay.com/v1 --model gpt-4"
echo "  /apicheck https://api.relay.com/v1 --skip context_truncation,semantic_truncation"
