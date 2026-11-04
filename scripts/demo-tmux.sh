#!/usr/bin/env bash
# Opens the demo layout in tmux (the dashboard's Terminal page shows the same panes):
#
#   ┌──────────────────────┬──────────────────────┐
#   │ broker spy           │ attacker             │
#   ├──────────────────────┼──────────────────────┤
#   │ front door log       │ hub alerts           │
#   ├──────────────────────┴──────────────────────┤
#   │ free shell                                  │
#   └─────────────────────────────────────────────┘
#
# Usage: scripts/demo-tmux.sh            (stack already running: docker compose up -d)
# Env:   BBIOT   how to run the CLI      (default: "uv run bbiot")
#        SESSION tmux session name       (default: bbiot)
set -euo pipefail

BBIOT=${BBIOT:-uv run bbiot}
SESSION=${SESSION:-bbiot}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

command -v tmux >/dev/null || { echo "tmux is not installed (Linux/macOS/WSL)"; exit 1; }

if tmux has-session -t "$SESSION" 2>/dev/null; then
  exec tmux attach -t "$SESSION"
fi

hub_filter="✗|⚠|alert|quarantin|late|missing|dropped|gap|block|violat|revok|rekey|counterfeit"

tmux new-session -d -s "$SESSION" -n demo -c "$ROOT"
tmux set-option -t "$SESSION" -g mouse on
tmux set-option -t "$SESSION" -g pane-border-status top
tmux set-option -t "$SESSION" -g pane-border-format " #{pane_title} "

# top-left: what the broker sees
tmux select-pane -t "$SESSION:demo.0" -T "broker spy"
tmux send-keys -t "$SESSION:demo.0" "$BBIOT spy --topic 'home/#'" C-m

# bottom: free shell (full width)
tmux split-window -v -t "$SESSION:demo.0" -l 25% -c "$ROOT"
tmux select-pane -t "$SESSION:demo.1" -T "shell"
tmux send-keys -t "$SESSION:demo.1" "$BBIOT --help | head -40" C-m

# middle-left: front door log
tmux split-window -v -t "$SESSION:demo.0" -c "$ROOT"
tmux select-pane -t "$SESSION:demo.1" -T "front door"
tmux send-keys -t "$SESSION:demo.1" "docker compose logs -f --no-log-prefix --tail 20 front-door" C-m

# top-right: attacker (ready to type)
tmux split-window -h -t "$SESSION:demo.0" -c "$ROOT"
tmux select-pane -t "$SESSION:demo.1" -T "attacker"
tmux send-keys -t "$SESSION:demo.1" "# try: $BBIOT attack replay   |   $BBIOT security on   |   $BBIOT attack redirect --from home/door/front/cmd --to home/door/back/cmd" C-m

# middle-right: hub alerts
tmux split-window -h -t "$SESSION:demo.2" -c "$ROOT"
tmux select-pane -t "$SESSION:demo.3" -T "hub alerts"
tmux send-keys -t "$SESSION:demo.3" \
  "docker compose logs -f --no-log-prefix --tail 50 hub | grep --line-buffered -iE '$hub_filter'" C-m

tmux select-pane -t "$SESSION:demo.1"
exec tmux attach -t "$SESSION"
