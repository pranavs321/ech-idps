#!/bin/bash
# Reads the PreToolUse JSON on stdin; denies destructive commands and any holdout access.
input=$(cat)
if echo "$input" | grep -Eq 'rm[[:space:]]+-[[:alpha:]]*[rR]|rm[[:space:]].*--recursive|-delete|rmtree|git[[:space:]]+(push|clean)|reset[[:space:]]+--hard|sudo[[:space:]]|diskutil|mkfs'; then
  echo '{"decision":"deny","reason":"Blocked by pipeline guard: destructive command. Move files to trash/ or ask the user."}'
elif echo "$input" | grep -Eq 'allow-holdout|malware-traffic-analysis\.net/202[2-6]|-malware[^"]*\.zip'; then
  echo '{"decision":"deny","reason":"Blocked by pipeline guard: holdout years or malware-sample zips. Only a human runs the confirm stage."}'
else
  echo '{"decision":"allow"}'
fi
