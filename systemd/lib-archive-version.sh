# Delad hjälpfunktion: arkiverar den KÖRANDE versionens binärer/webui/
# systemd-enheter innan de skrivs över, så att man kan rulla tillbaka till
# den senare. Källas (source) av både install.sh och rollback-runner.sh -
# de får ALDRIG divergera, då skulle en av vägarna sluta arkivera korrekt.
#
# Förutsätter att följande variabler redan är satta av den anropande
# skriptet: DATA_DIR, BIN_DIR.
#
# archive_current_version <ny-version>
#   Arkiverar den binär som just nu ligger på $BIN_DIR/security-harbor-agent
#   (om någon finns och dess version skiljer sig från <ny-version>) till
#   $DATA_DIR/versions/<gammal-version>/, uppdaterar index.json och pruning:ar
#   till de 3 senast arkiverade.
archive_current_version() {
  local new_version="$1"
  local agent_bin="$BIN_DIR/security-harbor-agent"

  if [ ! -x "$agent_bin" ]; then
    return 0  # färsk installation - inget att arkivera
  fi

  local old_version
  old_version="$("$agent_bin" --version 2>/dev/null || true)"
  if [ -z "$old_version" ] || [ "$old_version" = "$new_version" ]; then
    return 0  # okänd version, eller redan samma - inget att arkivera
  fi

  local versions_dir="$DATA_DIR/versions"
  local target="$versions_dir/$old_version"
  echo "-> Arkiverar utgående version $old_version till $target"

  install -d -m 0755 "$target/systemd"

  for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner; do
    if [ -f "$BIN_DIR/$bin" ]; then
      install -m 0755 -o root -g root "$BIN_DIR/$bin" "$target/$bin"
    fi
  done
  if [ -f /usr/local/lib/security-harbor/update-runner.sh ]; then
    install -m 0755 -o root -g root /usr/local/lib/security-harbor/update-runner.sh "$target/update-runner.sh"
  fi
  if [ -f /usr/local/lib/security-harbor/rollback-runner.sh ]; then
    install -m 0755 -o root -g root /usr/local/lib/security-harbor/rollback-runner.sh "$target/rollback-runner.sh"
  fi
  if [ -d "$DATA_DIR/webui" ]; then
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --delete "$DATA_DIR/webui/" "$target/webui/"
    else
      mkdir -p "$target/webui"
      cp -a "$DATA_DIR/webui/." "$target/webui/"
    fi
  fi
  for f in /etc/systemd/system/security-harbor-*.service /etc/systemd/system/security-harbor-*.timer; do
    [ -f "$f" ] && cp -a "$f" "$target/systemd/"
  done
  for f in /etc/polkit-1/rules.d/10-security-harbor-*.rules; do
    [ -f "$f" ] && cp -a "$f" "$target/systemd/"
  done

  local size_bytes
  size_bytes="$(du -sb "$target" 2>/dev/null | cut -f1)"
  size_bytes="${size_bytes:-0}"

  _index_add_and_prune "$versions_dir" "$old_version" "$size_bytes"
}

# _index_add_and_prune <versions-dir> <version> <size-bytes>
#   Lägger till en post i index.json (nyast först) och tar bort allt utom
#   de 3 senaste - både ur index.json och som kataloger på disk. Kräver jq
#   (installeras av install.sh) för säker/atomisk JSON-hantering.
_index_add_and_prune() {
  local versions_dir="$1" version="$2" size_bytes="$3"
  local index="$versions_dir/index.json"
  local archived_at
  archived_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if ! command -v jq >/dev/null 2>&1; then
    echo "VARNING: jq saknas - kan inte uppdatera versions/index.json (arkivet på disk är dock skapat)." >&2
    return 0
  fi

  local current="{\"versions\":[]}"
  if [ -f "$index" ] && jq -e . "$index" >/dev/null 2>&1; then
    current="$(cat "$index")"
  fi

  # Ta bort ev. tidigare post för samma version, lägg till den nya först,
  # behåll bara de 3 senaste.
  local updated
  updated="$(jq --arg v "$version" --arg t "$archived_at" --argjson s "${size_bytes:-0}" '
    .versions = ([{version:$v, archived_at:$t, size_bytes:$s}]
      + (.versions | map(select(.version != $v))))
    | .versions = (.versions[0:3])
  ' <<<"$current")"

  local tmp="$index.tmp"
  echo "$updated" >"$tmp"
  mv -f "$tmp" "$index"

  # Rensa kataloger som föll ur fönstret ovan.
  local kept
  kept="$(jq -r '.versions[].version' <<<"$updated")"
  for dir in "$versions_dir"/*/; do
    [ -d "$dir" ] || continue
    local v
    v="$(basename "$dir")"
    if ! grep -qxF "$v" <<<"$kept"; then
      rm -rf "$dir"
    fi
  done
}
