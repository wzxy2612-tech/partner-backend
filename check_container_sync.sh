#!/usr/bin/env bash
# Detect divergence between the host source tree and the code the container is
# actually running.
#
# Why this exists: the api service has no volume mount -- the Dockerfile COPYs
# the source -- so "the files on my disk", "the files baked into the image", and
# "the files inside the running container" are three separate things that can
# disagree. This series has been bitten by two of the three:
#
#   * an overlay applied to the host that never reached the image, because the
#     container was not rebuilt -- 87 tests passed with the security fix absent.
#   * an edit made INSIDE the running container (docker compose exec ... sed -i),
#     which turns tests green immediately, is invisible to git, and evaporates on
#     the next `make up`.
#
# verify_fixes.py cannot see either problem: run on the host it describes the
# host, run in the container it describes the container. It has no way to notice
# they differ. This compares them.
#
# Usage:  ./check_container_sync.sh
set -euo pipefail

SERVICE=api
FAIL=0

echo "comparing host tree against the running $SERVICE container"
echo

# Hash every tracked source file on both sides and compare. Uses find+md5sum
# rather than `docker cp` so nothing is written anywhere.
host_hashes=$(find app tests alembic verify_fixes.py -name '*.py' -type f 2>/dev/null \
  | sort | xargs md5sum 2>/dev/null | awk '{print $2, $1}')

cont_hashes=$(docker compose exec -T "$SERVICE" sh -c \
  "find app tests alembic verify_fixes.py -name '*.py' -type f 2>/dev/null | sort | xargs md5sum 2>/dev/null | awk '{print \$2, \$1}'")

diff_out=$(diff <(echo "$host_hashes") <(echo "$cont_hashes") || true)

if [ -z "$diff_out" ]; then
  echo "  OK   host and container are identical"
else
  echo "  DIVERGED:"
  echo "$diff_out" | sed 's/^/    /'
  echo
  echo "  < = host only, > = container only."
  echo "  A file differing means one of:"
  echo "    - the host was edited and the image not rebuilt  -> run: make up"
  echo "    - the CONTAINER was edited directly (exec ... sed -i, vi, etc.)"
  echo "      -> that change is not in git and will vanish on the next rebuild."
  echo "         Re-apply it on the host, then: make up"
  FAIL=1
fi

echo
echo "alembic revision recorded in the database"
db_rev=$(docker compose exec -T db psql -U app_owner -d partner_backend -tAc \
  "SELECT version_num FROM alembic_version;" 2>/dev/null || echo "UNREADABLE")
head_rev=$(docker compose exec -T "$SERVICE" sh -c \
  "ls alembic/versions/*.py | sed 's|.*/||' | cut -d_ -f1 | sort | tail -1" 2>/dev/null || echo "?")
echo "  db=$db_rev   highest migration file in container=$head_rev"
if [ "$db_rev" != "$head_rev" ]; then
  echo "  MISMATCH: the database is not at the newest migration present."
  echo "  Note a corrected migration is NOT re-applied once its revision is"
  echo "  recorded -- alembic sees head and skips it. Reset the volume"
  echo "  (make down && make up) or fix forward with a new revision."
  FAIL=1
fi

exit $FAIL
