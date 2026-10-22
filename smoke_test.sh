#!/usr/bin/env bash
# Smoke test for Cloud Drive: two users, folders, versions, sharing and permissions.
# Usage: bash smoke_test.sh            (tests http://127.0.0.1:8001)
#        BASE=https://your-domain bash smoke_test.sh
BASE="${BASE:-http://127.0.0.1:8001}"
N=$RANDOM
A="alice$N"; B="bob$N"; PW="Passw0rd123"
PASS=0; FAIL=0
TMP=$(mktemp -d)

pass() { echo "  PASS  $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$3', got '$2')"; fi; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== Cloud Drive smoke test against $BASE"

echo "-- accounts and login"
RA=$(curl -s -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$A\",\"email\":\"$A@test.com\",\"password\":\"$PW\"}" $BASE/api/register)
TA=$(echo "$RA" | jget "['token']")
RB=$(curl -s -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$B\",\"email\":\"$B@test.com\",\"password\":\"$PW\"}" $BASE/api/register)
TB=$(echo "$RB" | jget "['token']")
[ -n "$TA" ] && [ "$TA" != "None" ] && pass "register $A" || fail "register $A: $RA"
[ -n "$TB" ] && [ "$TB" != "None" ] && pass "register $B" || fail "register $B: $RB"
check "wrong password rejected" "$(code -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$A\",\"password\":\"wrong-pass\"}" $BASE/api/login)" "401"
check "request without token rejected" "$(code $BASE/api/list)" "401"

echo "-- folders and uploads"
FID=$(curl -s -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d '{"name":"Docs"}' $BASE/api/folders | jget "['id']")
[ -n "$FID" ] && [ "$FID" != "None" ] && pass "create folder (id $FID)" || fail "create folder"
printf 'version one' > $TMP/hello.txt
R1=$(curl -s -H "Authorization: Bearer $TA" -F "file=@$TMP/hello.txt" -F "folder_id=$FID" $BASE/api/files)
FILE=$(echo "$R1" | jget "['id']")
check "upload creates version 1" "$(echo "$R1" | jget "['version']")" "1"
printf 'version two' > $TMP/hello.txt
R2=$(curl -s -H "Authorization: Bearer $TA" -F "file=@$TMP/hello.txt" -F "folder_id=$FID" $BASE/api/files)
check "same name creates version 2" "$(echo "$R2" | jget "['version']")" "2"
check "two versions listed" "$(curl -s -H "Authorization: Bearer $TA" $BASE/api/files/$FILE/versions | jget "['versions'].__len__()")" "2"

echo "-- download (signed S3 link)"
URL=$(curl -s -H "Authorization: Bearer $TA" $BASE/api/files/$FILE/download | jget "['url']")
check "current version content" "$(curl -sL "$URL")" "version two"
URL1=$(curl -s -H "Authorization: Bearer $TA" "$BASE/api/files/$FILE/download?version=1" | jget "['url']")
check "old version content" "$(curl -sL "$URL1")" "version one"

echo "-- permissions"
check "other user cannot download (404)" "$(code -H "Authorization: Bearer $TB" $BASE/api/files/$FILE/download)" "404"
check "share with $B (view)" "$(code -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d "{\"username\":\"$B\",\"access\":\"view\"}" $BASE/api/files/$FILE/share)" "200"
URLB=$(curl -s -H "Authorization: Bearer $TB" $BASE/api/files/$FILE/download | jget "['url']")
check "$B can download after sharing" "$(curl -sL "$URLB")" "version two"
check "shared list shows the file" "$(curl -s -H "Authorization: Bearer $TB" $BASE/api/shared | jget "['files'].__len__()")" "1"
printf 'hack' > $TMP/b.txt
check "view-only cannot upload (403)" "$(code -H "Authorization: Bearer $TB" -F "file=@$TMP/b.txt" -F "file_id=$FILE" $BASE/api/files)" "403"
check "view-only cannot delete (403)" "$(code -X DELETE -H "Authorization: Bearer $TB" $BASE/api/files/$FILE)" "403"
curl -s -o /dev/null -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d "{\"username\":\"$B\",\"access\":\"edit\"}" $BASE/api/files/$FILE/share
printf 'version three by bob' > $TMP/b.txt
R3=$(curl -s -H "Authorization: Bearer $TB" -F "file=@$TMP/b.txt" -F "file_id=$FILE" $BASE/api/files)
check "edit access can upload version 3" "$(echo "$R3" | jget "['version']")" "3"

echo "-- restore, storage, cleanup"
check "restore version 1" "$(code -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d '{"version":1}' $BASE/api/files/$FILE/restore)" "200"
URLR=$(curl -s -H "Authorization: Bearer $TA" $BASE/api/files/$FILE/download | jget "['url']")
check "current content is version one again" "$(curl -sL "$URLR")" "version one"
USED=$(curl -s -H "Authorization: Bearer $TA" $BASE/api/storage | jget "['used_bytes']")
[ "${USED:-0}" -gt 0 ] && pass "storage used: $USED bytes" || fail "storage used is zero"
check "delete file (owner)" "$(code -X DELETE -H "Authorization: Bearer $TA" $BASE/api/files/$FILE)" "200"
check "deleted file gone for $B (404)" "$(code -H "Authorization: Bearer $TB" $BASE/api/files/$FILE/download)" "404"
check "delete empty folder" "$(code -X DELETE -H "Authorization: Bearer $TA" $BASE/api/folders/$FID)" "200"

rm -rf "$TMP"
echo
echo "== Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
