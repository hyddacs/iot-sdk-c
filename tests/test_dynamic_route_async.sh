#!/usr/bin/env bash
set -euo pipefail

src="${1:-gw_sdk.c}"

if ! grep -q "gw_add_rule_async" "$src"; then
    echo "missing async dynamic route dispatcher" >&2
    exit 1
fi

gw_on_message_body="$(
    awk '
        /static int gw_on_message/ { in_fn=1 }
        in_fn { print }
        in_fn && /^}/ { exit }
    ' "$src"
)"

if grep -q "ret = gw_add_rule(" <<<"$gw_on_message_body"; then
    echo "gw_on_message still calls gw_add_rule synchronously" >&2
    exit 1
fi

if ! grep -q "gw_add_rule_async" <<<"$gw_on_message_body"; then
    echo "gw_on_message does not dispatch add_rule asynchronously" >&2
    exit 1
fi

if ! grep -q "gw_del_rule_async" "$src"; then
    echo "missing async dynamic route delete dispatcher" >&2
    exit 1
fi

if grep -q "ret = gw_del_rule(" <<<"$gw_on_message_body"; then
    echo "gw_on_message still calls gw_del_rule synchronously" >&2
    exit 1
fi

if ! grep -q "gw_del_rule_async" <<<"$gw_on_message_body"; then
    echo "gw_on_message does not dispatch del_rule asynchronously" >&2
    exit 1
fi

if ! grep -q "user_service_dispatch_async" "$src"; then
    echo "missing async user service dispatcher" >&2
    exit 1
fi

if grep -q "g_user_service_cb(" <<<"$gw_on_message_body"; then
    echo "gw_on_message still calls user service callback synchronously" >&2
    exit 1
fi

if ! grep -q "user_service_dispatch_async" <<<"$gw_on_message_body"; then
    echo "gw_on_message does not dispatch user service asynchronously" >&2
    exit 1
fi

if ! grep -q '"/sys/%s/%s/thing/service/+"' "$src"; then
    echo "gateway does not subscribe to service call wildcard topic" >&2
    exit 1
fi

if ! grep -q 'strstr(topic_copy, "/thing/service/")' <<<"$gw_on_message_body"; then
    echo "gw_on_message does not accept service call topics such as /thing/service/add_rule" >&2
    exit 1
fi
