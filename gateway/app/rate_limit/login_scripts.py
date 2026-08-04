"""
Atomic Redis Lua scripts used for login protection.
"""


LOGIN_LOCK_STATUS_SCRIPT = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])

if now_ms == nil or now_ms < 0 then
    return redis.error_reply("invalid timestamp")
end

local state = redis.call(
    "HMGET",
    key,
    "failures",
    "locked_until_ms"
)

local failures = tonumber(state[1]) or 0
local locked_until_ms = tonumber(state[2]) or 0

if locked_until_ms > now_ms then
    return {
        1,
        failures,
        locked_until_ms - now_ms
    }
end

if locked_until_ms > 0 then
    redis.call("DEL", key)

    return {
        0,
        0,
        0
    }
end

return {
    0,
    failures,
    0
}
""".strip()


LOGIN_FAILURE_SCRIPT = """
local key = KEYS[1]

local threshold = tonumber(ARGV[1])
local now_ms = tonumber(ARGV[2])
local failure_window_ms = tonumber(ARGV[3])
local lockout_ms = tonumber(ARGV[4])

if threshold == nil or threshold <= 0 then
    return redis.error_reply("invalid threshold")
end

if now_ms == nil or now_ms < 0 then
    return redis.error_reply("invalid timestamp")
end

if failure_window_ms == nil or failure_window_ms <= 0 then
    return redis.error_reply("invalid failure window")
end

if lockout_ms == nil or lockout_ms <= 0 then
    return redis.error_reply("invalid lockout duration")
end

local state = redis.call(
    "HMGET",
    key,
    "failures",
    "locked_until_ms"
)

local failures = tonumber(state[1]) or 0
local locked_until_ms = tonumber(state[2]) or 0

if locked_until_ms > now_ms then
    return {
        1,
        failures,
        locked_until_ms - now_ms
    }
end

if locked_until_ms > 0 then
    redis.call("DEL", key)
    failures = 0
end

failures = failures + 1

redis.call(
    "HSET",
    key,
    "failures",
    tostring(failures)
)

if failures >= threshold then
    locked_until_ms = now_ms + lockout_ms

    redis.call(
        "HSET",
        key,
        "locked_until_ms",
        tostring(locked_until_ms)
    )

    redis.call(
        "PEXPIRE",
        key,
        lockout_ms
    )

    return {
        1,
        failures,
        lockout_ms
    }
end

redis.call(
    "HDEL",
    key,
    "locked_until_ms"
)

redis.call(
    "PEXPIRE",
    key,
    failure_window_ms
)

return {
    0,
    failures,
    0
}
""".strip()


LOGIN_RESET_SCRIPT = """
return redis.call(
    "DEL",
    KEYS[1]
)
""".strip()
