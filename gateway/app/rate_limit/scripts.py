"""
Lua scripts used by the Redis-backed rate limiter.
"""


TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]

local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])

if capacity == nil or capacity <= 0 then
    return redis.error_reply("invalid capacity")
end

if refill_rate == nil or refill_rate <= 0 then
    return redis.error_reply("invalid refill rate")
end

if requested == nil or requested <= 0 then
    return redis.error_reply("invalid token cost")
end

if now_ms == nil or now_ms < 0 then
    return redis.error_reply("invalid timestamp")
end

if ttl_ms == nil or ttl_ms <= 0 then
    return redis.error_reply("invalid ttl")
end

local state = redis.call(
    "HMGET",
    key,
    "tokens",
    "last_refill_ms"
)

local tokens = tonumber(state[1])
local last_refill_ms = tonumber(state[2])

if tokens == nil or last_refill_ms == nil then
    tokens = capacity
    last_refill_ms = now_ms
end

tokens = math.max(
    0,
    math.min(capacity, tokens)
)

local elapsed_ms = math.max(
    0,
    now_ms - last_refill_ms
)

local refilled_tokens = (
    tokens
    + (
        elapsed_ms
        * refill_rate
        / 1000
    )
)

tokens = math.min(
    capacity,
    refilled_tokens
)

local allowed = 0
local retry_after_ms = 0

if tokens >= requested then
    allowed = 1
    tokens = tokens - requested
else
    retry_after_ms = math.ceil(
        (
            requested - tokens
        )
        / refill_rate
        * 1000
    )
end

local reset_after_ms = math.ceil(
    (
        capacity - tokens
    )
    / refill_rate
    * 1000
)

redis.call(
    "HSET",
    key,
    "tokens",
    tostring(tokens),
    "last_refill_ms",
    tostring(now_ms)
)

redis.call(
    "PEXPIRE",
    key,
    ttl_ms
)

return {
    allowed,
    tostring(tokens),
    retry_after_ms,
    reset_after_ms
}
""".strip()
