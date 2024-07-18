// We are using Lua Scripts for scripting in the redis server

const sendSixDigitCodeScript = `
    local userId = KEYS[1]
    local operation = ARGV[1]

    if operation == "set" then
        local key = "user:" .. userId
        local expiry = tonumber(ARGV[3])  -- Expiry time in seconds
        local value = ARGV[2]
        redis.call("SET", key, value)
        redis.call("EXPIRE", key, expiry)
        return redis.status_reply("SUCCESS")
    elseif operation == "get" then
        local key = "user:" .. userId
        return redis.call("GET", key)
    elseif operation == "delete" then
        local keys = redis.call("KEYS", "user:" .. userId .. "*")
        for _, key in ipairs(keys) do
            redis.call("DEL", key)
        end
        return #keys
    else
        return "Unsupported operation"
    end
`;

module.exports = { sendSixDigitCodeScript };
