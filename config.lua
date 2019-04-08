rulePath = "waf/wafconf/"
attacklog = true
logPath = "/data/logs/hack"
urlDeny = true
redirect = true
cookieCheck = true
postCheck = true
whiteCheck = true
blackFileExt = {"php", "jsp"}
CCDeny = true
-- cc攻击频率限制(次数/秒)
CCrate = "1000/60"

-- 是否触发安全规则后写入临时封禁
setBindIP = true

-- 是否启用限流
rateLimit = true

-- redis 配置
redisHost = "127.0.0.1"
redisPort = 6379

-- 输出格式，text/json
format = "text"

-- 默认返回内容
html = "您的请求触发了安全规则，请联系客服。"

-- 黑名单返回内容
blockHtml = "您的IP地址无法访问，请联系客服。"

-- ip限流返回内容
rateHtml = "您请求的太过频繁，请稍候再试。"

-- 封禁IP多长时间(SQL,安全规则)
ipBindTime    = 3600

-- ip限流
ipMinuteCount    = 100     --每分钟最大访问次数
ipMinuteBindTime = 3600    --每分钟限制的封禁IP多长时间

ipHourCount      = 2000    --每小时最大访问次数
ipHourBindTime   = 3600    --每小时限制的封禁IP多长时间 

ipDayCount       = 100000  --每天最大访问次数
ipDayBindTime    = 3600    --每天限制的封禁IP多长时间

-- ip白名单配置
ipWhitelist = {
}

-- ip黑名单配置
ipBlocklist = {
}

conf = {}

-- www1域名个性化配置
conf["www1.vckai.com"] = {
	["foramt"] = "json",

	["ipBindTime"]    = 3600,
	["ipMinuteCount"] = 200,
	["ipHourCount"]   = 2000,
	["ipDayCount"]    = 20000,
}

-- www2域名个性化配置
conf["www2.vckai.com"] = {
	["ipBindTime"]    = 3600,
	["ipMinuteCount"] = 200,
	["ipHourCount"]   = 2000,
	["ipDayCount"]    = 20000,
}
