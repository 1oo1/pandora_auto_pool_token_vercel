基于 zhile 大佬自动脚本的修改： https://gist.github.com/pengzhile/448bfcfd548b3ae4e665a84cc86c4694 

部署在 vercel 上，只有一个 api /refresh_pk，通过调用自动刷新/生成 fakeopen 的 fk 和 pk，结果会被保存到 vercel kv 里。

通过 cloudflare 的 worker cron 触发调用。

环境变量说明：

```shell
# vercel kv 地址
redis_url = getenv('KV_URL', '')

# 调用 /refresh_pk 时的 key，目的是只允许 cf 的 worker 调用
api_auth = getenv('API_AUTH_KEY', '')

# chatGPT 账号，格式：username,password;username2,password2;username3,password3
open_ai_accounts = getenv('OPEN_AI_ACCOUNTS', '')

# 对应 fk 的唯一名称
fk_unique_name = getenv('FK_UNIQUE_NAME', '')
```