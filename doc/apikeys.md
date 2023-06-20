# API Keys

API keys can be created in order to facilitate M2M interactions.
In order to create an API key, a user must provide:
* a name
* a Time to Live in days, set to 30 by default (expiration date calculated on creation date + TTL), capped to 365 days (configurable)
* a list of roles associated to the key (chosen among the user roles)

Once created the user gets in return:
* a key ID
* a key secret

Both can then be used to authenticate requests to ARLAS, using dedicated headers:
* `arlas-api-key-id` for the key ID
* `arlas-api-key-secret` for the key secret

Example:
```shell
curl -X GET "http://localhost:9997/arlas_iam_server/organisations/c8b8169f-8fdc-408b-a972-bbf04802d719/roles" -H "accept: application/json;charset=utf-8" -H "arlas-api-key-id: 0756444bdf014cae" -H "arlas-api-key-secret: 46f1f26831abf269"
```