# Lambda Auth Tester

A sandbox project to try out lambda authorisation strategies

Includes:
- hashing and salting
- IAM policies with generic ARNs

To test:

```
yarn
yarn deploy
```

```
curl -i -u 'dan:hello' https://0owua1w2db.execute-api.us-east-1.amazonaws.com/dev/hello
```

```
curl -i -X POST -u 'dan:hello' https://0owua1w2db.execute-api.us-east-1.amazonaws.com/dev/example
```

