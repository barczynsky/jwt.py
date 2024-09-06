# `jwt.py`: a Python JWT/JWS Library

`jwt.py` is a simple JWT (**`JSON Web Token`**) library for Python, with support for HS256 (**`HMAC-SHA256`**) signature using JWS (**`JSON Web Signature`**). It is distributed as a single file module and has no dependencies other than the Python Standard Library.

Minimum required runtime version is Python **`3.10`** or newer. **Python `2.x` and older is not supported.**

## Example Usage

- how to encode and decode a JWT token with **secured** JWS signature:
```python
>>> import jwt
>>> token = jwt.encode({'data': 'foo'}, 'bar')
>>> print(token)
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiZm9vIn0.TjQsNFjqfo-QW4jobI-p0xF6PYPWXXudVkluuu7rXhM
>>> jwt.decode(token, 'bar')
{'data': 'foo'}
```

- how to encode and decode a JWT token without (**unsecured**) JWS signature:
```python
>>> import jwt
>>> token = jwt.encode({'data': 'foo'}, None)
>>> print(token)
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJkYXRhIjoiZm9vIn0
>>> jwt.decode(token, None)
{'data': 'foo'}
```
