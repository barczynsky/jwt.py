#!/bin/false
import base64 as _std_base64
import enum as _std_enum
import hashlib as _std_hashlib
import hmac as _std_hmac
import json as _std_json


JSONObject = dict[str, object]
# type JSONObject = dict[str, JSONObject | tuple[JSONObject] | list[JSONObject] | str | int | float | bool | None]  # Python 3.12


class _jwt_EnumMeta(_std_enum.EnumMeta, object):
	def __repr__(self):
		return f'''<enum '{__name__}.{self.__name__}': {{{', '.join(map(repr, self))}}}>'''


class _jwt_StrEnum(str, _std_enum.Enum):
	def __str__(self):
		return self.value

# class _jwt_StrEnum(_std_enum.StrEnum):  # Python 3.11
	def __repr__(self):
		return f'''{__name__}.{type(self).__name__}.{self.name}'''


class JWA(_jwt_StrEnum, metaclass=_jwt_EnumMeta):
	HS256 = 'HS256'
	NONE = 'none'


class JWS:
	@staticmethod
	def encode(payload: JSONObject | None, secret: str | None, algorithm: JWA = JWA.HS256) -> str | None:
		if not isinstance(payload, dict) or algorithm not in tuple(JWA):
			return None
		secret = secret or None
		header: JSONObject = {
			'typ': 'JWT',
			'alg': str(algorithm) if secret is not None else JWA.NONE,
		}
		header_str = _std_json.dumps(header, separators=(',', ':'))
		token_header = _std_base64.urlsafe_b64encode(header_str.encode()).rstrip(b'=')
		payload_str = _std_json.dumps(payload, separators=(',', ':'))
		token_payload = _std_base64.urlsafe_b64encode(payload_str.encode()).rstrip(b'=')
		optional_signature = [_std_base64.urlsafe_b64encode(_std_hmac.digest(
			str(secret).encode(),
			b'.'.join((token_header, token_payload)),
			_std_hashlib.sha256,
		)).rstrip(b'=')] if secret is not None and algorithm == JWA.HS256 else []
		return b'.'.join((token_header, token_payload, *optional_signature)).decode()

	@staticmethod
	def decode(token: str | None, secret: str | None, validate: bool = False) -> JSONObject | None:
		if not isinstance(token, str) or '.' not in token:
			return None
		(token_header, token_payload, *optional_signature) = str(token).encode().split(b'.', maxsplit=2)
		(token_signature,) = optional_signature or [None]
		secret = secret or None
		if token_signature is None and secret is not None:
			return None
		if token_signature is not None and secret is None:
			return None
		header: JSONObject = _std_json.loads(_std_base64.urlsafe_b64decode(token_header + b'=='))
		signature = _std_base64.urlsafe_b64encode(_std_hmac.digest(
			str(secret).encode(),
			b'.'.join((token_header, token_payload)),
			_std_hashlib.sha256,
		)).rstrip(b'=') if secret is not None and isinstance(header, dict) and header.get('alg') == JWA.HS256 else None
		if signature is not None and signature != token_signature:
			return None
		return _std_json.loads(_std_base64.urlsafe_b64decode(token_payload + b'=='))


encode = JWS.encode
decode = JWS.decode
