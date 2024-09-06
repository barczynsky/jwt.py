#!/usr/bin/env python3
import argparse
import datetime
import json
import sys
#
import jwt
from jwt import JSONObject


def parse_args(args: list[str] | None, module_name: str | None = None):
	payload: JSONObject | None
	secret: str | None

	now = datetime.datetime.now(datetime.timezone.utc)
	# now = datetime.datetime.now(datetime.UTC)  # Python 3.11
	default_payload: JSONObject = {
		'exp': int(now.replace(year=now.year + 1).timestamp())  # valid for 1 year
	}
	default_payload_param = json.dumps(default_payload, separators=(',', ':'))

	parser = argparse.ArgumentParser(prog=module_name)
	parser.add_argument('payload', nargs='?', help=f'JSON object (default: {default_payload_param})')
	parser.add_argument('secret', nargs='?', default='', help='HS256 signature secret')
	params = parser.parse_args(args)

	try:
		payload = json.loads(params.payload or default_payload_param)
	except json.JSONDecodeError:
		payload = None
	secret = params.secret or None

	return (payload, secret, params)


def main(args: list[str] | None = None):
	(payload, secret, params) = parse_args(args, module_name='jwt.encode')

	try:
		token = jwt.encode(payload, secret)
		if token is not None:
			return print(token)
	except Exception:
		pass
	print(
		f'error: \'{params.payload}\' is not a valid JSON object with secret \'{params.secret}\'',
		file=sys.stderr,
	)
	raise SystemExit


if __name__ == '__main__':
	main()
