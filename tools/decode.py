#!/usr/bin/env python3
import argparse
import sys
#
import jwt


def parse_args(args: list[str] | None, module_name: str | None = None):
	token: str
	secret: str | None

	parser = argparse.ArgumentParser(prog=module_name)
	parser.add_argument('token', help='JSON Web Token')
	parser.add_argument('secret', nargs='?', default='', help='HS256 signature secret')
	params = parser.parse_args(args)

	token = params.token
	secret = params.secret or None

	return (token, secret, params)


def main(args: list[str] | None = None):
	(token, secret, params) = parse_args(args, module_name='jwt.decode')

	try:
		payload = jwt.decode(token, secret)
		if payload is not None:
			return print(payload)
	except Exception:
		pass
	print(
		f'error: \'{params.token}\' is not a valid JSON Web Token with secret \'{params.secret}\'',
		file=sys.stderr,
	)
	raise SystemExit


if __name__ == '__main__':
	main()
