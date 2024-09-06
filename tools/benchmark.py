#!/usr/bin/env python3
import functools
import itertools
import sys
import time
#
import jwt
from tools.encode import parse_args


def main(args: list[str] | None = None):
	def benchmark(f):
		t0 = time.process_time()
		y = f()
		t1 = time.process_time()
		return (t1 - t0, y)

	(payload, secret, params) = parse_args(args, module_name='utils.benchmark')

	n = 100
	i = 100

	try:
		if payload is not None:
			(t_token, test_token) = min(
				map(
					benchmark,
					(
						lambda: functools.reduce(
							lambda x, _: x,
							map(jwt.JWS.encode, itertools.repeat(payload, n), itertools.repeat(secret, n)),
						) for _ in range(i)
					)
				)
			)
			print(f'encode: {t_token / n * 1000000:.1f}us')
			print(f'result: {test_token}')
			print()

			(t_payload, test_payload) = min(
				map(
					benchmark,
					(
						lambda: functools.reduce(
							lambda x, _: x,
							map(jwt.JWS.decode, itertools.repeat(test_token, n), itertools.repeat(secret, n)),
						) for _ in range(i)
					)
				)
			)
			print(f'decode: {t_payload / n * 1000000:.1f}us')
			print(f'result: {test_payload}')
			print()

			raise SystemExit

	except Exception:
		pass
	print(
		f'error: \'{params.payload}\' is not a valid JWT payload',
		file=sys.stderr,
	)
	raise SystemExit


if __name__ == '__main__':
	main()
