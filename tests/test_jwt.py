#!/usr/bin/env python3
import unittest
#
import jwt


class Test_jwt(unittest.TestCase):
	secret = '37e3ca21-d64e-43cb-80ab-58dd0581c6ae'

	# header_HS256: jwt.JSONObject = {  # implicit JWT header
	# 	'typ': 'JWT',
	# 	'alg': 'HS256',
	# }
	payload_HS256: jwt.JSONObject = {
		'exp': 1756729920,
	}
	signature_HS256 = 'xmA7Q62j3ngthj2FOPjnxo2N0jo46Po2Soq3xdBI3mQ'
	token_HS256 = '.'.join((
		'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9',
		'eyJleHAiOjE3NTY3Mjk5MjB9',
		signature_HS256,
	))

	def test_Encode_HS256(self):
		token = jwt.encode(self.payload_HS256, self.secret)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_HS256)

	def test_Encode_HS256_with_correct_algorithm(self):
		token = jwt.encode(self.payload_HS256, self.secret, jwt.JWA.HS256)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_HS256)

	def test_Encode_HS256_with_incorrect_algorithm(self):
		token = jwt.encode(self.payload_HS256, self.secret, jwt.JWA.NONE)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_NONE)

	def test_Decode_HS256(self):
		payload = jwt.decode(self.token_HS256, self.secret)
		self.assertIsInstance(payload, dict)
		self.assertEqual(payload, self.payload_HS256)

	def test_Decode_HS256_with_empty_secret(self):
		payload = jwt.decode(self.token_HS256, '')
		self.assertEqual(payload, None)

	def test_Decode_HS256_with_no_secret(self):
		payload = jwt.decode(self.token_HS256, None)
		self.assertEqual(payload, None)

	# header_NONE: jwt.JSONObject = {  # implicit JWT header
	# 	'typ': 'JWT',
	# 	'alg': 'none',
	# }
	payload_NONE: jwt.JSONObject = payload_HS256
	token_NONE = '.'.join((
		'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0',
		'eyJleHAiOjE3NTY3Mjk5MjB9',
	))

	def test_Encode_none(self):
		token = jwt.encode(self.payload_NONE, None)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_NONE)

	def test_Encode_none_with_correct_algorithm(self):
		token = jwt.encode(self.payload_NONE, None, jwt.JWA.NONE)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_NONE)

	def test_Encode_none_with_incorrect_algorithm(self):
		token = jwt.encode(self.payload_NONE, None, jwt.JWA.HS256)
		self.assertIsInstance(token, str)
		self.assertEqual(token, self.token_NONE)

	def test_Decode_none(self):
		payload = jwt.decode(self.token_NONE, None)
		self.assertIsInstance(payload, dict)
		self.assertEqual(payload, self.payload_NONE)

	def test_Decode_none_with_empty_secret(self):
		payload = jwt.decode(self.token_NONE, '')
		self.assertIsInstance(payload, dict)
		self.assertEqual(payload, self.payload_NONE)

	def test_Decode_none_with_extra_secret(self):
		payload = jwt.decode(self.token_NONE, self.secret)
		self.assertEqual(payload, None)
