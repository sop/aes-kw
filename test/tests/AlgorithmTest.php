<?php

use AESKW\AESKW128;


class AlgorithmTest extends PHPUnit_Framework_TestCase
{
	private static $_key8;
	
	private static $_key16;
	
	public static function setUpBeforeClass() {
		self::$_key8 = hex2bin("0011223344556677");
		self::$_key16 = str_repeat(self::$_key8, 2);
	}
	
	public static function tearDownAfterClass() {
		self::$_key8 = null;
		self::$_key16 = null;
	}
	
	public function testWrap() {
		$algo = new AESKW128();
		$data = $algo->wrap(self::$_key16, self::$_key16);
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testWrap
	 *
	 * @param string $ciphertext
	 */
	public function testUnwrap($ciphertext) {
		$algo = new AESKW128();
		$key = $algo->unwrap($ciphertext, self::$_key16);
		$this->assertEquals(self::$_key16, $key);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapShortKeyFail() {
		$algo = new AESKW128();
		$algo->wrap(self::$_key8, self::$_key16);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapEmptyKeyFail() {
		$algo = new AESKW128();
		$algo->wrap("", self::$_key16);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapShortKEKFail() {
		$algo = new AESKW128();
		$algo->wrap(self::$_key16, self::$_key8);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapEmptyKEKFail() {
		$algo = new AESKW128();
		$algo->wrap(self::$_key16, "");
	}
	
	/**
	 * @depends testWrap
	 * @expectedException RuntimeException
	 *
	 * @param string $ciphertext
	 */
	public function testUnwrapShortKEKFail($ciphertext) {
		$algo = new AESKW128();
		$algo->unwrap($ciphertext, self::$_key8);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testUnwrapInvalidCiphertextFail() {
		$algo = new AESKW128();
		$algo->unwrap("nope", self::$_key16);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testUnwrapEmptyCiphertextFail() {
		$algo = new AESKW128();
		$algo->unwrap("", self::$_key16);
	}
	
	public function testWrapPad() {
		$algo = new AESKW128();
		$data = $algo->wrapPad(self::$_key8, self::$_key16);
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testWrapPad
	 *
	 * @param string $ciphertext
	 */
	public function testUnwrapPad($ciphertext) {
		$algo = new AESKW128();
		$key = $algo->unwrapPad($ciphertext, self::$_key16);
		$this->assertEquals(self::$_key8, $key);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapPadEmptyKeyFail() {
		$algo = new AESKW128();
		$data = $algo->wrapPad("", self::$_key16);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testWrapPadShortKEKFail() {
		$algo = new AESKW128();
		$algo->wrapPad(self::$_key16, self::$_key8);
	}
	
	/**
	 * @depends testWrapPad
	 * @expectedException RuntimeException
	 *
	 * @param string $ciphertext
	 */
	public function testUnwrapPadShortKEKFail($ciphertext) {
		$algo = new AESKW128();
		$algo->unwrapPad($ciphertext, self::$_key8);
	}
	
	/**
	 * @dataProvider provideWrapPadCiphertext
	 *
	 * @param string $key
	 * @param int $blocks
	 */
	public function testWrapPadCiphertextLength($key, $blocks) {
		$algo = new AESKW128();
		$data = $algo->wrapPad($key, self::$_key16);
		$this->assertEquals($blocks * 8, strlen($data));
	}
	
	/**
	 * @dataProvider provideWrapPadCiphertext
	 *
	 * @param string $key
	 * @param int $blocks
	 */
	public function testWrapAndUnwrapWithPad($key, $blocks) {
		$algo = new AESKW128();
		$data = $algo->wrapPad($key, self::$_key16);
		$result = $algo->unwrapPad($data, self::$_key16);
		$this->assertEquals($key, $result);
	}
	
	public function provideWrapPadCiphertext() {
		return array(
			/* @formatter:off */
			["1", 2],
			["1234567", 2],
			["12345678", 2],
			["123456781", 3],
			["123456781234567", 3],
			["1234567812345678", 3],
			["12345678123456781", 4],
			/* @formatter:on */
		);
	}
}
